#!/usr/bin/env python3
"""eml_reverse.py — „обратната папка“: огледало с обърнати роли и връщане в поща.

Команди:
    python eml_reverse.py mirror          # eml_in/ -> eml_reverse/ (обърнати From/To)
    python eml_reverse.py verify          # проверява, че огледалото е 1:1 с оригинала
    python eml_reverse.py restore-imap    # показва/възстановява .eml обратно в поща

Идея:
    Извличането (forensic_extract.py) върви по посока  поща → файлове.
    „Обратната папка“ върви по обратната посока:
      1) mirror        — обръща ролите на подател и получател (From ↔ To) и реда,
                         като пази тялото и прикачените файлове бит-в-бит;
      2) restore-imap  — връща оригиналните .eml обратно в IMAP папка (APPEND).

    Огледалният файл съдържа X-Reverse-Original-SHA256 — хеша на оригинала, така
    че по всяко време може да се докаже кой документ е обърнат.

Сигурност:
    * По подразбиране restore-imap е „dry-run“ — само показва какво би направил.
    * Паролата за IMAP се чете САМО от променлива на средата (виж
      imap_settings.example.json). Не се записва на диск и не се отпечатва.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import html
import imaplib
import json
import os
import re
import sys
from datetime import datetime, timezone
from email import policy
from email.parser import BytesParser
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

TOOL = "eml-reverse"
VERSION = "1.0.0"
DEFAULT_ROOT = "eml_in"
DEFAULT_OUT = "eml_reverse"
DEFAULT_SETTINGS = "imap_settings.json"
SLUG_RE = re.compile(r"[^0-9A-Za-z\u0400-\u04FF._-]+")


def utcnow_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def human_size(n: int) -> str:
    value = float(n or 0)
    for unit in ("B", "KB", "MB", "GB"):
        if value < 1024 or unit == "GB":
            return f"{value:.0f} {unit}" if unit == "B" else f"{value:.1f} {unit}"
        value /= 1024.0
    return f"{value:.1f} GB"


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def slug(text: str, fallback: str = "message", limit: int = 48) -> str:
    text = (text or "").strip()
    if not text:
        return fallback
    text = SLUG_RE.sub("_", text).strip("_")
    text = re.sub(r"_{2,}", "_", text)
    return (text[:limit] or fallback)


def body_sha(msg: Any) -> str:
    """Хеш на съдържанието (без хедърите) — за да се докаже, че тялото е непокътнато."""
    digest = hashlib.sha256()
    for part in msg.walk():
        if part.get_filename():
            digest.update(b"\x00att\x00")
            digest.update((part.get_filename() or "").encode("utf-8", "replace"))
        payload = part.get_payload(decode=False)
        if isinstance(payload, str):
            digest.update(payload.encode("utf-8", "replace"))
        elif isinstance(payload, bytes):
            digest.update(payload)
        digest.update(b"\x00part\x00")
    return digest.hexdigest()


def parse_message(path: Path):
    raw = path.read_bytes()
    msg = BytesParser(policy=policy.default).parsebytes(raw)
    return raw, msg


# ---------------------------------------------------------------- mirror

def reverse_copy(msg: Any, orig_name: str, orig_sha: str) -> Any:
    """Обръща From/To (и Reply-To) и добавя следа към оригинала."""
    out = copy.deepcopy(msg)
    frm = out.get("From")
    to = out.get("To")
    reply_to = out.get("Reply-To")

    for name in ("From", "To", "Reply-To"):
        while name in out:
            del out[name]

    if to is not None:
        out["From"] = str(to)
    if frm is not None:
        out["To"] = str(frm)
    if reply_to is not None:
        out["Reply-To"] = str(reply_to)

    out["X-Reverse-Of"] = orig_name
    out["X-Reverse-Original-SHA256"] = orig_sha
    out["X-Reverse-Generated-UTC"] = utcnow_iso()
    out["X-Reverse-Tool"] = f"{TOOL}/{VERSION}"
    return out


def cmd_mirror(args: argparse.Namespace) -> int:
    base = Path(__file__).resolve().parent
    root = Path(args.root) if Path(args.root).is_absolute() else base / args.root
    out_dir = Path(args.out) if Path(args.out).is_absolute() else base / args.out

    if not root.is_dir():
        print(f"Липсва папка: {root}", file=sys.stderr)
        return 2
    out_dir.mkdir(parents=True, exist_ok=True)

    sources: List[Path] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if not d.startswith("."))
        for name in sorted(filenames):
            if name.lower().endswith(".eml"):
                sources.append(Path(dirpath) / name)

    if not sources:
        print(f"Няма .eml файлове в {root}", file=sys.stderr)
        return 2

    prepared: List[Dict[str, Any]] = []
    for path in sources:
        try:
            raw, msg = parse_message(path)
        except Exception as exc:  # noqa: BLE001
            print(f"  ! {path.name}: {type(exc).__name__}: {exc}", file=sys.stderr)
            continue
        prepared.append(
            {
                "path": path,
                "raw": raw,
                "msg": msg,
                "sha": sha256_bytes(raw),
                "date": str(msg.get("Date") or ""),
                "subject": str(msg.get("Subject") or ""),
                "body_sha": body_sha(msg),
            }
        )

    # ред: по подразбиране „на обратно“ — най-новите първи
    prepared.sort(key=lambda item: (item["date"], item["path"].name),
                  reverse=(args.order == "newest"))

    manifest: List[Dict[str, Any]] = []
    for index, item in enumerate(prepared, start=1):
        reversed_msg = reverse_copy(item["msg"], item["path"].name, item["sha"])
        data = reversed_msg.as_bytes(
            policy=policy.default.clone(linesep="\r\n")
        )
        target = out_dir / f"{index:04d}_{slug(item['subject'], item['path'].stem)}" \
                           ".reverse.eml"
        target.write_bytes(data)
        new_body_sha = body_sha(reversed_msg)
        manifest.append(
            {
                "index": index,
                "original": item["path"].relative_to(root).as_posix(),
                "original_sha256": item["sha"],
                "original_body_sha256": item["body_sha"],
                "reverse": target.name,
                "reverse_sha256": sha256_bytes(data),
                "reverse_body_sha256": new_body_sha,
                "body_intact": new_body_sha == item["body_sha"],
                "subject": item["subject"][:200],
            }
        )
        print(
            f"  [{index:04d}] {item['path'].name} -> {target.name}"
            f"  тяло: {'OK' if manifest[-1]['body_intact'] else 'ПРОМЕНЕНО'}"
        )

    intact = sum(1 for m in manifest if m["body_intact"])
    payload = {
        "schema": "eml-reverse/v1",
        "tool": {"name": TOOL, "version": VERSION},
        "generated_utc": utcnow_iso(),
        "order": args.order,
        "root": str(root),
        "out": str(out_dir),
        "count": len(manifest),
        "bodies_intact": intact,
        "entries": manifest,
    }
    (out_dir / "reverse_manifest.json").write_text(
        json.dumps(payload, ensure_ascii=False, indent=1), encoding="utf-8"
    )
    (out_dir / "reverse_index.html").write_text(
        render_reverse_html(payload), encoding="utf-8"
    )

    print(f"Източник : {root}")
    print(f"Огледало : {out_dir}")
    print(f"Файлове  : {len(manifest)}  (тяло непокътнато: {intact})")
    if intact != len(manifest):
        print("ВНИМАНИЕ: при някои файлове тялото е променено — вижте отчета.",
              file=sys.stderr)
        return 4
    return 0


def render_reverse_html(payload: Dict[str, Any]) -> str:
    rows = []
    for entry in payload["entries"]:
        rows.append(
            "<tr>"
            f"<td>{entry['index']}</td>"
            f"<td>{html.escape(entry['original'])}</td>"
            f"<td><code>{entry['original_sha256'][:16]}</code></td>"
            f"<td><a href=\"{html.escape(entry['reverse'])}\">"
            f"{html.escape(entry['reverse'])}</a></td>"
            f"<td>{'OK' if entry['body_intact'] else 'ПРОМЕНЕНО'}</td>"
            "</tr>"
        )
    return f"""<!DOCTYPE html>
<html lang="bg"><head><meta charset="utf-8">
<title>Обратна папка — огледало на .eml</title>
<style>
 body{{font-family:"Segoe UI",system-ui,sans-serif;margin:24px;background:#f6f8fa;color:#1f2328}}
 h1{{font-size:20px;margin:0 0 6px}} .meta{{color:#59636e;font-size:13px;margin-bottom:14px}}
 table{{width:100%;border-collapse:collapse;background:#fff;border:1px solid #d1d9e0;font-size:12.5px}}
 th,td{{text-align:left;padding:7px 9px;border-bottom:1px solid #eaeef2}}
 th{{background:#f0f3f6}} code{{font-family:Consolas,monospace;font-size:11.5px}}
 a{{color:#0969da;text-decoration:none}} a:hover{{text-decoration:underline}}
</style></head><body>
<h1>Обратна папка — огледало на .eml файловете</h1>
<div class="meta">Генерирано {payload['generated_utc']} · ред: {payload['order']} ·
 {payload['count']} файла · тяло непокътнато: {payload['bodies_intact']}</div>
<table><thead><tr><th>№</th><th>оригинал</th><th>SHA-256 (ориг.)</th>
<th>огледален файл</th><th>тяло</th></tr></thead><tbody>
{''.join(rows)}
</tbody></table>
<p style="color:#59636e;font-size:12px">From и To са разменени; оригиналът е
посочен в заглавките <code>X-Reverse-Of</code> и
<code>X-Reverse-Original-SHA256</code>.</p>
</body></html>
"""


# ---------------------------------------------------------------- verify

def cmd_verify(args: argparse.Namespace) -> int:
    base = Path(__file__).resolve().parent
    root = Path(args.root) if Path(args.root).is_absolute() else base / args.root
    out_dir = Path(args.out) if Path(args.out).is_absolute() else base / args.out
    manifest_path = out_dir / "reverse_manifest.json"
    if not manifest_path.exists():
        print(f"Липсва {manifest_path}", file=sys.stderr)
        return 2

    payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    ok = 0
    problems: List[str] = []
    for entry in payload["entries"]:
        original = root / entry["original"]
        mirror = out_dir / entry["reverse"]
        if not original.exists():
            problems.append(f"липсва оригинал: {entry['original']}")
            continue
        if not mirror.exists():
            problems.append(f"липсва огледало: {entry['reverse']}")
            continue
        if sha256_bytes(original.read_bytes()) != entry["original_sha256"]:
            problems.append(f"оригиналът е променен: {entry['original']}")
            continue
        _raw, mirror_msg = parse_message(mirror)
        recorded = str(mirror_msg.get("X-Reverse-Original-SHA256") or "")
        if recorded != entry["original_sha256"]:
            problems.append(f"грешен X-Reverse-Original-SHA256: {entry['reverse']}")
            continue
        if body_sha(mirror_msg) != entry["original_body_sha256"]:
            problems.append(f"тялото се различава: {entry['reverse']}")
            continue
        ok += 1

    report = {
        "schema": "eml-reverse-verify/v1",
        "generated_utc": utcnow_iso(),
        "checked": len(payload["entries"]),
        "ok": ok,
        "problems": problems,
    }
    (out_dir / "reverse_verify.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=1), encoding="utf-8"
    )
    print(f"Проверени : {len(payload['entries'])}")
    print(f"Изрядни   : {ok}")
    for item in problems:
        print(f"  ! {item}")
    return 0 if not problems else 4


# ---------------------------------------------------------------- restore

def load_imap_settings(path: Path) -> Dict[str, Any]:
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001
        print(f"Невалиден {path.name}: {exc}", file=sys.stderr)
        return {}


def cmd_restore_imap(args: argparse.Namespace) -> int:
    base = Path(__file__).resolve().parent
    root = Path(args.root) if Path(args.root).is_absolute() else base / args.root
    settings_path = Path(args.settings)
    if not settings_path.is_absolute():
        settings_path = base / settings_path
    settings = load_imap_settings(settings_path)

    host = args.host or settings.get("host") or ""
    port = int(args.port or settings.get("port") or 993)
    user = args.user or settings.get("user") or ""
    mailbox = args.mailbox or settings.get("mailbox") or "Forensic Restore"
    password_env = settings.get("password_env") or "IMAP_PASSWORD"
    password = os.environ.get(password_env, "")
    use_ssl = bool(settings.get("ssl", True))

    files: List[Path] = []
    if root.is_dir():
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = sorted(d for d in dirnames if not d.startswith("."))
            for name in sorted(filenames):
                if name.lower().endswith(".eml"):
                    files.append(Path(dirpath) / name)
    if args.limit:
        files = files[: args.limit]

    if not files:
        print(f"Няма .eml файлове в {root}", file=sys.stderr)
        return 2

    print(f"Режим   : {'ВЪЗСТАНОВЯВАНЕ' if args.apply else 'ПРОБЕН (dry-run)'}")
    print(f"Сървър  : {host or '(не е зададен)'}:{port}  SSL={use_ssl}")
    print(f"Поща    : {user or '(не е зададена)'}  папка: {mailbox}")
    print(f"Файлове : {len(files)}")

    if not args.apply:
        for path in files:
            print(f"  + {path.name}  ({human_size(path.stat().st_size)}) -> APPEND {mailbox}")
        print("\nНищо не е променено. За реално възстановяване: --apply")
        if not host or not user:
            print(f"Забележка: попълнете {settings_path.name} (виж "
                  f"imap_settings.example.json) или подайте --host/--user.")
        if not password:
            print(f"Забележка: паролата се чете от променлива ${password_env}.")
        return 0

    if not host or not user or not password:
        print(
            f"Липсват данни за вход (host/user/${password_env}). "
            "Нищо не е променено.",
            file=sys.stderr,
        )
        return 2

    results: List[Dict[str, Any]] = []
    try:
        conn = (
            imaplib.IMAP4_SSL(host, port) if use_ssl else imaplib.IMAP4(host, port)
        )
        conn.login(user, password)
    except Exception as exc:  # noqa: BLE001
        print(f"Връзката е неуспешна: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 4

    try:
        for path in files:
            raw = path.read_bytes()
            try:
                typ, data = conn.append(mailbox, None, None, raw)
                ok = typ == "OK"
                note = (data[0].decode("utf-8", "replace")
                        if data and isinstance(data[0], bytes) else str(typ))
            except Exception as exc:  # noqa: BLE001
                ok = False
                note = f"{type(exc).__name__}: {exc}"
            results.append(
                {
                    "file": path.name,
                    "sha256": sha256_bytes(raw),
                    "appended": ok,
                    "note": note,
                }
            )
            print(f"  {'OK  ' if ok else 'ГРЕШ'} {path.name}  {note[:80]}")
    finally:
        try:
            conn.logout()
        except Exception:  # noqa: BLE001
            pass

    report = {
        "schema": "eml-restore-imap/v1",
        "generated_utc": utcnow_iso(),
        "host": host,
        "port": port,
        "user": user,
        "mailbox": mailbox,
        "count": len(results),
        "appended": sum(1 for r in results if r["appended"]),
        "entries": results,
    }
    out_dir = Path(args.out) if Path(args.out).is_absolute() else base / args.out
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "restore_imap_report.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=1), encoding="utf-8"
    )
    print(f"\nВъзстановени: {report['appended']} / {report['count']}")
    print(f"Отчет: {out_dir / 'restore_imap_report.json'}")
    return 0 if report["appended"] == report["count"] else 4


# ---------------------------------------------------------------- CLI

def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        description="Обратна папка: огледало на .eml с обърнати роли + връщане в поща"
    )
    sub = ap.add_subparsers(dest="command", required=True)

    p_mirror = sub.add_parser("mirror", help="създава огледални .eml с обърнати From/To")
    p_mirror.add_argument("--root", default=DEFAULT_ROOT)
    p_mirror.add_argument("--out", default=DEFAULT_OUT)
    p_mirror.add_argument("--order", choices=("newest", "oldest"), default="newest")
    p_mirror.set_defaults(func=cmd_mirror)

    p_verify = sub.add_parser("verify", help="проверка на огледалото")
    p_verify.add_argument("--root", default=DEFAULT_ROOT)
    p_verify.add_argument("--out", default=DEFAULT_OUT)
    p_verify.set_defaults(func=cmd_verify)

    p_restore = sub.add_parser("restore-imap", help="връща .eml в поща (IMAP APPEND)")
    p_restore.add_argument("--root", default=DEFAULT_ROOT)
    p_restore.add_argument("--out", default=DEFAULT_OUT)
    p_restore.add_argument("--settings", default=DEFAULT_SETTINGS)
    p_restore.add_argument("--host", default="")
    p_restore.add_argument("--port", type=int, default=0)
    p_restore.add_argument("--user", default="")
    p_restore.add_argument("--mailbox", default="")
    p_restore.add_argument("--limit", type=int, default=0)
    p_restore.add_argument("--apply", action="store_true",
                           help="реално записване (по подразбиране само пробен режим)")
    p_restore.set_defaults(func=cmd_restore_imap)
    return ap


def main(argv: Optional[Sequence[str]] = None) -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    args = build_parser().parse_args(list(argv) if argv is not None else None)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
