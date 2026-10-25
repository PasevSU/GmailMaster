#!/usr/bin/env python3
"""pgp_sign.py — PGP/GnuPG подпис и проверка на доказателствени файлове.

Команди:
    python pgp_sign.py keys                     # списък на тайните ключове
    python pgp_sign.py sign                     # .asc подпис за всеки .eml + подписан манифест
    python pgp_sign.py verify                   # проверка на всички подписи и хешове
    python pgp_sign.py gen-key                  # създаване на нов ключ (по избор)

Поведение:
    * За всеки .eml се създава деташиран подпис  <файл>.asc  (ASCII armored).
    * Създава се  SHA256SUMS.txt  (хешове на всички подписани файлове) и неговият
      подпис  SHA256SUMS.txt.asc  — един подпис, който покрива целия комплект.
    * Отчет:  pgp_sign_report.json / .md

Сигурност:
    * Паролата на ключа НЕ се пише на диск. Ако ключът е защитен, задайте я в
      променлива на средата GPG_PASSPHRASE (или използвайте ключ без парола).
    * Ключът се избира с --key, иначе се използва ключът по подразбиране на GnuPG.

Употреба:
    $env:GPG_PASSPHRASE = "..."; python pgp_sign.py sign
    python pgp_sign.py verify
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

TOOL = "pgp-sign"
VERSION = "1.0.0"
DEFAULT_ROOT = "eml_in"
DEFAULT_OUT = "eml_index"
MANIFEST = "SHA256SUMS.txt"
PASSPHRASE_ENV = "GPG_PASSPHRASE"

GPG_CANDIDATES = (
    os.environ.get("GPG_BIN"),
    shutil.which("gpg"),
    shutil.which("gpg2"),
    r"C:\Program Files\GnuPG\bin\gpg.exe",
    r"C:\Program Files (x86)\GnuPG\bin\gpg.exe",
    r"C:\Program Files (x86)\Gpg4win\bin\gpg.exe",
    r"C:\Program Files\Git\usr\bin\gpg.exe",
    "/usr/bin/gpg",
)


def utcnow_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def human_size(n: int) -> str:
    value = float(n or 0)
    for unit in ("B", "KB", "MB", "GB"):
        if value < 1024 or unit == "GB":
            return f"{value:.0f} {unit}" if unit == "B" else f"{value:.1f} {unit}"
        value /= 1024.0
    return f"{value:.1f} GB"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def find_gpg() -> str:
    for candidate in GPG_CANDIDATES:
        if candidate and Path(candidate).exists():
            return str(candidate)
    raise SystemExit(
        "GnuPG не е намерен. Инсталирайте Gpg4win или задайте GPG_BIN."
    )


class Gpg:
    """Тънка обвивка около gpg, без интерактивни покани за парола."""

    def __init__(self, homedir: Optional[str] = None) -> None:
        self.exe = find_gpg()
        self.homedir = homedir
        self.passphrase = os.environ.get(PASSPHRASE_ENV) or ""

    def base(self) -> List[str]:
        cmd = [self.exe, "--batch", "--yes", "--no-tty", "--no-greeting"]
        if self.homedir:
            cmd += ["--homedir", self.homedir]
        return cmd

    def run(self, args: Sequence[str], use_passphrase: bool = False) -> Tuple[int, str, str]:
        cmd = self.base() + list(args)
        data = None
        if use_passphrase and self.passphrase:
            cmd += ["--pinentry-mode", "loopback", "--passphrase-fd", "0"]
            data = (self.passphrase + "\n").encode("utf-8")
        proc = subprocess.run(
            cmd, input=data, capture_output=True, text=bool(True), check=False
        )
        out = proc.stdout if isinstance(proc.stdout, str) else proc.stdout.decode(
            "utf-8", "replace"
        )
        err = proc.stderr if isinstance(proc.stderr, str) else proc.stderr.decode(
            "utf-8", "replace"
        )
        return proc.returncode, out, err

    def secret_keys(self) -> List[Dict[str, str]]:
        code, out, err = self.run(["--with-colons", "--list-secret-keys"])
        if code not in (0, 2) and not out:
            raise SystemExit(f"gpg --list-secret-keys неуспешно: {err.strip()}")
        keys: List[Dict[str, str]] = []
        current: Optional[Dict[str, str]] = None
        for line in out.splitlines():
            fields = line.split(":")
            kind = fields[0]
            if kind == "sec":
                current = {
                    "keyid": fields[4],
                    "algo": fields[3],
                    "bits": fields[2],
                    "created": fields[5],
                    "caps": fields[11] if len(fields) > 11 else "",
                    "fpr": "",
                    "uid": "",
                }
                keys.append(current)
            elif kind == "fpr" and current is not None and not current["fpr"]:
                current["fpr"] = fields[9]
            elif kind == "uid" and current is not None and not current["uid"]:
                current["uid"] = fields[9].replace("\\x3a", ":")
        return keys


def default_key(gpg: Gpg) -> Optional[str]:
    keys = gpg.secret_keys()
    if not keys:
        return None
    capable = [k for k in keys if "S" in (k.get("caps") or "")]
    chosen = (capable or keys)[0]
    return chosen.get("fpr") or chosen.get("keyid")


def gather_targets(root: Path, out_dir: Path) -> List[Path]:
    targets: List[Path] = []
    if root.is_dir():
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = sorted(d for d in dirnames if not d.startswith("."))
            for name in sorted(filenames):
                if name.lower().endswith(".eml"):
                    targets.append(Path(dirpath) / name)
    for name in ("index.html", "index.md", "index.json"):
        candidate = out_dir / name
        if candidate.exists() and candidate not in targets:
            targets.append(candidate)
    return targets


def short_path(value: str, payload: Dict[str, Any]) -> str:
    """Показва пътя относително към root/out, за да не се пренася таблицата."""
    if not value:
        return "—"
    path = Path(value)
    for base_key in ("root", "out"):
        base = payload.get(base_key)
        if not base:
            continue
        try:
            rel = Path(os.path.relpath(path, base)).as_posix()
        except Exception:  # noqa: BLE001
            continue
        if not rel.startswith(".."):
            return rel
    return path.name


def write_report(out_dir: Path, payload: Dict[str, Any]) -> None:
    (out_dir / "pgp_sign_report.json").write_text(
        json.dumps(payload, ensure_ascii=False, indent=1), encoding="utf-8"
    )
    lines = [
        "# PGP отчет",
        "",
        f"- Операция: **{payload['operation']}**",
        f"- Дата (UTC): `{payload['generated_utc']}`",
        f"- Ключ: `{payload.get('key') or '—'}`",
        f"- GnuPG: `{payload.get('gpg')}`",
        f"- Успешни: **{payload['ok']}** · неуспешни: **{payload['failed']}**",
        "",
    ]
    if payload.get("entries"):
        lines += [
            "| файл | резултат | подпис | бележка |",
            "| --- | --- | --- | --- |",
        ]
        for item in payload["entries"]:
            lines.append(
                "| `{f}` | {r} | `{s}` | {n} |".format(
                    f=short_path(item.get("file") or "", payload),
                    r=item.get("result"),
                    s=(item.get("sig") or "—"),
                    n=(item.get("note") or "").replace("|", "\\|"),
                )
            )
        lines.append("")
    if payload.get("errors"):
        lines += ["## Грешки", ""]
        lines += [f"- `{e}`" for e in payload["errors"]]
        lines.append("")
    (out_dir / "pgp_sign_report.md").write_text("\n".join(lines), encoding="utf-8")


# ---------------------------------------------------------------- команди

def cmd_keys(args: argparse.Namespace) -> int:
    gpg = Gpg(args.gnupg_home)
    keys = gpg.secret_keys()
    if not keys:
        print("Няма тайни ключове в keyring-а.")
        return 3
    print(f"GnuPG: {gpg.exe}")
    print(f"{'ключ':>17}  {'алго':<6} {'създаден':<12} uid")
    for key in keys:
        print(
            f"{key['keyid']:>17}  {key['algo'] + '/' + key['bits']:<6} "
            f"{key['created'][:8]:<12} {key['uid'][:70]}"
        )
    return 0


def cmd_sign(args: argparse.Namespace) -> int:
    base = Path(__file__).resolve().parent
    root = Path(args.root) if Path(args.root).is_absolute() else base / args.root
    out_dir = Path(args.out) if Path(args.out).is_absolute() else base / args.out
    out_dir.mkdir(parents=True, exist_ok=True)

    gpg = Gpg(args.gnupg_home)
    key = args.key or default_key(gpg)
    payload: Dict[str, Any] = {
        "schema": "pgp-sign-report/v1",
        "tool": {"name": TOOL, "version": VERSION},
        "operation": "sign",
        "generated_utc": utcnow_iso(),
        "gpg": gpg.exe,
        "key": key,
        "operator": os.environ.get("USERNAME") or os.environ.get("USER") or "",
        "root": str(root),
        "out": str(out_dir),
        "entries": [],
        "errors": [],
        "ok": 0,
        "failed": 0,
    }

    if not key:
        msg = (
            "Няма таен ключ за подпис. Създайте ключ с: "
            f"python pgp_sign.py gen-key \"Име <email>\""
        )
        print(msg, file=sys.stderr)
        payload["errors"].append(msg)
        write_report(out_dir, payload)
        return 3

    targets = gather_targets(root, out_dir)
    if not targets:
        print("Няма файлове за подпис (.eml / индекс).", file=sys.stderr)
        return 2

    use_pp = bool(gpg.passphrase)
    for target in targets:
        sig = target.with_suffix(target.suffix + ".asc")
        if sig.exists() and not args.force:
            payload["entries"].append(
                {"file": str(target), "result": "пропуснат", "sig": sig.name,
                 "note": "подписът вече съществува (--force за презапис)"}
            )
            continue
        code, _out, err = gpg.run(
            ["--armor", "--detach-sign", "--local-user", key,
             "--output", str(sig), str(target)],
            use_passphrase=use_pp,
        )
        if code == 0 and sig.exists():
            payload["ok"] += 1
            payload["entries"].append(
                {"file": str(target), "result": "подписан", "sig": sig.name,
                 "note": human_size(sig.stat().st_size)}
            )
        else:
            payload["failed"] += 1
            note = (err.strip().splitlines() or ["неизвестна грешка"])[-1]
            payload["entries"].append(
                {"file": str(target), "result": "ГРЕШКА", "sig": "", "note": note}
            )
            payload["errors"].append(f"{target.name}: {note}")

    # --- манифест с хешове + неговият подпис ---
    if not args.no_manifest:
        manifest_path = out_dir / MANIFEST
        lines = []
        for target in sorted(targets):
            try:
                rel = Path(os.path.relpath(target, out_dir)).as_posix()
                lines.append(f"{sha256_file(target)}  {rel}")
            except Exception as exc:  # noqa: BLE001
                payload["errors"].append(f"{target.name}: {exc}")
        manifest_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        sig = manifest_path.with_suffix(manifest_path.suffix + ".asc")
        code, _out, err = gpg.run(
            ["--armor", "--detach-sign", "--local-user", key,
             "--output", str(sig), str(manifest_path)],
            use_passphrase=use_pp,
        )
        if code == 0:
            payload["ok"] += 1
            payload["manifest"] = {"file": str(manifest_path.name),
                                   "sig": sig.name, "lines": len(lines)}
            payload["entries"].append(
                {"file": manifest_path.name, "result": "подписан",
                 "sig": sig.name, "note": f"{len(lines)} записа"}
            )
        else:
            payload["failed"] += 1
            note = (err.strip().splitlines() or ["неизвестна грешка"])[-1]
            payload["entries"].append(
                {"file": manifest_path.name, "result": "ГРЕШКА", "sig": "",
                 "note": note}
            )
            payload["errors"].append(f"{MANIFEST}: {note}")

    payload["finished_utc"] = utcnow_iso()
    write_report(out_dir, payload)

    print(f"GnuPG   : {gpg.exe}")
    print(f"Ключ    : {key}")
    print(f"Файлове : {len(targets)}")
    print(f"Успешни : {payload['ok']}   Неуспешни: {payload['failed']}")
    if payload["failed"]:
        for entry in payload["entries"]:
            if entry["result"] == "ГРЕШКА":
                print(f"  ! {entry['file']}: {entry['note']}")
        joined = " ".join(payload["errors"]).lower()
        if not use_pp and any(
            token in joined
            for token in ("passphrase", "cancelled", "canceled", "no pinentry", "pinentry")
        ):
            print(
                "Съвет: ключът изглежда защитен с парола. Задайте я и опитайте пак:",
                file=sys.stderr,
            )
            print(f"  $env:{PASSPHRASE_ENV} = '...'  # или ключ без парола", file=sys.stderr)
        return 4
    print(f"Отчет   : {out_dir / 'pgp_sign_report.md'}")
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    base = Path(__file__).resolve().parent
    root = Path(args.root) if Path(args.root).is_absolute() else base / args.root
    out_dir = Path(args.out) if Path(args.out).is_absolute() else base / args.out

    gpg = Gpg(args.gnupg_home)
    payload: Dict[str, Any] = {
        "schema": "pgp-sign-report/v1",
        "tool": {"name": TOOL, "version": VERSION},
        "operation": "verify",
        "generated_utc": utcnow_iso(),
        "gpg": gpg.exe,
        "key": args.key or "",
        "root": str(root),
        "out": str(out_dir),
        "entries": [],
        "errors": [],
        "ok": 0,
        "failed": 0,
    }

    signatures = sorted(
        list(out_dir.glob("*.asc")) + list(root.glob("**/*.asc"))
    )
    seen = set()
    for sig in signatures:
        if sig in seen:
            continue
        seen.add(sig)
        target = Path(str(sig)[: -len(".asc")])
        if not target.exists():
            payload["failed"] += 1
            payload["entries"].append(
                {"file": sig.name, "result": "ЛИПСВА ФАЙЛ", "sig": sig.name,
                 "note": f"няма {target.name}"}
            )
            continue
        code, out, err = gpg.run(["--verify", str(sig), str(target)])
        good = code == 0 and "Good signature" in (err + out)
        if good:
            payload["ok"] += 1
            fingerprint = ""
            for line in err.splitlines():
                if "using" in line and "key" in line:
                    fingerprint = line.strip()
            payload["entries"].append(
                {"file": target.name, "result": "ВАЛИДЕН", "sig": sig.name,
                 "note": fingerprint[-60:]}
            )
        else:
            payload["failed"] += 1
            note = (err.strip().splitlines() or ["невалиден подпис"])[-1]
            payload["entries"].append(
                {"file": target.name, "result": "НЕВАЛИДЕН", "sig": sig.name,
                 "note": note}
            )
            payload["errors"].append(f"{target.name}: {note}")

    # --- проверка на хешовете в манифеста ---
    manifest = out_dir / MANIFEST
    if manifest.exists():
        for line in manifest.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split("  ", 1)
            if len(parts) != 2:
                continue
            expected, rel = parts
            target = (out_dir / rel).resolve()
            if not target.exists():
                payload["failed"] += 1
                payload["errors"].append(f"липсва файл от манифеста: {rel}")
                continue
            actual = sha256_file(target)
            if actual != expected:
                payload["failed"] += 1
                payload["errors"].append(f"хеш несъответствие: {rel}")
                payload["entries"].append(
                    {"file": target.name, "result": "ХЕШ ГРЕШКА", "sig": "—",
                     "note": rel}
                )
            else:
                payload["ok"] += 1

    payload["finished_utc"] = utcnow_iso()
    write_report(out_dir, payload)

    print(f"Проверени подписа: {len(seen)}")
    print(f"Успешни: {payload['ok']}   Неуспешни: {payload['failed']}")
    for entry in payload["entries"]:
        if entry["result"] not in ("ВАЛИДЕН",):
            print(f"  ! {entry['file']}: {entry['result']} {entry['note']}")
    return 0 if payload["failed"] == 0 else 4


def cmd_gen_key(args: argparse.Namespace) -> int:
    gpg = Gpg(args.gnupg_home)
    uid = args.uid
    if not uid or "<" not in uid:
        print('Формат: python pgp_sign.py gen-key "Име <email>"', file=sys.stderr)
        return 2
    passphrase = os.environ.get(PASSPHRASE_ENV) or ""
    args_run: List[str] = [
        "--pinentry-mode", "loopback", "--passphrase-fd", "0",
        "--quick-generate-key", uid, "default", "default", "never",
    ]
    proc = subprocess.run(
        gpg.base() + args_run,
        input=(passphrase + "\n").encode("utf-8"),
        capture_output=True,
        check=False,
    )
    code = proc.returncode
    err = proc.stderr.decode("utf-8", "replace")
    if code != 0:
        print(f"Грешка при създаване на ключ: {err.strip()}", file=sys.stderr)
        return 4
    print("Ключът е създаден.")
    return cmd_keys(args)


# ---------------------------------------------------------------- CLI

def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(description="PGP подпис и проверка на .eml комплект")
    ap.add_argument("--gnupg-home", default=None, help="алтернативен GNUPGHOME")
    sub = ap.add_subparsers(dest="command", required=True)

    p_keys = sub.add_parser("keys", help="списък на тайните ключове")
    p_keys.set_defaults(func=cmd_keys)

    p_sign = sub.add_parser("sign", help="подписване на .eml + манифест")
    p_sign.add_argument("--root", default=DEFAULT_ROOT)
    p_sign.add_argument("--out", default=DEFAULT_OUT)
    p_sign.add_argument("--key", default=None, help="ключ (пръстов отпечатък или ID)")
    p_sign.add_argument("--force", action="store_true", help="презапис на съществуващи .asc")
    p_sign.add_argument("--no-manifest", action="store_true")
    p_sign.set_defaults(func=cmd_sign)

    p_verify = sub.add_parser("verify", help="проверка на подписи и хешове")
    p_verify.add_argument("--root", default=DEFAULT_ROOT)
    p_verify.add_argument("--out", default=DEFAULT_OUT)
    p_verify.add_argument("--key", default=None)
    p_verify.set_defaults(func=cmd_verify)

    p_gen = sub.add_parser("gen-key", help="създаване на нов ключ")
    p_gen.add_argument("uid", nargs="?", default="", help='"Име <email>"')
    p_gen.set_defaults(func=cmd_gen_key)
    return ap


def main(argv: Optional[Sequence[str]] = None) -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    args = build_parser().parse_args(list(argv) if argv is not None else None)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
