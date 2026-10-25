#!/usr/bin/env python3
"""eml_index.py — индекс с връзки за всички .eml файлове в дадена папка.

ПРАВИЛО: всеки .eml файл се свързва в индекс (HTML + Markdown + JSON) заедно
с неговия SHA-256, за да може всеки документ да бъде намерен, отворен и проверен.

Употреба:
    python eml_index.py                          # eml_in/  ->  eml_index/
    python eml_index.py --root DIR --out DIR
    python eml_index.py --max 50 --title "..."

Изходи (в --out):
    index.html      — списък с връзки (отваря се в браузър, работи и в GitHub)
    index.md        — същият списък в Markdown
    index.json      — машинно четим индекс (метаданни + SHA-256)
    SHA256SUMS.txt  — хешове за проверка (относителни пътища спрямо --root)

Инструментът е само за четене: не променя и не мести .eml файловете.
"""
from __future__ import annotations

import argparse
import hashlib
import html
import json
import os
import sys
from datetime import datetime, timezone
from email import policy
from email.parser import BytesParser
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence
from urllib.parse import quote

TOOL = "eml-index"
VERSION = "1.0.0"
DEFAULT_ROOT = "eml_in"
DEFAULT_OUT = "eml_index"
SUFFIXES = {".eml"}


# ---------------------------------------------------------------- помощни

def utcnow_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def human_size(n: int) -> str:
    value = float(n or 0)
    for unit in ("B", "KB", "MB", "GB"):
        if value < 1024 or unit == "GB":
            return f"{value:.0f} {unit}" if unit == "B" else f"{value:.1f} {unit}"
        value /= 1024.0
    return f"{value:.1f} GB"


def one_line(value: Any, limit: int = 300) -> str:
    if value is None:
        return ""
    text = " ".join(str(value).split())
    return text[:limit]


def header_text(msg: Any, name: str) -> str:
    try:
        value = msg.get(name)
    except Exception:  # noqa: BLE001
        return ""
    return one_line(value) if value is not None else ""


def parse_one(path: Path, root: Path) -> Dict[str, Any]:
    rel = path.relative_to(root).as_posix()
    st = path.stat()
    rec: Dict[str, Any] = {
        "file": rel,
        "abs_path": str(path),
        "size": st.st_size,
        "mtime_utc": datetime.fromtimestamp(st.st_mtime, timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        ),
        "sha256": "",
        "from": "",
        "to": "",
        "cc": "",
        "subject": "",
        "date_utc": "",
        "message_id": "",
        "attachments": 0,
        "content_type": "",
        "error": "",
    }
    try:
        raw = path.read_bytes()
    except Exception as exc:  # noqa: BLE001
        rec["error"] = f"read: {type(exc).__name__}: {exc}"
        return rec

    rec["sha256"] = sha256_bytes(raw)

    try:
        msg = BytesParser(policy=policy.default).parsebytes(raw)
    except Exception as exc:  # noqa: BLE001
        rec["error"] = f"parse: {type(exc).__name__}: {exc}"
        return rec

    rec["from"] = header_text(msg, "From")
    rec["to"] = header_text(msg, "To")
    rec["cc"] = header_text(msg, "Cc")
    rec["subject"] = header_text(msg, "Subject")
    rec["message_id"] = header_text(msg, "Message-ID")
    rec["content_type"] = one_line(msg.get_content_type(), 60)

    raw_date = msg.get("Date")
    if raw_date is not None:
        try:
            rec["date_utc"] = (
                parsedate_to_datetime(str(raw_date))
                .astimezone(timezone.utc)
                .strftime("%Y-%m-%dT%H:%M:%SZ")
            )
        except Exception:  # noqa: BLE001
            rec["date_utc"] = one_line(raw_date, 40)

    try:
        rec["attachments"] = sum(1 for part in msg.walk() if part.get_filename())
    except Exception:  # noqa: BLE001
        rec["attachments"] = 0

    return rec


def collect(root: Path, out_dir: Path, max_files: int) -> List[Dict[str, Any]]:
    out_resolved = out_dir.resolve()
    records: List[Dict[str, Any]] = []
    for dirpath, dirnames, filenames in os.walk(root):
        current = Path(dirpath)
        # не влизаме в изходната папка и в скрити папки
        dirnames[:] = sorted(
            d
            for d in dirnames
            if not d.startswith(".")
            and (current / d).resolve() != out_resolved
        )
        for name in sorted(filenames):
            if Path(name).suffix.lower() not in SUFFIXES:
                continue
            if name.startswith("."):
                continue
            path = current / name
            try:
                records.append(parse_one(path, root))
            except Exception as exc:  # noqa: BLE001
                records.append(
                    {
                        "file": path.relative_to(root).as_posix(),
                        "abs_path": str(path),
                        "size": 0,
                        "sha256": "",
                        "error": f"stat: {type(exc).__name__}: {exc}",
                    }
                )
            if max_files and len(records) >= max_files:
                return records
    return records


def sort_key(rec: Dict[str, Any]):
    return (rec.get("date_utc") or "9999", rec.get("file") or "")


# ---------------------------------------------------------------- изходи

def link_for(rec: Dict[str, Any], out_dir: Path) -> str:
    """Относителна връзка от index.html към .eml файла."""
    target = Path(rec["abs_path"])
    try:
        rel = os.path.relpath(target, out_dir).replace(os.sep, "/")
    except ValueError:
        rel = target.as_posix()
    return quote(rel, safe="/:")


def render_markdown(records: List[Dict[str, Any]], out_dir: Path,
                    root: Path) -> str:
    total_bytes = sum(int(r.get("size") or 0) for r in records)
    uniq = len({r["sha256"] for r in records if r.get("sha256")})
    lines = [
        "# Индекс на .eml файловете",
        "",
        f"- Генериран: `{utcnow_iso()}`",
        f"- Източник: `{root.as_posix()}`",
        f"- Файлове: **{len(records)}** · уникални хешове: **{uniq}** · "
        f"общ обем: **{human_size(total_bytes)}**",
        "",
        "| № | дата (UTC) | от | до | тема | разм. | SHA-256 | файл |",
        "|---:|---|---|---|---|---:|---|---|",
    ]
    for i, rec in enumerate(records, start=1):
        lines.append(
            "| {i} | {date} | {frm} | {to} | {subj} | {size} | `{sha}` | [{name}]({href}) |".format(
                i=i,
                date=(rec.get("date_utc") or "—").replace("T", " ").replace("Z", ""),
                frm=(rec.get("from") or "—").replace("|", "\\|")[:60],
                to=(rec.get("to") or "—").replace("|", "\\|")[:60],
                subj=(rec.get("subject") or "—").replace("|", "\\|")[:80],
                size=human_size(int(rec.get("size") or 0)),
                sha=(rec.get("sha256") or "")[:16],
                name=(rec.get("file") or "").replace("|", "\\|"),
                href=link_for(rec, out_dir),
            )
        )
    lines.append("")
    return "\n".join(lines)


HTML_HEAD = """<!DOCTYPE html>
<html lang="bg">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title}</title>
<style>
  :root {{ color-scheme: light dark; }}
  body {{ font-family: "Segoe UI", system-ui, sans-serif; margin: 0; padding: 24px;
         background: #f6f8fa; color: #1f2328; }}
  h1 {{ font-size: 20px; margin: 0 0 4px; }}
  .meta {{ color: #59636e; font-size: 13px; margin-bottom: 16px; }}
  .stats {{ display: flex; gap: 12px; flex-wrap: wrap; margin-bottom: 16px; }}
  .card {{ background: #fff; border: 1px solid #d1d9e0; border-radius: 6px;
           padding: 10px 14px; min-width: 120px; }}
  .card b {{ display: block; font-size: 18px; }}
  .card span {{ color: #59636e; font-size: 12px; }}
  table {{ width: 100%; border-collapse: collapse; background: #fff;
           border: 1px solid #d1d9e0; border-radius: 6px; overflow: hidden;
           font-size: 12.5px; }}
  th, td {{ text-align: left; padding: 7px 9px; border-bottom: 1px solid #eaeef2;
            vertical-align: top; }}
  th {{ background: #f0f3f6; position: sticky; top: 0; font-weight: 600; }}
  tr:hover td {{ background: #f6f8fa; }}
  td.num {{ text-align: right; white-space: nowrap; }}
  code {{ font-family: Consolas, monospace; font-size: 11.5px; }}
  a {{ color: #0969da; text-decoration: none; }}
  a:hover {{ text-decoration: underline; }}
  .err {{ color: #b42318; font-weight: 600; }}
  footer {{ margin-top: 18px; color: #59636e; font-size: 12px; }}
</style>
</head>
<body>
<h1>{title}</h1>
<div class="meta">Генериран {generated} · източник <code>{root}</code> · {tool} v{version}</div>
<div class="stats">
  <div class="card"><b>{count}</b><span>.eml файла</span></div>
  <div class="card"><b>{uniq}</b><span>уникални хеша</span></div>
  <div class="card"><b>{size}</b><span>общ обем</span></div>
  <div class="card"><b>{atts}</b><span>прикачени файла</span></div>
  <div class="card"><b>{dups}</b><span>дубликата</span></div>
</div>
<table>
<thead>
<tr><th>№</th><th>Дата (UTC)</th><th>От</th><th>До</th><th>Тема</th>
<th>Прик.</th><th>Размер</th><th>SHA-256</th><th>Файл</th></tr>
</thead>
<tbody>
"""

HTML_TAIL = """</tbody>
</table>
<footer>Всеки ред сочи към съответния .eml файл. Хешът е SHA-256 на целия файл —
сравнете го с <code>SHA256SUMS.txt</code> преди да използвате документа.</footer>
</body>
</html>
"""


def render_html(records: List[Dict[str, Any]], out_dir: Path, root: Path,
                title: str) -> str:
    total_bytes = sum(int(r.get("size") or 0) for r in records)
    hashes = [r["sha256"] for r in records if r.get("sha256")]
    uniq = len(set(hashes))
    atts = sum(int(r.get("attachments") or 0) for r in records)
    parts = [
        HTML_HEAD.format(
            title=html.escape(title),
            generated=utcnow_iso(),
            root=str(root),
            tool=TOOL,
            version=VERSION,
            count=len(records),
            uniq=uniq,
            size=human_size(total_bytes),
            atts=atts,
            dups=len(hashes) - uniq,
        )
    ]
    for i, rec in enumerate(records, start=1):
        href = link_for(rec, out_dir)
        err = rec.get("error") or ""
        parts.append(
            "<tr>"
            f'<td class="num">{i}</td>'
            f"<td>{(rec.get('date_utc') or '—')[:19].replace('T', ' ')}</td>"
            f"<td>{html.escape((rec.get('from') or '—')[:120])}</td>"
            f"<td>{html.escape((rec.get('to') or '—')[:120])}</td>"
            f"<td>{html.escape((rec.get('subject') or '—')[:160])}"
            + (f' <span class="err">{html.escape(err)}</span>' if err else "")
            + "</td>"
            f'<td class="num">{int(rec.get("attachments") or 0)}</td>'
            f'<td class="num">{human_size(int(rec.get("size") or 0))}</td>'
            f'<td><code title="{html.escape(rec.get("sha256") or "")}">'
            f"{(rec.get('sha256') or '')[:16]}</code></td>"
            f'<td><a href="{html.escape(href)}">{html.escape(rec.get("file") or "")}</a></td>'
            "</tr>"
        )
    parts.append(HTML_TAIL)
    return "".join(parts)


def render_sums(records: List[Dict[str, Any]]) -> str:
    lines = [f"{r['sha256']}  {r['file']}" for r in records if r.get("sha256")]
    return "\n".join(sorted(lines)) + "\n"


# ---------------------------------------------------------------- main

def main(argv: Optional[Sequence[str]] = None) -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")

    ap = argparse.ArgumentParser(description="Индекс с връзки за всички .eml файлове")
    ap.add_argument("--root", default=DEFAULT_ROOT, help=f"папка с .eml ({DEFAULT_ROOT})")
    ap.add_argument("--out", default=DEFAULT_OUT, help=f"папка за индекса ({DEFAULT_OUT})")
    ap.add_argument("--title", default="Индекс на .eml файловете")
    ap.add_argument("--max", type=int, default=0, help="максимум файлове (0 = без лимит)")
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args(list(argv) if argv is not None else None)

    base = Path(__file__).resolve().parent
    root = Path(args.root)
    if not root.is_absolute():
        root = base / root
    out_dir = Path(args.out)
    if not out_dir.is_absolute():
        out_dir = base / out_dir

    if not root.is_dir():
        print(f"Липсва папка: {root}", file=sys.stderr)
        return 2

    out_dir.mkdir(parents=True, exist_ok=True)
    records = sorted(collect(root, out_dir, args.max), key=sort_key)

    (out_dir / "index.json").write_text(
        json.dumps(
            {
                "schema": "eml-index/v1",
                "tool": {"name": TOOL, "version": VERSION},
                "generated_utc": utcnow_iso(),
                "root": str(root),
                "count": len(records),
                "records": records,
            },
            ensure_ascii=False,
            indent=1,
        ),
        encoding="utf-8",
    )
    (out_dir / "index.md").write_text(
        render_markdown(records, out_dir, root), encoding="utf-8"
    )
    (out_dir / "index.html").write_text(
        render_html(records, out_dir, root, args.title), encoding="utf-8"
    )
    (out_dir / "SHA256SUMS.txt").write_text(
        render_sums(records), encoding="utf-8"
    )

    if not args.quiet:
        hashes = [r["sha256"] for r in records if r.get("sha256")]
        errors = [r for r in records if r.get("error")]
        print(f"Източник : {root}")
        print(f"Индекс   : {out_dir}")
        print(f"Файлове  : {len(records)}  (уникални {len(set(hashes))})")
        print(f"Обем     : {human_size(sum(int(r.get('size') or 0) for r in records))}")
        print(f"Прикачени: {sum(int(r.get('attachments') or 0) for r in records)}")
        if errors:
            print(f"Грешки   : {len(errors)}")
            for rec in errors[:5]:
                print(f"  ! {rec.get('file')}: {rec.get('error')}")
        print(f"Отвори   : {(out_dir / 'index.html')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
