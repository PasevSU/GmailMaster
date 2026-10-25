#!/usr/bin/env python3
"""
forensic_report.py — чете готов forensic run каталог и генерира човешки отчет.

Само четене. Не променя нищо в run каталога освен добавянето на
`forensic_report.md` (и по избор `forensic_report.json`).

Употреба:
    python forensic_report.py forensic_out\\run_<ID>
    python forensic_report.py forensic_out\\run_<ID> --json
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")


def load_records(run_dir: Path) -> tuple[List[Dict[str, Any]], str]:
    """Зарежда JSONL (с прикачени файлове, ако е налично, иначе базовия файл)."""
    with_att = run_dir / "evidence_records_with_attachments.jsonl"
    base = run_dir / "evidence_records.jsonl"
    src = with_att if with_att.exists() else base
    if not src.exists():
        raise SystemExit(f"Липсва evidence файл в {run_dir}")
    records: List[Dict[str, Any]] = []
    with src.open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                records.append(json.loads(line))
    return records, src.name


def domain_of(addr: str) -> str:
    return addr.rsplit("@", 1)[-1].lower() if "@" in addr else ""


def header(rec: Dict[str, Any], name: str) -> str:
    headers = rec.get("headers") or {}
    for key, value in headers.items():
        if key.lower() == name.lower():
            if isinstance(value, list):
                return ", ".join(value)
            return value or ""
    return ""


def build_stats(records: List[Dict[str, Any]]) -> Dict[str, Any]:
    senders: Counter = Counter()
    sender_domains: Counter = Counter()
    matched: Counter = Counter()
    per_month: Counter = Counter()
    per_domain_month: Dict[str, Counter] = defaultdict(Counter)
    attachments_total = 0
    attachments_hashed = 0
    attachments_bytes = 0
    by_ext: Counter = Counter()
    with_attachment = 0
    dates: List[datetime] = []
    subjects_sample: List[str] = []

    for rec in records:
        frm = header(rec, "From")
        addrs = EMAIL_RE.findall(frm)
        sender = addrs[0].lower() if addrs else (frm.strip().lower() or "(неизвестен)")
        senders[sender] += 1
        dom = domain_of(sender)
        sender_domains[dom] += 1

        for d in rec.get("matched_domains") or []:
            matched[d] += 1

        ts = rec.get("internal_date_utc")
        if ts:
            try:
                dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                dates.append(dt)
                key = dt.strftime("%Y-%m")
                per_month[key] += 1
                if dom:
                    per_domain_month[dom][key] += 1
            except ValueError:
                pass

        atts = rec.get("attachments") or []
        if atts:
            with_attachment += 1
        for att in atts:
            attachments_total += 1
            attachments_bytes += int(att.get("size_bytes") or 0)
            if att.get("hashed"):
                attachments_hashed += 1
            name = (att.get("filename") or "").lower()
            ext = name.rsplit(".", 1)[-1] if "." in name else "(без разширение)"
            by_ext[ext[:12]] += 1

        subj = header(rec, "Subject").strip()
        if subj and len(subjects_sample) < 12:
            subjects_sample.append(subj)

    return {
        "records": len(records),
        "senders": senders,
        "sender_domains": sender_domains,
        "matched": matched,
        "per_month": per_month,
        "per_domain_month": per_domain_month,
        "attachments_total": attachments_total,
        "attachments_hashed": attachments_hashed,
        "attachments_bytes": attachments_bytes,
        "by_ext": by_ext,
        "with_attachment": with_attachment,
        "first": min(dates) if dates else None,
        "last": max(dates) if dates else None,
        "subjects_sample": subjects_sample,
    }


def fmt_bytes(n: int) -> str:
    value = float(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if value < 1024 or unit == "TB":
            return f"{value:.1f} {unit}" if unit != "B" else f"{int(value)} B"
        value /= 1024
    return f"{n} B"


def load_custody(run_dir: Path) -> Dict[str, Any]:
    for name in ("chain_of_custody_phase2.json", "chain_of_custody.json"):
        path = run_dir / name
        if path.exists():
            try:
                return json.loads(path.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                continue
    return {}


def render(run_dir: Path, records: List[Dict[str, Any]], source: str, stats: Dict[str, Any], custody: Dict[str, Any]) -> str:
    out: List[str] = []
    add = out.append

    add(f"# Форензик отчет — {run_dir.name}\n")
    add(f"- Генериран: `{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%SZ')}`")
    add(f"- Източник на записите: `{source}`")
    add(f"- Брой записи: **{stats['records']}**")
    if stats["first"] and stats["last"]:
        add(f"- Период: **{stats['first'].strftime('%Y-%m-%d')} → {stats['last'].strftime('%Y-%m-%d')}** (UTC)")
    add(f"- Съобщения с прикачени файлове: **{stats['with_attachment']}**")
    add(f"- Прикачени файлове: **{stats['attachments_total']}**, общ обем **{fmt_bytes(stats['attachments_bytes'])}**, хеширани **{stats['attachments_hashed']}**")
    if custody.get("records_digest"):
        add(f"- `records_digest`: `{custody['records_digest']}`")
    add("")

    add("## Съвпадения по домейн от филтъра\n")
    add("| Домейн | Съобщения |")
    add("|---|---:|")
    for dom, count in stats["matched"].most_common():
        add(f"| {dom} | {count} |")
    add("")

    add("## Топ 15 податели\n")
    add("| Подател | Съобщения |")
    add("|---|---:|")
    for sender, count in stats["senders"].most_common(15):
        add(f"| {sender} | {count} |")
    add("")

    add("## Топ 10 домейна на подател\n")
    add("| Домейн | Съобщения |")
    add("|---|---:|")
    for dom, count in stats["sender_domains"].most_common(10):
        add(f"| {dom or '(неизвестен)'} | {count} |")
    add("")

    add("## Обем по месеци\n")
    add("| Месец | Съобщения |")
    add("|---|---:|")
    for month in sorted(stats["per_month"]):
        add(f"| {month} | {stats['per_month'][month]} |")
    add("")

    if stats["by_ext"]:
        add("## Видове прикачени файлове (по разширение)\n")
        add("| Разширение | Брой |")
        add("|---|---:|")
        for ext, count in stats["by_ext"].most_common(15):
            add(f"| .{ext} | {count} |")
        add("")

    if stats["subjects_sample"]:
        add("## Примерни теми (първи 12)\n")
        for subj in stats["subjects_sample"]:
            add(f"- {subj}")
        add("")

    outputs = custody.get("outputs") or []
    if outputs:
        add("## Хешове на изходните файлове (SHA-256)\n")
        add("| Файл | Размер | SHA-256 |")
        add("|---|---:|---|")
        for item in outputs:
            label = item.get("file") or item.get("name") or "(без име)"
            add(f"| `{label}` | {item.get('size_bytes')} | `{item.get('sha256')}` |")
        add("")

    if custody.get("custody_statement"):
        add("## Декларация за веригата на съхранение\n")
        add(custody["custody_statement"])
        add("")

    return "\n".join(out)


def main() -> int:
    ap = argparse.ArgumentParser(description="Човешки отчет върху forensic run каталог")
    ap.add_argument("run_dir", help="път до forensic_out/run_<ID>")
    ap.add_argument("--json", action="store_true", help="запиши и forensic_report.json")
    args = ap.parse_args()

    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")

    run_dir = Path(args.run_dir).resolve()
    if not run_dir.is_dir():
        raise SystemExit(f"Няма такъв каталог: {run_dir}")

    records, source = load_records(run_dir)
    stats = build_stats(records)
    custody = load_custody(run_dir)

    report = render(run_dir, records, source, stats, custody)
    out_md = run_dir / "forensic_report.md"
    out_md.write_text(report, encoding="utf-8")
    print(report)
    print(f"\nЗаписан: {out_md}")

    if args.json:
        payload = {
            "run_dir": str(run_dir),
            "source": source,
            "records": stats["records"],
            "first": stats["first"].isoformat() if stats["first"] else None,
            "last": stats["last"].isoformat() if stats["last"] else None,
            "with_attachment": stats["with_attachment"],
            "attachments_total": stats["attachments_total"],
            "attachments_hashed": stats["attachments_hashed"],
            "attachments_bytes": stats["attachments_bytes"],
            "matched_domains": dict(stats["matched"]),
            "top_senders": dict(stats["senders"].most_common(50)),
            "sender_domains": dict(stats["sender_domains"].most_common(50)),
            "per_month": dict(sorted(stats["per_month"].items())),
            "by_extension": dict(stats["by_ext"].most_common()),
        }
        out_json = run_dir / "forensic_report.json"
        out_json.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"Записан: {out_json}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
