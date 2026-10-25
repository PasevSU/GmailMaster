#!/usr/bin/env python3
"""Генерира PDF отчети от завършен форензик run (gmail-forensic-extract).

Употреба:
    python forensic_pdf_report.py                        # авто-избор на най-пълния run
    python forensic_pdf_report.py --run forensic_out/run_XXX
    python forensic_pdf_report.py --out forensic_pdf_reports

Създава нова папка с отделни PDF отчети, обединен PDF, SHA256SUMS.txt и README.md.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections import Counter, OrderedDict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_JUSTIFY
from reportlab.lib.pagesizes import A4, landscape
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import (
    BaseDocTemplate,
    Frame,
    Image,
    PageBreak,
    PageTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
)

TOOL_VERSION = "1.0.0"
DEFAULT_OUT = "forensic_pdf_reports"
RUNS_DIR = "forensic_out"

# ---------------------------------------------------------------- шрифтове

FONT_CANDIDATES = [
    (r"C:\Windows\Fonts\segoeui.ttf", r"C:\Windows\Fonts\segoeuib.ttf"),
    (r"C:\Windows\Fonts\arial.ttf", r"C:\Windows\Fonts\arialbd.ttf"),
    (r"C:\Windows\Fonts\calibri.ttf", r"C:\Windows\Fonts\calibrib.ttf"),
]

FONT = "Helvetica"
FONT_B = "Helvetica-Bold"


def register_fonts() -> None:
    global FONT, FONT_B
    for regular, bold in FONT_CANDIDATES:
        if Path(regular).exists() and Path(bold).exists():
            pdfmetrics.registerFont(TTFont("Doc", regular))
            pdfmetrics.registerFont(TTFont("Doc-Bold", bold))
            pdfmetrics.registerFontFamily("Doc", normal="Doc", bold="Doc-Bold")
            FONT, FONT_B = "Doc", "Doc-Bold"
            return


# ---------------------------------------------------------------- помощни

def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def read_jsonl(path: Path) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                out.append(json.loads(line))
    return out


def header(rec: Dict[str, Any], name: str) -> str:
    hdrs = rec.get("headers") or {}
    for k, v in hdrs.items():
        if k.lower() == name.lower():
            return str(v)
    return ""


def sender_email(rec: Dict[str, Any]) -> str:
    raw = header(rec, "From")
    if "<" in raw and ">" in raw:
        return raw.rsplit("<", 1)[1].split(">")[0].strip()
    return raw.strip()


def sender_name(rec: Dict[str, Any]) -> str:
    raw = header(rec, "From")
    if "<" in raw:
        name = raw.split("<")[0].strip().strip('"').strip()
        return name or sender_email(rec)
    return raw


def domain_of(address: str) -> str:
    return address.rsplit("@", 1)[1].lower() if "@" in address else ""


def fmt_bytes(n: Optional[int]) -> str:
    n = int(n or 0)
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024.0
    return f"{n:.1f} GB"


def day(rec: Dict[str, Any]) -> str:
    return (rec.get("internal_date_utc") or "")[:10]


def month(rec: Dict[str, Any]) -> str:
    return (rec.get("internal_date_utc") or "")[:7]


# ---------------------------------------------------------------- стилове

STYLES: Dict[str, ParagraphStyle] = {}


def build_styles() -> None:
    STYLES.update(
        {
            "title": ParagraphStyle(
                "title", fontName=FONT_B, fontSize=22, leading=27, spaceAfter=6,
                textColor=colors.HexColor("#12263f"),
            ),
            "subtitle": ParagraphStyle(
                "subtitle", fontName=FONT, fontSize=11, leading=15,
                textColor=colors.HexColor("#52667a"), spaceAfter=14,
            ),
            "h2": ParagraphStyle(
                "h2", fontName=FONT_B, fontSize=13, leading=17, spaceBefore=12,
                spaceAfter=6, textColor=colors.HexColor("#1b3a5c"),
            ),
            "h3": ParagraphStyle(
                "h3", fontName=FONT_B, fontSize=10.5, leading=14, spaceBefore=8,
                spaceAfter=4, textColor=colors.HexColor("#2d4f6f"),
            ),
            "body": ParagraphStyle(
                "body", fontName=FONT, fontSize=9.5, leading=13.5, spaceAfter=5,
                alignment=TA_JUSTIFY,
            ),
            "bullet": ParagraphStyle(
                "bullet", fontName=FONT, fontSize=9.5, leading=13.5,
                leftIndent=12, bulletIndent=2, spaceAfter=3,
            ),
            "note": ParagraphStyle(
                "note", fontName=FONT, fontSize=8, leading=11,
                textColor=colors.HexColor("#5d6b7a"), spaceBefore=6,
            ),
            "cell": ParagraphStyle("cell", fontName=FONT, fontSize=7, leading=8.6),
            "cellb": ParagraphStyle(
                "cellb", fontName=FONT_B, fontSize=7, leading=8.6,
                textColor=colors.white,
            ),
            "cell_r": ParagraphStyle(
                "cell_r", fontName=FONT, fontSize=7, leading=8.6, alignment=2
            ),
            "tiny": ParagraphStyle("tiny", fontName=FONT, fontSize=5.6, leading=6.8),
            "mono": ParagraphStyle(
                "mono", fontName="Courier", fontSize=5.6, leading=6.8
            ),
        }
    )


HDR_BG = colors.HexColor("#1b3a5c")
ROW_ALT = colors.HexColor("#eef2f7")
GRID = colors.HexColor("#b8c4d2")


def cell(text: str, style: str = "cell") -> Paragraph:
    return Paragraph(escape(str(text)) if text is not None else "", STYLES[style])


def data_table(
    header_cells: Sequence[str],
    rows: Iterable[Sequence[Any]],
    widths: Sequence[float],
    align_right: Sequence[int] = (),
    font_key: str = "cell",
) -> Table:
    data: List[List[Any]] = [[cell(h, "cellb") for h in header_cells]]
    for row in rows:
        line = []
        for i, v in enumerate(row):
            st = "cell_r" if i in align_right else font_key
            line.append(cell(v, st))
        data.append(line)
    t = Table(data, colWidths=list(widths), repeatRows=1, hAlign="LEFT")
    style = [
        ("BACKGROUND", (0, 0), (-1, 0), HDR_BG),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("GRID", (0, 0), (-1, -1), 0.4, GRID),
        ("LEFTPADDING", (0, 0), (-1, -1), 3),
        ("RIGHTPADDING", (0, 0), (-1, -1), 3),
        ("TOPPADDING", (0, 0), (-1, -1), 2),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
    ]
    for i in range(2, len(data), 2):
        style.append(("BACKGROUND", (0, i), (-1, i), ROW_ALT))
    t.setStyle(TableStyle(style))
    return t


def kv_table(pairs: Sequence[Tuple[str, Any]], widths: Sequence[float]) -> Table:
    data = [[cell(k, "cellb"), cell(v, "cell")] for k, v in pairs]
    t = Table(data, colWidths=list(widths), hAlign="LEFT")
    t.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#e3e9f1")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("GRID", (0, 0), (-1, -1), 0.4, GRID),
                ("LEFTPADDING", (0, 0), (-1, -1), 4),
                ("RIGHTPADDING", (0, 0), (-1, -1), 4),
                ("TOPPADDING", (0, 0), (-1, -1), 2.5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 2.5),
            ]
        )
    )
    return t


# ---------------------------------------------------------------- документ

def make_doc(path: Path, title: str, subtitle: str, run_id: str) -> BaseDocTemplate:
    doc = BaseDocTemplate(
        str(path), pagesize=A4,
        leftMargin=18 * mm, rightMargin=18 * mm,
        topMargin=20 * mm, bottomMargin=16 * mm,
        title=title, author="gmail-forensic-extract", subject=subtitle,
        creator=f"forensic_pdf_report/{TOOL_VERSION}",
    )
    frame = Frame(
        doc.leftMargin, doc.bottomMargin, doc.width, doc.height, id="body"
    )

    def decorate(canvas, d):
        canvas.saveState()
        canvas.setFont(FONT, 7.5)
        canvas.setFillColor(colors.HexColor("#7b8794"))
        canvas.drawString(doc.leftMargin, A4[1] - 13 * mm, title)
        canvas.drawRightString(A4[0] - doc.rightMargin, A4[1] - 13 * mm, run_id)
        canvas.setStrokeColor(colors.HexColor("#c9d3dd"))
        canvas.setLineWidth(0.5)
        canvas.line(
            doc.leftMargin, A4[1] - 14.5 * mm, A4[0] - doc.rightMargin, A4[1] - 14.5 * mm
        )
        canvas.line(doc.leftMargin, 12 * mm, A4[0] - doc.rightMargin, 12 * mm)
        canvas.setFont(FONT, 7.5)
        canvas.drawString(doc.leftMargin, 8.5 * mm, "Доказателствен комплект — поверително")
        canvas.drawRightString(
            A4[0] - doc.rightMargin, 8.5 * mm, f"стр. {d.page}"
        )
        canvas.restoreState()

    doc.addPageTemplates([PageTemplate(id="main", frames=[frame], onPage=decorate)])
    return doc


# ---------------------------------------------------------------- данни

def run_info(run_dir: Path) -> Dict[str, Any]:
    manifest_path = run_dir / "chain_of_custody.json"
    manifest = (
        json.loads(manifest_path.read_text(encoding="utf-8"))
        if manifest_path.exists()
        else None
    )
    jsonl = run_dir / "evidence_records.jsonl"
    records = read_jsonl(jsonl) if jsonl.exists() else []
    with_att = run_dir / "evidence_records_with_attachments.jsonl"
    records_full = read_jsonl(with_att) if with_att.exists() else records
    return {
        "dir": run_dir,
        "id": run_dir.name,
        "manifest": manifest,
        "records": records,
        "records_full": records_full,
        "has_manifest": manifest is not None,
        "count": len(records),
    }


def detect_primary(base: Path) -> Path:
    runs_root = base / RUNS_DIR
    best: Optional[Tuple[int, Path]] = None
    for d in sorted(runs_root.iterdir()) if runs_root.exists() else []:
        if not d.is_dir() or not (d / "chain_of_custody.json").exists():
            continue
        jsonl = d / "evidence_records.jsonl"
        if not jsonl.exists():
            continue
        n = sum(1 for line in jsonl.open("r", encoding="utf-8") if line.strip())
        if best is None or n > best[0]:
            best = (n, d)
    if best is None:
        raise SystemExit(f"Не е намерен завършен run в {runs_root}")
    return best[1]


def all_runs(base: Path) -> List[Dict[str, Any]]:
    runs_root = base / RUNS_DIR
    out = []
    if runs_root.exists():
        for d in sorted(runs_root.iterdir()):
            if d.is_dir():
                out.append(run_info(d))
    return out


def run_status(info: Dict[str, Any]) -> str:
    m = info.get("manifest")
    if not m:
        return "прекъснат (без манифест)"
    scanned = m["results"]["messages_scanned"]
    limit = m["criteria"]["max_messages_limit"]
    if limit and scanned >= limit:
        return f"отрязан от лимит ({scanned}/{limit})"
    return "пълен"


def stats(records: List[Dict[str, Any]]) -> Dict[str, Any]:
    st: Dict[str, Any] = {}
    st["count"] = len(records)
    st["senders"] = Counter(sender_email(r) for r in records)
    st["sender_domains"] = Counter(domain_of(sender_email(r)) for r in records)
    dom = Counter()
    for r in records:
        for d in r.get("matched_domains") or ["(няма)"]:
            dom[d] += 1
    st["domains"] = dom
    months = Counter(month(r) for r in records)
    st["months"] = OrderedDict(sorted(months.items()))
    atts = [a for r in records for a in (r.get("attachments") or [])]
    st["atts"] = atts
    st["att_count"] = len(atts)
    st["att_bytes"] = sum(int(a.get("size_bytes") or 0) for a in atts)
    st["att_hashed"] = sum(1 for a in atts if a.get("hashed"))
    exts = Counter()
    for a in atts:
        name = a.get("filename") or ""
        ext = name.rsplit(".", 1)[-1].lower() if "." in name else "(без разширение)"
        if len(ext) > 6:
            ext = "(без разширение)"
        exts[ext] += 1
    st["exts"] = exts
    dates = sorted(d for d in (r.get("internal_date_utc") or "" for r in records) if d)
    st["first"] = dates[0] if dates else ""
    st["last"] = dates[-1] if dates else ""
    st["with_att"] = sum(1 for r in records if r.get("attachments"))
    return st


# ---------------------------------------------------------------- отчети

def report_overview(path: Path, info: Dict[str, Any], run_list: List[Dict[str, Any]],
                    st: Dict[str, Any]) -> None:
    m = info["manifest"]
    doc = make_doc(path, "Форензик отчет — Обобщение", "Обобщен отчет", info["id"])
    s: List[Any] = []
    s.append(Paragraph("Форензик извличане на електронна поща", STYLES["title"]))
    s.append(
        Paragraph(
            f"Gmail API — доказателствен комплект по филтър <b>filters.yaml</b><br/>"
            f"run <b>{info['id']}</b> · генериран {iso(utcnow())}",
            STYLES["subtitle"],
        )
    )

    s.append(Paragraph("1. Ключови показатели", STYLES["h2"]))
    s.append(
        kv_table(
            [
                ("Оператор", m.get("operator")),
                ("Хост / платформа", f"{m.get('host')} · {m.get('platform')}"),
                ("Инструмент", f"{m['tool']['name']} v{m['tool']['version']}"),
                ("Старт (UTC)", m.get("started_utc")),
                ("Край (UTC)", m.get("finished_utc")),
                ("Продължителност", f"{m.get('duration_seconds')} s"),
                ("Прегледани съобщения", m["results"]["messages_scanned"]),
                ("Приети записи", m["results"]["records_accepted"]),
                ("Изключени (извън домейните)", m["results"]["records_excluded_by_domain"]),
                ("Грешки", m["results"]["errors"]),
                ("Съобщения с прикачени файлове", st["with_att"]),
                ("Прикачени файлове", f"{st['att_count']} ({fmt_bytes(st['att_bytes'])})"),
                ("Хеширани прикачени файлове", st["att_hashed"]),
                ("Период (UTC)", f"{st['first'][:10]} → {st['last'][:10]}"),
                ("records_digest", m.get("records_digest")),
            ],
            widths=[150, 343],
        )
    )

    s.append(Paragraph("2. Критерии на извличането", STYLES["h2"]))
    s.append(
        kv_table(
            [
                ("Филтър", m["criteria"].get("filters_file")),
                ("SHA-256 на филтъра", m["criteria"].get("filters_sha256")),
                ("Домейни", ", ".join(m["criteria"].get("domain_filter") or [])),
                ("Лимит съобщения", m["criteria"].get("max_messages_limit")),
                ("Gmail заявка", m["criteria"].get("gmail_query")),
            ],
            widths=[150, 343],
        )
    )

    s.append(Paragraph("3. Методология", STYLES["h2"]))
    for text in [
        "Достъпът е <b>само за четене</b> чрез Gmail API v1 със scope "
        "<font face='Courier'>gmail.readonly</font>; съдържанието на пощенската "
        "кутия не е променяно.",
        "За всяко съобщение се записват пълните хедъри, идентификаторите "
        "(<font face='Courier'>message_id</font>, <font face='Courier'>thread_id</font>), "
        "вътрешната дата, етикетите, структурата на частите и метаданните на "
        "прикачените файлове.",
        "Всеки запис получава <b>record_sha256</b> — SHA-256 върху каноничен JSON, "
        "което прави всяка промяна в записа откриваема.",
        "На прикачените файлове се изчислява SHA-256 от реалното им съдържание "
        "(фаза 2), без да се запазва самото съдържание.",
        "Цялостта на извадката се удостоверява с <b>records_digest</b> и с хешове "
        "на всички изходни файлове в манифеста на веригата на съхранение.",
        "Проверка по всяко време: "
        "<font face='Courier'>python forensic_extract.py --verify &lt;run_dir&gt;</font>",
    ]:
        s.append(Paragraph(text, STYLES["bullet"], bulletText="•"))

    s.append(Paragraph("4. Верига на съхранение — декларация", STYLES["h2"]))
    s.append(Paragraph(m.get("custody_statement") or "", STYLES["body"]))

    s.append(Paragraph("5. Всички налични извличания", STYLES["h2"]))
    rows = []
    for info_x in run_list:
        man = info_x.get("manifest")
        rows.append(
            [
                info_x["id"],
                (len(info_x["records"]) if man else "—"),
                (man["results"]["errors"] if man else "—"),
                (man["results"]["attachments_hashed"] if man else "—"),
                (man.get("finished_utc") if man else "—"),
                run_status(info_x),
            ]
        )
    s.append(
        data_table(
            ["run", "записи", "грешки", "хеш. файлове", "завършен (UTC)", "състояние"],
            rows, widths=[112, 42, 42, 55, 120, 122],
            align_right=(1, 2, 3),
        )
    )
    s.append(
        Paragraph(
            "Забележка: run с достигнат лимит съдържа само най-новите N съобщения "
            "и не представлява пълна извадка.",
            STYLES["note"],
        )
    )

    repro = reproducibility_rows(info["records"], run_list, info["id"])
    if repro:
        s.append(Paragraph("6. Възпроизводимост (съпоставка по message_id)", STYLES["h2"]))
        s.append(
            data_table(
                ["сравняван run", "общи", "само в основния", "само в другия",
                 "еднакво съдържание"],
                repro, widths=[132, 46, 68, 68, 179], align_right=(1, 2, 3),
            )
        )
        s.append(
            Paragraph(
                "Съдържанието се сравнява по message_id, вътрешна дата, подател, "
                "тема и съвпадащ домейн (без служебните полета run_id и "
                "extracted_at_utc, които се различават при всяко изпълнение).",
                STYLES["note"],
            )
        )
    doc.build(s)


def reproducibility_rows(primary: List[Dict[str, Any]],
                         run_list: List[Dict[str, Any]],
                         primary_id: str) -> List[List[Any]]:
    def payload(r: Dict[str, Any]) -> Tuple[Any, ...]:
        return (
            r.get("message_id"),
            r.get("internal_date_utc"),
            header(r, "From"),
            header(r, "Subject"),
            tuple(r.get("matched_domains") or []),
        )

    base_ids = {r.get("message_id") for r in primary}
    base_payload = {payload(r) for r in primary}
    rows: List[List[Any]] = []
    for info_x in run_list:
        if info_x["id"] == primary_id or not info_x.get("manifest"):
            continue
        other = info_x["records"]
        ids = {r.get("message_id") for r in other}
        same = base_payload == {payload(r) for r in other}
        rows.append(
            [info_x["id"], len(base_ids & ids), len(base_ids - ids),
             len(ids - base_ids), "да" if same else "не"]
        )
    return rows


def report_sources(path: Path, info: Dict[str, Any], st: Dict[str, Any]) -> None:
    doc = make_doc(path, "Форензик отчет — Домейни и податели", "Статистика", info["id"])
    s: List[Any] = []
    s.append(Paragraph("Съответствия по домейн от филтъра", STYLES["h2"]))
    s.append(
        data_table(
            ["домейн", "съобщения", "дял"],
            [
                [d, n, f"{100.0 * n / max(st['count'], 1):.1f} %"]
                for d, n in st["domains"].most_common()
            ],
            widths=[220, 80, 80], align_right=(1, 2),
        )
    )

    s.append(Paragraph("Податели (всички)", STYLES["h2"]))
    s.append(
        data_table(
            ["подател", "съобщения"],
            [[k, v] for k, v in st["senders"].most_common()],
            widths=[400, 80], align_right=(1,),
        )
    )

    s.append(Paragraph("Домейни на подателя", STYLES["h2"]))
    s.append(
        data_table(
            ["домейн на подател", "съобщения"],
            [[k or "(неизвестен)", v] for k, v in st["sender_domains"].most_common()],
            widths=[400, 80], align_right=(1,),
        )
    )

    s.append(Paragraph("Видове прикачени файлове", STYLES["h2"]))
    s.append(
        data_table(
            ["разширение", "брой", "обем"],
            [
                [f".{e}" if e != "(без разширение)" else e, n, ""]
                for e, n in st["exts"].most_common()
            ],
            widths=[220, 80, 80], align_right=(1, 2),
        )
    )
    doc.build(s)


def report_timeline(path: Path, info: Dict[str, Any], st: Dict[str, Any],
                    charts_dir: Path) -> None:
    doc = make_doc(path, "Форензик отчет — Хронология", "Хронология", info["id"])
    s: List[Any] = []
    s.append(Paragraph("Разпределение по месеци", STYLES["h2"]))
    try:
        chart = make_chart(st["months"], charts_dir / "timeline.png")
        if chart:
            s.append(Image(str(chart), width=470, height=235))
            s.append(Spacer(1, 8))
    except Exception as exc:  # noqa: BLE001
        s.append(Paragraph(f"(графиката не е генерирана: {exc})", STYLES["note"]))

    per_domain_month: Dict[str, Counter] = {}
    totals = st["months"]
    rows = [[mo, n, f"{100.0 * n / max(st['count'], 1):.1f} %"]
            for mo, n in totals.items()]
    s.append(
        data_table(
            ["месец", "съобщения", "дял"], rows,
            widths=[120, 90, 90], align_right=(1, 2),
        )
    )
    del per_domain_month
    doc.build(s)


def make_chart(months: "OrderedDict[str, int]", path: Path) -> Optional[Path]:
    try:
        import matplotlib

        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except Exception:  # noqa: BLE001
        return None
    labels = list(months.keys())
    values = list(months.values())
    matplotlib.rcParams["font.family"] = "DejaVu Sans"
    fig, ax = plt.subplots(figsize=(11, 3.6), dpi=140)
    ax.bar(range(len(values)), values, color="#1b3a5c", width=0.75)
    ax.set_title("Съобщения по месеци (UTC)", fontsize=11)
    ax.set_ylabel("брой")
    step = max(1, len(labels) // 22)
    ax.set_xticks(range(0, len(labels), step))
    ax.set_xticklabels([labels[i] for i in range(0, len(labels), step)],
                       rotation=60, ha="right", fontsize=7)
    ax.grid(axis="y", color="#d5dde6", linewidth=0.6)
    ax.set_axisbelow(True)
    for spine in ("top", "right"):
        ax.spines[spine].set_visible(False)
    fig.tight_layout()
    path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(path)
    plt.close(fig)
    return path


def report_messages(path: Path, info: Dict[str, Any],
                    records: List[Dict[str, Any]]) -> None:
    doc = make_doc(path, "Форензик отчет — Регистър на съобщенията",
                   "Регистър", info["id"])
    s: List[Any] = []
    s.append(Paragraph("Регистър на извлечените съобщения", STYLES["h2"]))
    s.append(
        Paragraph(
            f"Общо {len(records)} записа, подредени по вътрешна дата (UTC). "
            "Колоната „хеш“ съдържа първите 16 знака от record_sha256.",
            STYLES["body"],
        )
    )
    rows = []
    for i, r in enumerate(records, start=1):
        rows.append(
            [
                i,
                (r.get("internal_date_utc") or "")[:19].replace("T", " "),
                sender_email(r),
                header(r, "Subject")[:110],
                ", ".join(r.get("matched_domains") or [])[:40],
                len(r.get("attachments") or []),
                (r.get("record_sha256") or "")[:16],
            ]
        )
    s.append(
        data_table(
            ["№", "дата (UTC)", "подател", "тема", "домейн", "прик.", "хеш"],
            rows, widths=[22, 72, 108, 158, 68, 26, 39],
            align_right=(0, 5),
        )
    )
    doc.build(s)


def report_attachments(path: Path, info: Dict[str, Any],
                       records: List[Dict[str, Any]]) -> None:
    doc = make_doc(path, "Форензик отчет — Прикачени файлове",
                   "Инвентар на прикачените файлове", info["id"])
    s: List[Any] = []
    atts: List[Tuple[Dict[str, Any], Dict[str, Any]]] = []
    for r in records:
        for a in r.get("attachments") or []:
            atts.append((r, a))
    s.append(Paragraph("Инвентар на прикачените файлове", STYLES["h2"]))
    total = sum(int(a.get("size_bytes") or 0) for _r, a in atts)
    s.append(
        Paragraph(
            f"Общо {len(atts)} файла, {fmt_bytes(total)}. Хешовете са изчислени "
            "върху съдържанието на файла (SHA-256); самото съдържание не се "
            "съхранява в извадката.",
            STYLES["body"],
        )
    )
    rows = [
        [
            i,
            (r.get("internal_date_utc") or "")[:10],
            (a.get("filename") or "")[:70],
            fmt_bytes(a.get("size_bytes")),
            cell(a.get("sha256") or "(не е хеширан)", "mono"),
        ]
        for i, (r, a) in enumerate(atts, start=1)
    ]
    data = [[cell(h, "cellb") for h in
             ["№", "дата", "файл", "размер", "SHA-256"]]]
    for i, (r, a) in enumerate(atts, start=1):
        data.append(
            [
                cell(i, "cell_r"),
                cell((r.get("internal_date_utc") or "")[:10]),
                cell((a.get("filename") or "")[:70]),
                cell(fmt_bytes(a.get("size_bytes")), "cell_r"),
                cell(a.get("sha256") or "(не е хеширан)", "mono"),
            ]
        )
    t = Table(data, colWidths=[22, 46, 150, 44, 231], repeatRows=1, hAlign="LEFT")
    style = [
        ("BACKGROUND", (0, 0), (-1, 0), HDR_BG),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("GRID", (0, 0), (-1, -1), 0.4, GRID),
        ("LEFTPADDING", (0, 0), (-1, -1), 2.5),
        ("RIGHTPADDING", (0, 0), (-1, -1), 2.5),
        ("TOPPADDING", (0, 0), (-1, -1), 1.6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 1.6),
    ]
    for i in range(2, len(data), 2):
        style.append(("BACKGROUND", (0, i), (-1, i), ROW_ALT))
    t.setStyle(TableStyle(style))
    s.append(t)
    del rows
    doc.build(s)


def verify_integrity(info: Dict[str, Any]) -> List[List[Any]]:
    """Локална проверка: хешове на изходните файлове + records_digest."""
    run_dir: Path = info["dir"]
    rows: List[List[Any]] = []
    manifests: List[Tuple[str, Dict[str, Any]]] = []
    if info.get("manifest"):
        manifests.append(("фаза 1 — метаданни", info["manifest"]))
    p2 = run_dir / "chain_of_custody_phase2.json"
    if p2.exists():
        manifests.append(
            ("фаза 2 — прикачени файлове",
             json.loads(p2.read_text(encoding="utf-8")))
        )
    for label, man in manifests:
        for item in man.get("outputs") or []:
            f = run_dir / (item.get("file") or "")
            if not f.exists():
                rows.append([label, item.get("file"), "ЛИПСВА", "—"])
                continue
            actual = sha256_file(f)
            rows.append(
                [label, item.get("file"),
                 "OK" if actual == item.get("sha256") else "НЕСЪОТВЕТСТВИЕ",
                 item.get("sha256") or "—"]
            )
        # records_digest
        man_dir = run_dir
        rfile = man_dir / "evidence_records.jsonl"
        if man.get("outputs") and label.startswith("фаза 2"):
            rfile = man_dir / "evidence_records_with_attachments.jsonl"
        if rfile.exists() and man.get("records_digest"):
            h = hashlib.sha256()
            for rec in read_jsonl(rfile):
                h.update((rec.get("record_sha256") or "").encode("utf-8"))
            rows.append(
                [label, f"records_digest ({rfile.name})",
                 "OK" if h.hexdigest() == man["records_digest"] else "НЕСЪОТВЕТСТВИЕ",
                 man["records_digest"]]
            )
    return rows


def report_custody(path: Path, info: Dict[str, Any]) -> None:
    m = info["manifest"]
    run_dir: Path = info["dir"]
    doc = make_doc(path, "Форензик отчет — Верига на съхранение",
                   "Chain of custody", info["id"])
    s: List[Any] = []
    s.append(Paragraph("Манифест на извличането", STYLES["h2"]))
    s.append(
        kv_table(
            [
                ("Схема", m.get("schema")),
                ("run_id", m.get("run_id")),
                ("Инструмент", f"{m['tool']['name']} v{m['tool']['version']}"),
                ("SHA-256 на скрипта", m["tool"].get("script_sha256")),
                ("Python", m.get("python")),
                ("Хост", m.get("host")),
                ("Платформа", m.get("platform")),
                ("Начало (UTC)", m.get("started_utc")),
                ("Край (UTC)", m.get("finished_utc")),
                ("Продължителност", f"{m.get('duration_seconds')} s"),
                ("records_digest", m.get("records_digest")),
            ],
            widths=[150, 343],
        )
    )

    tok = (m.get("source") or {}).get("token") or {}
    if tok:
        s.append(Paragraph("Токен за достъп", STYLES["h2"]))
        s.append(
            kv_table(
                [("Файл", tok.get("token_file")),
                 ("SHA-256 преди", tok.get("token_sha256_before")),
                 ("SHA-256 след", tok.get("token_sha256_after")),
                 ("Опреснен в паметта", tok.get("access_token_refreshed_in_memory")),
                 ("Записан на диск", tok.get("token_persisted_to_disk"))],
                widths=[150, 343],
            )
        )

    s.append(Paragraph("Файлове в run папката (SHA-256)", STYLES["h2"]))
    files = sorted(p for p in run_dir.iterdir() if p.is_file())
    rows = []
    for p in files:
        rows.append(
            [p.name, fmt_bytes(p.stat().st_size), p.stat().st_mtime and
             datetime.fromtimestamp(p.stat().st_mtime, timezone.utc).strftime(
                 "%Y-%m-%d %H:%M:%S"), sha256_file(p)]
        )
    data = [[cell(h, "cellb") for h in
             ["файл", "размер", "променен (UTC)", "SHA-256"]]]
    for r in rows:
        data.append([cell(r[0]), cell(r[1], "cell_r"), cell(r[2]),
                     cell(r[3], "mono")])
    t = Table(data, colWidths=[128, 44, 78, 243], repeatRows=1, hAlign="LEFT")
    t.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), HDR_BG),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("GRID", (0, 0), (-1, -1), 0.4, GRID),
                ("LEFTPADDING", (0, 0), (-1, -1), 2.5),
                ("RIGHTPADDING", (0, 0), (-1, -1), 2.5),
                ("TOPPADDING", (0, 0), (-1, -1), 1.6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 1.6),
            ]
        )
    )
    s.append(t)

    if m.get("reseal_history"):
        s.append(Paragraph("Пре-запечатвания на манифеста", STYLES["h2"]))
        for item in m["reseal_history"]:
            s.append(
                Paragraph(
                    f"{item.get('resealed_utc')} — {item.get('reason')} "
                    f"({len(item.get('changed') or [])} обновени хеша)",
                    STYLES["bullet"], bulletText="•",
                )
            )

    phase2 = run_dir / "chain_of_custody_phase2.json"
    if phase2.exists():
        p2 = json.loads(phase2.read_text(encoding="utf-8"))
        s.append(Paragraph("Фаза 2 — хеширане на прикачените файлове", STYLES["h2"]))
        s.append(
            kv_table(
                [("Предназначение", p2.get("purpose")),
                 ("Старт (UTC)", p2.get("started_utc")),
                 ("Край (UTC)", p2.get("finished_utc")),
                 ("Опит за хеширане", p2["results"]["attachments_attempted"]),
                 ("Успешно хеширани", p2["results"]["attachments_hashed"]),
                 ("Неуспешни", p2["results"]["attachments_failed"]),
                 ("SHA-256 на фаза 1 записи",
                  p2["phase1"]["records_sha256"]),
                 ("records_digest (фаза 2)", p2.get("records_digest"))],
                widths=[150, 343],
            )
        )
        s.append(
            data_table(
                ["извод (фаза 2)", "размер", "SHA-256"],
                [[o.get("file"), fmt_bytes(o.get("size_bytes")), o.get("sha256")]
                 for o in p2.get("outputs") or []],
                widths=[160, 50, 283], align_right=(1,),
            )
        )

    s.append(Paragraph("Проверка на цялостта (извършена при генерирането)", STYLES["h2"]))
    rows = verify_integrity(info)
    if rows:
        s.append(
            data_table(
                ["етап", "обект", "резултат", "очакван SHA-256"],
                rows, widths=[96, 132, 66, 199],
            )
        )
        bad = sum(1 for r in rows if r[2] != "OK")
        s.append(
            Paragraph(
                "Всички проверки са успешни." if bad == 0 else
                f"<b>Внимание:</b> {bad} проверки не съвпадат.",
                STYLES["note"],
            )
        )

    s.append(Paragraph("Събития в одитния лог", STYLES["h2"]))
    log_path = run_dir / "forensic.log"
    if log_path.exists():
        ev = Counter()
        with log_path.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    ev[json.loads(line).get("event", "?")] += 1
                except Exception:  # noqa: BLE001
                    ev["(невалиден ред)"] += 1
        s.append(
            data_table(["събитие", "брой"],
                       [[k, v] for k, v in ev.most_common()],
                       widths=[220, 80], align_right=(1,))
        )
    doc.build(s)


# ---------------------------------------------------------------- main

def build_readme(out: Path, info: Dict[str, Any], pdfs: List[Path],
                 run_list: List[Dict[str, Any]]) -> None:
    lines = [
        "# PDF отчети — форензик извличане",
        "",
        f"- Генерирано: `{iso(utcnow())}`",
        f"- Основен run: `{info['id']}`",
        f"- Записи: {info['count']}",
        f"- Инструмент: `forensic_pdf_report` v{TOOL_VERSION}",
        "",
        "## Съдържание",
        "",
    ]
    for p in pdfs:
        lines.append(f"- `{p.name}`")
    lines += [
        "",
        "## Проверка на цялостта",
        "",
        "```powershell",
        "Get-FileHash .\\*.pdf -Algorithm SHA256",
        "python ..\\forensic_extract.py --verify ..\\forensic_out\\<run_id>",
        "```",
        "",
        "## Източници",
        "",
    ]
    for i in run_list:
        lines.append(f"- `{i['id']}` — {run_status(i)}")
    lines.append("")
    (out / "README.md").write_text("\n".join(lines), encoding="utf-8")


def build_sha256sums(out: Path, pdfs: List[Path]) -> None:
    lines = [f"{sha256_file(p)}  {p.name}" for p in sorted(pdfs)]
    (out / "SHA256SUMS.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")


def main(argv: Optional[Sequence[str]] = None) -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    ap = argparse.ArgumentParser(description="PDF отчети от форензик run")
    ap.add_argument("--base-dir", default=str(Path(__file__).resolve().parent))
    ap.add_argument("--run", default=None, help="конкретен run (по подразбиране най-пълният)")
    ap.add_argument("--out", default=DEFAULT_OUT, help=f"изходна папка ({DEFAULT_OUT})")
    args = ap.parse_args(list(argv) if argv is not None else None)

    base = Path(args.base_dir).resolve()
    run_dir = Path(args.run).resolve() if args.run else detect_primary(base)
    if not run_dir.is_dir():
        print(f"Липсва run папка: {run_dir}", file=sys.stderr)
        return 2

    register_fonts()
    build_styles()

    info = run_info(run_dir)
    if not info["has_manifest"]:
        print(f"Липсва манифест в {run_dir}", file=sys.stderr)
        return 2

    records = info["records_full"]
    st = stats(records)
    run_list = all_runs(base)

    out = Path(args.out)
    if not out.is_absolute():
        out = base / out
    out.mkdir(parents=True, exist_ok=True)
    charts = out / "_charts"

    print(f"Основен run : {info['id']}")
    print(f"Записи      : {len(records)}")
    print(f"Изход       : {out}")

    pdfs: List[Path] = []

    def emit(name: str, fn, *a) -> None:
        p = out / name
        fn(p, *a)
        pdfs.append(p)
        print(f"  [OK] {name}  ({p.stat().st_size / 1024:.0f} KB)")

    emit("01_Обобщение.pdf", report_overview, info, run_list, st)
    emit("02_Домейни_и_податели.pdf", report_sources, info, st)
    emit("03_Хронология.pdf", report_timeline, info, st, charts)
    emit("04_Регистър_на_съобщенията.pdf", report_messages, info, records)
    emit("05_Прикачени_файлове.pdf", report_attachments, info, records)
    emit("06_Верига_на_съхранение.pdf", report_custody, info)

    merged = out / "00_ПЪЛЕН_ОТЧЕТ.pdf"
    try:
        from pypdf import PdfReader, PdfWriter

        writer = PdfWriter()
        for p in pdfs:
            for page in PdfReader(str(p)).pages:
                writer.add_page(page)
        with merged.open("wb") as f:
            writer.write(f)
        pdfs.append(merged)
        print(f"  [OK] {merged.name}  ({merged.stat().st_size / 1024:.0f} KB)")
    except Exception as exc:  # noqa: BLE001
        print(f"  [!] обединяването не е направено: {exc}", file=sys.stderr)

    build_sha256sums(out, pdfs)
    build_readme(out, info, pdfs, run_list)
    print("\nГотово.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
