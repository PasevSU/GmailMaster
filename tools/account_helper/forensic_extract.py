#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
forensic_extract.py — Read-only форензик извличане на Gmail доказателства
по изградения филтър (filters.yaml).

Принципи:
  * Само ЧЕТЕНЕ от Gmail (scope: gmail.readonly). Никакви промени по пощата.
  * Токенът се опреснява САМО в паметта (освен ако не е подаден --persist-token).
  * Всеки запис получава SHA-256 (каноничен JSON), всеки изходен файл — също.
  * UTC времеви марки + оригинални хедъри без промяна.
  * Append-only лог на действията (forensic.log, JSONL).
  * Chain of custody манифест с хеш на филтъра, заявката, броя записи и изходите.

Употреба:
  python forensic_extract.py --dry-run
  python forensic_extract.py --max 500
  python forensic_extract.py --operator "Име Фамилия" --no-attachment-hash
  python forensic_extract.py --verify forensic_out/run_20261025T101500Z
"""

from __future__ import annotations

import argparse
import base64
import csv
import hashlib
import json
import os
import platform
import random
import re
import socket
import sys
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, List, Optional, Tuple

TOOL_NAME = "gmail-forensic-extract"
TOOL_VERSION = "1.0.0"
RECORD_SCHEMA = "gmail-forensic-record/v1"

TOKEN_FILE = "gmail_token.json"
FILTERS_FILE = "filters.yaml"
SCOPES = ["https://www.googleapis.com/auth/gmail.readonly"]

DEFAULT_OUT_DIR = "forensic_out"
DEFAULT_MAX = 500
MAX_ATTACHMENT_HASH_BYTES = 25 * 1024 * 1024  # 25 MB

# Хедъри, които имат форензик стойност (traffic path, автентикация, идентичност)
INTERESTING_HEADERS = [
    "Date",
    "From",
    "Sender",
    "Reply-To",
    "To",
    "Cc",
    "Bcc",
    "Subject",
    "Message-ID",
    "Message-Id",
    "Return-Path",
    "Delivered-To",
    "Received",
    "Received-SPF",
    "Authentication-Results",
    "ARC-Authentication-Results",
    "DKIM-Signature",
    "X-Originating-IP",
    "X-Google-Smtp-Source",
    "X-Received",
    "List-Id",
    "MIME-Version",
    "Content-Type",
    "X-Mailer",
    "User-Agent",
]

EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")


# --------------------------------------------------------------------------- #
# Помощни функции
# --------------------------------------------------------------------------- #
def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def canonical_json(obj: Any) -> bytes:
    """Детерминистична сериализация — база за хеширане на доказателство."""
    return json.dumps(
        obj, sort_keys=True, ensure_ascii=False, separators=(",", ":"), default=str
    ).encode("utf-8")


def redact_path(p: str) -> str:
    return p


# --------------------------------------------------------------------------- #
# Филтри
# --------------------------------------------------------------------------- #
def load_filters(path: Path) -> Tuple[Dict[str, Any], bytes]:
    if not path.exists():
        raise FileNotFoundError(f"Липсва филтър: {path}")
    raw = path.read_bytes()
    import yaml  # локален import, за да е ясна грешката при липса

    data = yaml.safe_load(raw.decode("utf-8")) or {}
    if not isinstance(data, dict):
        raise ValueError("filters.yaml не е YAML речник")
    return data, raw


def build_domain_query(domains: List[str]) -> str:
    """Gmail заявка по домейни в From/To/Cc/Bcc — пълно покритие, не само последни N."""
    if not domains:
        return ""
    per_domain = [
        f"(from:{d} OR to:{d} OR cc:{d} OR bcc:{d})" for d in domains
    ]
    return "(" + " OR ".join(per_domain) + ")"


def build_query(
    filters: Dict[str, Any], domains: Optional[List[str]] = None, use_domain_query: bool = True
) -> Tuple[str, List[str]]:
    """Същата семантика като gmail_auth.build_gmail_query, но с проследимост."""
    parts: List[str] = []

    if use_domain_query and domains:
        dq = build_domain_query(domains)
        if dq:
            parts.append(dq)

    if filters.get("unread_only"):
        parts.append("is:unread")
    if filters.get("has_attachment"):
        parts.append("has:attachment")
    if filters.get("subject_contains"):
        parts.append(f'subject:"{filters["subject_contains"]}"')
    if filters.get("from_contains"):
        parts.append(f'from:"{filters["from_contains"]}"')
    if filters.get("label"):
        parts.append(f'label:{filters["label"]}')

    date_range = filters.get("date_range") or {}
    if isinstance(date_range, dict):
        if date_range.get("from"):
            parts.append(f'after:{date_range["from"]}')
        if date_range.get("to"):
            parts.append(f'before:{date_range["to"]}')

    if filters.get("query_extra"):
        parts.append(str(filters["query_extra"]).strip())

    return " ".join(parts), parts


def normalize_domains(filters: Dict[str, Any]) -> List[str]:
    domains = filters.get("domains") or []
    out: List[str] = []
    for d in domains:
        if not d:
            continue
        out.append(str(d).strip().lower().lstrip("@"))
    return [d for d in out if d]


def match_domains(record_headers: Dict[str, Any], domains: List[str]) -> Tuple[List[str], List[str]]:
    """
    Строго съвпадение по домейн на реалните адреси в From/To/Cc/Bcc
    (+ substring проверка за прозрачност, защото оригиналният код ползваше substring).
    """
    if not domains:
        return [], []

    addresses: List[str] = []
    for key in ("From", "To", "Cc", "Bcc", "Sender", "Reply-To"):
        val = record_headers.get(key)
        if not val:
            continue
        if isinstance(val, list):
            addresses.extend(EMAIL_RE.findall(" ".join(map(str, val))))
        else:
            addresses.extend(EMAIL_RE.findall(str(val)))

    addr_domains = {a.rsplit("@", 1)[1].lower() for a in addresses if "@" in a}

    exact = sorted(
        d for d in domains
        if any(ad == d or ad.endswith("." + d) for ad in addr_domains)
    )

    haystack = " ".join(str(v) for v in record_headers.values()).lower()
    substring = sorted(d for d in domains if d in haystack)

    return exact, substring


# --------------------------------------------------------------------------- #
# Gmail достъп
# --------------------------------------------------------------------------- #
def get_service(token_path: Path, persist_token: bool) -> Tuple[Any, Dict[str, Any]]:
    from google.auth.transport.requests import Request
    from google.oauth2.credentials import Credentials
    from googleapiclient.discovery import build

    if not token_path.exists():
        raise FileNotFoundError(
            f"Липсва {token_path.name}. Първо стартирайте gmail_auth.py."
        )

    token_hash_before = sha256_file(token_path)
    creds = Credentials.from_authorized_user_file(str(token_path), SCOPES)

    refreshed = False
    if creds.expired and creds.refresh_token:
        creds.refresh(Request())
        refreshed = True
        if persist_token:
            token_path.write_text(creds.to_json(), encoding="utf-8")

    token_meta = {
        "token_file": token_path.name,
        "token_sha256_before": token_hash_before,
        "token_sha256_after": sha256_file(token_path),
        "access_token_refreshed_in_memory": refreshed,
        "token_persisted_to_disk": bool(refreshed and persist_token),
        "scope": SCOPES[0],
    }
    return build("gmail", "v1", credentials=creds, cache_discovery=False), token_meta, creds


_local = threading.local()


def _build_service(creds: Any) -> Any:
    from googleapiclient.discovery import build

    return build("gmail", "v1", credentials=creds, cache_discovery=False)


def _thread_service(creds: Any) -> Any:
    """По един HTTP клиент на нишка — избягва споделено състояние."""
    svc = getattr(_local, "service", None)
    if svc is None:
        svc = _build_service(creds)
        _local.service = svc
    return svc


def iter_message_ids(service: Any, query: str, limit: int) -> Iterator[str]:
    page_token: Optional[str] = None
    fetched = 0
    while fetched < limit:
        page = service.users().messages().list(
            userId="me",
            q=query or None,
            maxResults=min(100, limit - fetched),
            pageToken=page_token,
        ).execute()
        msgs = page.get("messages", []) or []
        if not msgs:
            return
        for m in msgs:
            yield m["id"]
            fetched += 1
            if fetched >= limit:
                return
        page_token = page.get("nextPageToken")
        if not page_token:
            return


def _collect_headers(raw_headers: List[Dict[str, str]]) -> Dict[str, Any]:
    wanted = {h.lower(): h for h in INTERESTING_HEADERS}
    out: Dict[str, Any] = {}
    for h in raw_headers:
        name = (h.get("name") or "").strip()
        key = wanted.get(name.lower())
        if not key:
            continue
        value = h.get("value") or ""
        if key in out:
            if isinstance(out[key], list):
                out[key].append(value)
            else:
                out[key] = [out[key], value]
        else:
            out[key] = value
    return out


def _walk_parts(part: Dict[str, Any], path: str = "1") -> Iterator[Tuple[str, Dict[str, Any]]]:
    yield path, part
    for i, child in enumerate(part.get("parts") or [], start=1):
        yield from _walk_parts(child, f"{path}.{i}")


def _decode_b64url(data: str) -> bytes:
    pad = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + pad)


_RETRYABLE_MARKERS = (
    "rateLimitExceeded",
    "userRateLimitExceeded",
    "Quota exceeded",
    "backendError",
    "internalError",
    "The service is currently unavailable",
)


class RateLimiter:
    """Глобален ограничител: не повече от N заявки в секунда."""

    def __init__(self, rps: float):
        self.min_interval = 1.0 / rps if rps and rps > 0 else 0.0
        self._next = 0.0
        self._lock = threading.Lock()

    def acquire(self) -> None:
        if self.min_interval <= 0:
            return
        with self._lock:
            now = time.monotonic()
            if now < self._next:
                delay = self._next - now
                self._next += self.min_interval
            else:
                delay = 0.0
                self._next = now + self.min_interval
        if delay > 0:
            time.sleep(delay)


_LIMITER = RateLimiter(0.0)


def configure_limiter(rps: float) -> None:
    global _LIMITER
    _LIMITER = RateLimiter(rps)


def _is_retryable(exc: Exception) -> bool:
    text = str(exc)
    status = getattr(getattr(exc, "resp", None), "status", None)
    if status in (429, 500, 502, 503, 504):
        return True
    return any(m in text for m in _RETRYABLE_MARKERS)


def _with_retry(fn, attempts: int = 7, base_delay: float = 1.5, max_delay: float = 90.0):
    """Повторение при 429/403 quota с експоненциален backoff — без загуба на доказателства."""
    last: Optional[Exception] = None
    for i in range(attempts):
        _LIMITER.acquire()
        try:
            return fn()
        except Exception as e:  # noqa: BLE001
            last = e
            if i == attempts - 1 or not _is_retryable(e):
                raise
            delay = min(max_delay, base_delay * (2 ** i)) * (0.5 + random.random())
            time.sleep(delay)
    raise last  # pragma: no cover


def fetch_message(
    service: Any,
    message_id: str,
    run_id: str,
    acquisition: Dict[str, Any],
    hash_attachments: bool,
    max_attachment_bytes: int,
) -> Dict[str, Any]:
    msg = _with_retry(
        lambda: service.users().messages().get(
            userId="me", id=message_id, format="full"
        ).execute()
    )

    payload = msg.get("payload") or {}
    headers = _collect_headers(payload.get("headers") or [])

    attachments: List[Dict[str, Any]] = []
    mime_types: List[str] = []
    total_body_size = 0
    part_count = 0

    for part_path, part in _walk_parts(payload):
        part_count += 1
        mime = part.get("mimeType") or ""
        if mime:
            mime_types.append(mime)
        body = part.get("body") or {}
        size = int(body.get("size") or 0)
        total_body_size += size
        filename = part.get("filename") or ""
        att_id = body.get("attachmentId")
        if not (filename or att_id):
            continue

        att: Dict[str, Any] = {
            "part_path": part_path,
            "filename": filename,
            "mime_type": mime,
            "size_bytes": size,
            "attachment_id": att_id,
            "sha256": None,
            "hashed": False,
            "hash_note": None,
        }

        if not att_id:
            att["hash_note"] = "no attachmentId (inline part)"
        elif not hash_attachments:
            att["hash_note"] = "hashing disabled by flag"
        elif size > max_attachment_bytes:
            att["hash_note"] = f"skipped: size exceeds {max_attachment_bytes} bytes"
        else:
            try:
                blob = _with_retry(
                    lambda: service.users().messages().attachments().get(
                        userId="me", messageId=message_id, id=att_id
                    ).execute()
                )
                raw = _decode_b64url(blob.get("data") or "")
                att["sha256"] = sha256_bytes(raw)
                att["hashed"] = True
            except Exception as e:  # noqa: BLE001 - всеки провал се документира
                att["hash_note"] = f"error: {type(e).__name__}: {e}"

        attachments.append(att)

    internal_ms = int(msg.get("internalDate") or 0)

    record: Dict[str, Any] = {
        "schema": RECORD_SCHEMA,
        "run_id": run_id,
        "acquisition": acquisition,
        "message_id": msg.get("id"),
        "thread_id": msg.get("threadId"),
        "history_id": msg.get("historyId"),
        "internal_date_utc": (
            iso(datetime.fromtimestamp(internal_ms / 1000, tz=timezone.utc))
            if internal_ms
            else None
        ),
        "internal_date_epoch_ms": internal_ms,
        "labels": msg.get("labelIds") or [],
        "size_estimate_bytes": msg.get("sizeEstimate"),
        "snippet": msg.get("snippet") or "",
        "headers": headers,
        "parts_summary": {
            "part_count": part_count,
            "total_body_size_bytes": total_body_size,
            "mime_types": sorted(set(mime_types)),
        },
        "attachments": attachments,
        "extracted_at_utc": iso(utcnow()),
    }

    # Идентификатор на доказателството: стабилен, детерминистичен
    id_seed = f"{record['message_id']}|{record['thread_id']}|{internal_ms}"
    record["evidence_id"] = sha256_bytes(id_seed.encode("utf-8"))
    record["record_sha256"] = sha256_bytes(canonical_json(record))
    return record


# --------------------------------------------------------------------------- #
# Изходи
# --------------------------------------------------------------------------- #
def _acquire_batch(
    creds: Any,
    message_ids: List[str],
    run_id: str,
    acquisition: Dict[str, Any],
    hash_attachments: bool,
    max_attachment_bytes: int,
    domains: List[str],
    log: "EvidenceLog",
    workers: int,
    progress_every: int = 50,
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """Паралелно извличане; редът на записите се нормализира по-късно."""
    records: List[Dict[str, Any]] = []
    errors: List[Dict[str, Any]] = []
    lock = threading.Lock()
    accepted = 0

    def work(mid: str) -> Dict[str, Any]:
        return fetch_message(
            _thread_service(creds),
            mid,
            run_id=run_id,
            acquisition=acquisition,
            hash_attachments=hash_attachments,
            max_attachment_bytes=max_attachment_bytes,
        )

    with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        futures = {pool.submit(work, mid): mid for mid in message_ids}
        for fut in as_completed(futures):
            mid = futures[fut]
            try:
                rec = fut.result()
            except Exception as e:  # noqa: BLE001
                err = {
                    "message_id": mid,
                    "error": f"{type(e).__name__}: {e}",
                    "at_utc": iso(utcnow()),
                }
                with lock:
                    errors.append(err)
                log.write("message_error", **err)
                continue

            exact, substring = match_domains(rec["headers"], domains)
            rec["matched_domains"] = exact
            rec["matched_domains_substring"] = substring
            rec["domain_match_method"] = (
                "exact" if exact else ("substring-only" if substring else "none")
            )

            if domains and not exact:
                # Заявката на Gmail върна съобщението, но строгият домейн тест не мина
                log.write(
                    "excluded",
                    message_id=rec["message_id"],
                    evidence_id=rec["evidence_id"],
                    substring_hits=substring,
                )
                continue

            rec.pop("record_sha256", None)
            rec["record_sha256"] = sha256_bytes(canonical_json(rec))
            with lock:
                records.append(rec)
                accepted += 1
                n = accepted
                log.write(
                    "record_captured",
                    message_id=rec["message_id"],
                    evidence_id=rec["evidence_id"],
                    record_sha256=rec["record_sha256"],
                    matched_domains=exact,
                    attachments=len(rec["attachments"]),
                )
            if n % progress_every == 0:
                print(f"  ... приети {n}/{len(message_ids)}")

    return records, errors


CSV_FIELDS = [
    "evidence_id",
    "message_id",
    "thread_id",
    "internal_date_utc",
    "date_header",
    "from",
    "to",
    "cc",
    "bcc",
    "subject",
    "message_id_header",
    "reply_to",
    "return_path",
    "auth_results",
    "labels",
    "size_estimate_bytes",
    "attachment_count",
    "attachment_filenames",
    "matched_domains",
    "record_sha256",
]


def _first(value: Any) -> str:
    if isinstance(value, list):
        return str(value[0]) if value else ""
    return "" if value is None else str(value)


def _flat(value: Any) -> str:
    if isinstance(value, list):
        return " | ".join(str(v) for v in value)
    return "" if value is None else str(value)


def record_to_row(rec: Dict[str, Any]) -> Dict[str, str]:
    h = rec.get("headers") or {}
    return {
        "evidence_id": rec.get("evidence_id", ""),
        "message_id": rec.get("message_id", ""),
        "thread_id": rec.get("thread_id", ""),
        "internal_date_utc": rec.get("internal_date_utc", ""),
        "date_header": _first(h.get("Date")),
        "from": _first(h.get("From")),
        "to": _first(h.get("To")),
        "cc": _first(h.get("Cc")),
        "bcc": _first(h.get("Bcc")),
        "subject": _first(h.get("Subject")),
        "message_id_header": _first(h.get("Message-ID") or h.get("Message-Id")),
        "reply_to": _first(h.get("Reply-To")),
        "return_path": _first(h.get("Return-Path")),
        "auth_results": _flat(h.get("Authentication-Results")),
        "labels": _flat(rec.get("labels")),
        "size_estimate_bytes": str(rec.get("size_estimate_bytes") or ""),
        "attachment_count": str(len(rec.get("attachments") or [])),
        "attachment_filenames": _flat([a.get("filename") for a in rec.get("attachments") or []]),
        "matched_domains": _flat(rec.get("matched_domains") or []),
        "record_sha256": rec.get("record_sha256", ""),
    }


class EvidenceLog:
    """Append-only JSONL лог на действията (нишково безопасен)."""

    def __init__(self, path: Path):
        self.path = path
        self._lock = threading.Lock()

    def write(self, event: str, **fields: Any) -> None:
        entry = {"ts_utc": iso(utcnow()), "event": event, **fields}
        line = json.dumps(entry, ensure_ascii=False, default=str) + "\n"
        with self._lock:
            with self.path.open("a", encoding="utf-8") as f:
                f.write(line)


def write_csv(path: Path, records: List[Dict[str, Any]]) -> None:
    with path.open("w", encoding="utf-8-sig", newline="") as f:
        w = csv.DictWriter(f, fieldnames=CSV_FIELDS)
        w.writeheader()
        for rec in records:
            w.writerow(record_to_row(rec))


# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #
def cmd_extract(args: argparse.Namespace) -> int:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace") if hasattr(sys.stdout, "reconfigure") else None

    base = Path(args.base_dir).resolve()
    filters_path = base / FILTERS_FILE
    token_path = base / TOKEN_FILE
    configure_limiter(args.max_rps)

    filters, filters_raw = load_filters(filters_path)
    domains = normalize_domains(filters)
    query, query_parts = build_query(
        filters, domains=domains, use_domain_query=not args.no_domain_query
    )

    run_id = utcnow().strftime("%Y%m%dT%H%M%SZ") + "-" + uuid.uuid4().hex[:8]
    out_dir = Path(args.out).resolve() if args.out else (base / DEFAULT_OUT_DIR)
    run_dir = out_dir / f"run_{run_id}"
    run_dir.mkdir(parents=True, exist_ok=True)

    log = EvidenceLog(run_dir / "forensic.log")
    started = utcnow()

    log.write(
        "run_start",
        run_id=run_id,
        tool=f"{TOOL_NAME}/{TOOL_VERSION}",
        operator=args.operator,
        host=socket.gethostname(),
        filters_file=str(filters_path),
        filters_sha256=sha256_bytes(filters_raw),
        gmail_query=query,
        max_messages=args.max,
        attachment_hashing=not args.no_attachment_hash,
    )

    print(f"Run ID : {run_id}")
    print(f"Изход  : {run_dir}")
    print(f"Заявка : {query if query else '(без Gmail заявка — само Python филтър)'}")
    print(f"Домейни: {', '.join(domains) if domains else '(няма)'}")

    service, token_meta, creds = get_service(token_path, persist_token=args.persist_token)
    log.write("auth_ready", **token_meta)

    acquisition = {
        "tool": f"{TOOL_NAME}/{TOOL_VERSION}",
        "source": "gmail.googleapis.com (users.messages.list + users.messages.get)",
        "scope": SCOPES[0],
        "gmail_query": query,
        "gmail_query_parts": query_parts,
        "domain_matcher": "exact-domain + substring (transparency)",
        "domain_filter": domains,
        "run_id": run_id,
        "operator": args.operator,
        "host": socket.gethostname(),
        "filters_sha256": sha256_bytes(filters_raw),
        "read_only": True,
    }

    records: List[Dict[str, Any]] = []
    errors: List[Dict[str, Any]] = []
    message_ids = list(iter_message_ids(service, query, args.max))
    scanned = len(message_ids)
    print(f"Извлечени за обработка: {scanned} съобщения, нишки: {args.workers}")
    log.write("batch_start", messages=scanned, workers=args.workers)

    records, errors = _acquire_batch(
        creds,
        message_ids,
        run_id=run_id,
        acquisition=acquisition,
        hash_attachments=not args.no_attachment_hash,
        max_attachment_bytes=args.max_attachment_bytes,
        domains=domains,
        log=log,
        workers=args.workers,
    )

    records.sort(key=lambda r: (r.get("internal_date_epoch_ms") or 0, r.get("message_id") or ""))

    jsonl_path = run_dir / "evidence_records.jsonl"
    with jsonl_path.open("w", encoding="utf-8") as f:
        for rec in records:
            f.write(json.dumps(rec, ensure_ascii=False, sort_keys=True, default=str) + "\n")

    csv_path = run_dir / "evidence_summary.csv"
    write_csv(csv_path, records)

    filters_snapshot = run_dir / "filters_snapshot.yaml"
    filters_snapshot.write_bytes(filters_raw)

    script_path = Path(__file__).resolve()

    # Финалният ред в лога се записва ПРЕДИ изчисляването на хешовете.
    # Иначе forensic.log се променя след хеширането и verify отчита
    # несъответствие по този файл.
    log.write("run_finish", run_id=run_id, records=len(records), errors=len(errors))

    finished = utcnow()
    outputs: List[Dict[str, Any]] = []
    for p in (filters_snapshot, jsonl_path, csv_path, run_dir / "forensic.log"):
        outputs.append(
            {
                "file": p.name,
                "size_bytes": p.stat().st_size,
                "sha256": sha256_file(p),
            }
        )

    manifest = {
        "schema": "chain-of-custody/v1",
        "run_id": run_id,
        "tool": {"name": TOOL_NAME, "version": TOOL_VERSION, "script_sha256": sha256_file(script_path)},
        "operator": args.operator,
        "host": socket.gethostname(),
        "platform": platform.platform(),
        "python": sys.version.split()[0],
        "started_utc": iso(started),
        "finished_utc": iso(finished),
        "duration_seconds": round((finished - started).total_seconds(), 3),
        "source": {
            "provider": "Google Gmail API v1",
            "access": "read-only",
            "scope": SCOPES[0],
            "token": token_meta,
        },
        "criteria": {
            "filters_file": FILTERS_FILE,
            "filters_sha256": sha256_bytes(filters_raw),
            "filters_normalized": filters,
            "gmail_query": query,
            "gmail_query_parts": query_parts,
            "domain_filter": domains,
            "max_messages_limit": args.max,
        },
        "results": {
            "messages_scanned": scanned,
            "records_accepted": len(records),
            "records_excluded_by_domain": scanned - len(records) - len(errors),
            "errors": len(errors),
            "attachments_hashed": sum(
                1 for r in records for a in r["attachments"] if a.get("hashed")
            ),
            "attachments_total": sum(len(r["attachments"]) for r in records),
            "error_details": errors,
        },
        "records_digest": sha256_bytes(
            "".join(r["record_sha256"] for r in records).encode("utf-8")
        ),
        "outputs": outputs,
        "custody_statement": (
            "Данните са извлечени в режим само за четене чрез Gmail API със scope "
            "gmail.readonly. Съдържанието на пощенската кутия не е променяно. "
            "Целостта на всеки запис се проверява чрез record_sha256 (SHA-256 върху "
            "каноничен JSON), а на файловете — чрез полетата outputs[].sha256."
        ),
    }

    manifest_path = run_dir / "chain_of_custody.json"
    manifest_path.write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2, default=str), encoding="utf-8"
    )
    manifest["outputs"].append(
        {
            "file": manifest_path.name,
            "size_bytes": manifest_path.stat().st_size,
            "sha256": sha256_file(manifest_path),
            "note": "хеш на самия манифест, изчислен преди добавянето на този запис",
        }
    )

    print()
    print(f"Готово. Приети записи: {len(records)} (прегледани {scanned}, грешки {len(errors)})")
    print(f"JSONL    : {jsonl_path}")
    print(f"CSV      : {csv_path}")
    print(f"Манифест : {manifest_path}")
    print(f"Хеш на извадката (records_digest): {manifest['records_digest']}")
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    run_dir = Path(args.verify).resolve()
    manifest_path = run_dir / "chain_of_custody.json"
    if not manifest_path.exists():
        print(f"Липсва манифест: {manifest_path}", file=sys.stderr)
        return 2

    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    ok = True

    print(f"Проверка на run: {manifest.get('run_id')}")
    for out in manifest.get("outputs", []):
        p = run_dir / out["file"]
        if not p.exists():
            print(f"  [ЛИПСВА] {out['file']}")
            ok = False
            continue
        current = sha256_file(p)
        status = "OK" if current == out["sha256"] else "РАЗЛИЧЕН"
        if current != out["sha256"] and not out.get("note"):
            ok = False
        print(f"  [{status:9}] {out['file']}  {current}")

    jsonl_path = run_dir / "evidence_records.jsonl"
    if jsonl_path.exists():
        bad = 0
        total = 0
        digest_parts: List[str] = []
        with jsonl_path.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                total += 1
                rec = json.loads(line)
                stored = rec.pop("record_sha256", None)
                if sha256_bytes(canonical_json(rec)) != stored:
                    bad += 1
                    print(f"  [ПОВРЕДЕН] message_id={rec.get('message_id')}")
                digest_parts.append(stored or "")
        print(f"  Записи: {total}, повредени: {bad}")
        if bad:
            ok = False
        recomputed = sha256_bytes("".join(digest_parts).encode("utf-8"))
        expected = manifest.get("records_digest")
        if expected and recomputed != expected:
            print(f"  [РАЗЛИЧЕН] records_digest  {recomputed} != {expected}")
            ok = False

    print("РЕЗУЛТАТ:", "ЦЯЛОСТТА Е ПОТВЪРДЕНА" if ok else "ОТКРИТИ СА НЕСЪОТВЕТСТВИЯ")
    return 0 if ok else 1


def cmd_reseal(args: argparse.Namespace) -> int:
    """Пре-запечатва манифеста на завършен run (преизчислява outputs[].sha256).

    Използва се, когато след записването на манифеста файл в run директорията е
    бил променен (напр. дописан ред в forensic.log). Не променя записите и не се
    свързва с Gmail — само подновява хешовете и добавя одитна следа за намесата.
    """
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")

    run_dir = Path(args.reseal).resolve()
    manifest_path = run_dir / "chain_of_custody.json"
    if not manifest_path.exists():
        print(f"Липсва манифест: {manifest_path}", file=sys.stderr)
        return 2

    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

    changed: List[Dict[str, str]] = []
    for out in manifest.get("outputs", []):
        p = run_dir / out["file"]
        if not p.exists():
            continue
        current = sha256_file(p)
        if current != out["sha256"]:
            changed.append(
                {"file": out["file"], "old_sha256": out["sha256"], "new_sha256": current}
            )
        out["sha256"] = current
        out["size_bytes"] = p.stat().st_size

    history = manifest.setdefault("reseal_history", [])
    history.append(
        {
            "resealed_utc": iso(utcnow()),
            "reason": args.reason
            or "преизчисляване на хешовете след промяна на файл",
            "changed": changed,
        }
    )
    manifest["resealed_utc"] = iso(utcnow())

    manifest_path.write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2, default=str), encoding="utf-8"
    )

    print(f"Манифестът е пре-запечатан: {manifest_path}")
    if changed:
        for c in changed:
            print(f"  обновен хеш: {c['file']}  {c['old_sha256']} -> {c['new_sha256']}")
    else:
        print("  няма променени файлове")
    print(f"  брой пре-запечатвания: {len(history)}")
    return 0


def cmd_hash_attachments(args: argparse.Namespace) -> int:
    """Фаза 2: допълва SHA-256 на прикачените файлове без да пипа фаза 1."""
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")

    base = Path(args.base_dir).resolve()
    raw_run = Path(args.hash_attachments_only)
    run_dir = raw_run if raw_run.is_absolute() else (base / raw_run).resolve()

    records_path = run_dir / "evidence_records.jsonl"
    if not records_path.exists():
        print(f"Липсва {records_path}", file=sys.stderr)
        return 2

    phase1_manifest = run_dir / "chain_of_custody.json"
    phase1_manifest_sha = sha256_file(phase1_manifest) if phase1_manifest.exists() else None

    configure_limiter(args.max_rps)
    service, token_meta, creds = get_service(base / TOKEN_FILE, persist_token=False)

    records = [
        json.loads(line)
        for line in records_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]

    started = utcnow()
    hashed = 0
    failed = 0
    skipped = 0
    total = 0

    for idx, rec in enumerate(records, start=1):
        for att in rec.get("attachments") or []:
            if att.get("hashed"):
                continue
            att_id = att.get("attachment_id")
            if not att_id:
                skipped += 1
                continue
            total += 1
            try:
                blob = _with_retry(
                    lambda: _thread_service(creds).users().messages().attachments().get(
                        userId="me", messageId=rec["message_id"], id=att_id
                    ).execute()
                )
                raw = _decode_b64url(blob.get("data") or "")
                att["sha256"] = sha256_bytes(raw)
                att["hashed"] = True
                att["hash_note"] = "phase2"
                hashed += 1
            except Exception as e:  # noqa: BLE001
                att["hash_note"] = f"phase2 error: {type(e).__name__}: {e}"
                failed += 1

        rec.pop("record_sha256", None)
        rec["record_sha256"] = sha256_bytes(canonical_json(rec))

        if idx % 50 == 0 or idx == len(records):
            print(f"  ... обработени {idx}/{len(records)} съобщения, хеширани {hashed}, грешки {failed}")

    out_jsonl = run_dir / "evidence_records_with_attachments.jsonl"
    with out_jsonl.open("w", encoding="utf-8") as f:
        for rec in records:
            f.write(json.dumps(rec, ensure_ascii=False, sort_keys=True, default=str) + "\n")

    out_csv = run_dir / "evidence_summary_with_attachments.csv"
    write_csv(out_csv, records)

    finished = utcnow()
    manifest = {
        "schema": "chain-of-custody/v1",
        "phase": 2,
        "purpose": "Допълнително изчисляване на SHA-256 за прикачени файлове",
        "tool": {"name": TOOL_NAME, "version": TOOL_VERSION,
                 "script_sha256": sha256_file(Path(__file__).resolve())},
        "operator": args.operator,
        "host": socket.gethostname(),
        "started_utc": iso(started),
        "finished_utc": iso(finished),
        "phase1": {
            "records_file": records_path.name,
            "records_sha256": sha256_file(records_path),
            "manifest_sha256": phase1_manifest_sha,
        },
        "source": {"provider": "Google Gmail API v1", "access": "read-only",
                   "scope": SCOPES[0], "token": token_meta},
        "results": {
            "records": len(records),
            "attachments_attempted": total,
            "attachments_hashed": hashed,
            "attachments_failed": failed,
            "attachments_without_id": skipped,
        },
        "outputs": [
            {"file": out_jsonl.name, "size_bytes": out_jsonl.stat().st_size,
             "sha256": sha256_file(out_jsonl)},
            {"file": out_csv.name, "size_bytes": out_csv.stat().st_size,
             "sha256": sha256_file(out_csv)},
        ],
        "records_digest": sha256_bytes(
            "".join(r["record_sha256"] for r in records).encode("utf-8")
        ),
    }

    manifest_path = run_dir / "chain_of_custody_phase2.json"
    manifest_path.write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2, default=str), encoding="utf-8"
    )

    print(f"\nФаза 2 завършена: хеширани {hashed}, грешки {failed}, без attachmentId {skipped}")
    print(f"JSONL  : {out_jsonl}")
    print(f"CSV    : {out_csv}")
    print(f"Манифест: {manifest_path}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Read-only форензик извличане на Gmail съобщения по filters.yaml"
    )
    p.add_argument("--base-dir", default=str(Path(__file__).resolve().parent),
                   help="Папка с filters.yaml и gmail_token.json")
    p.add_argument("--out", default=None, help=f"Изходна папка (по подразбиране: {DEFAULT_OUT_DIR})")
    p.add_argument("--max", type=int, default=DEFAULT_MAX, help="Максимален брой съобщения")
    p.add_argument("--workers", type=int, default=4,
                   help="Брой паралелни нишки при извличане (по подразбиране 4)")
    p.add_argument("--max-rps", type=float, default=4.0,
                   help="Горна граница на заявките към Gmail в секунда (по подразбиране 4)")
    p.add_argument("--hash-attachments-only", default=None, metavar="RUN_DIR",
                   help="Фаза 2: допълва SHA-256 на прикачените файлове в съществуващ run")
    p.add_argument("--operator", default=os.environ.get("USERNAME", "unknown"),
                   help="Име на оператора (за chain of custody)")
    p.add_argument("--no-attachment-hash", action="store_true",
                   help="Да не се изчислява SHA-256 на прикачените файлове")
    p.add_argument("--max-attachment-bytes", type=int, default=MAX_ATTACHMENT_HASH_BYTES,
                   help="Горна граница за хеширане на прикачен файл")
    p.add_argument("--persist-token", action="store_true",
                   help="Записва опреснения токен на диск (по подразбиране: само в паметта)")
    p.add_argument("--no-domain-query", action="store_true",
                   help="Не добавяй домейните към Gmail заявката (само Python филтър)")
    p.add_argument("--dry-run", action="store_true",
                   help="Само показва заявката и броя съобщения, без експорт")
    p.add_argument("--verify", default=None, metavar="RUN_DIR",
                   help="Проверка на цялостта на предишен run")
    p.add_argument("--reseal", default=None, metavar="RUN_DIR",
                   help="Преизчислява хешовете в манифеста на завършен run")
    p.add_argument("--reason", default=None,
                   help="Причина за пре-запечатването (записва се в манифеста)")
    return p


def cmd_dry_run(args: argparse.Namespace) -> int:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace") if hasattr(sys.stdout, "reconfigure") else None
    base = Path(args.base_dir).resolve()
    filters, filters_raw = load_filters(base / FILTERS_FILE)
    domains = normalize_domains(filters)
    query, parts = build_query(
        filters, domains=domains, use_domain_query=not args.no_domain_query
    )

    print(f"Филтър   : {base / FILTERS_FILE}")
    print(f"SHA-256  : {sha256_bytes(filters_raw)}")
    print(f"Домейни  : {len(domains)} -> {', '.join(domains)}")
    print(f"Заявка   : {query if query else '(празна)'}")
    print(f"Части    : {parts}")
    print(f"Лимит    : {args.max}")

    service, token_meta, _creds = get_service(base / TOKEN_FILE, persist_token=False)
    count = 0
    for _ in iter_message_ids(service, query, args.max):
        count += 1
    print(f"Намерени : {count} съобщения (ограничение {args.max})")
    print(f"Токен    : опреснен в паметта = {token_meta['access_token_refreshed_in_memory']}, "
          f"записан на диск = {token_meta['token_persisted_to_disk']}")
    return 0


def main(argv: Optional[Iterable[str]] = None) -> int:
    args = build_parser().parse_args(list(argv) if argv is not None else None)
    try:
        if args.reseal:
            return cmd_reseal(args)
        if args.verify:
            return cmd_verify(args)
        if args.hash_attachments_only:
            return cmd_hash_attachments(args)
        if args.dry_run:
            return cmd_dry_run(args)
        return cmd_extract(args)
    except FileNotFoundError as e:
        print(f"ГРЕШКА: {e}", file=sys.stderr)
        return 2
    except Exception as e:  # noqa: BLE001
        print(f"ГРЕШКА: {type(e).__name__}: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
