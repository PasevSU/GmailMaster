"""Fail CI if repository contains likely secrets, mailbox dumps, or frontend JS."""
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
EXCLUDED = {".git", ".venv", "__pycache__", ".pytest_cache"}
FORBIDDEN_NAMES = re.compile(r"^(gmail_token.*\.json|client_secrets?.*\.json|credentials\.json|token\.json|\.auth_done\.json)$", re.I)
FORBIDDEN_SUFFIXES = {".eml", ".mbox", ".pst", ".ost", ".p12", ".pfx", ".key", ".7z"}
FORBIDDEN_DIRS = {"gmail_accounts", "forensic_out", "forensic_pdf_reports", "eml_in", "gmail_full_json"}
PATTERNS = [
    re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH |ENCRYPTED )?PRIVATE KEY-----"),
    re.compile(rb"\"refresh_token\"\s*:\s*\"[^\"]+\""),
    re.compile(rb"\"client_secret\"\s*:\s*\"[^\"]+\""),
]
errors = []
for p in ROOT.rglob("*"):
    if not p.is_file() or set(p.relative_to(ROOT).parts) & EXCLUDED:
        continue
    rel = p.relative_to(ROOT)
    if FORBIDDEN_NAMES.match(p.name) or p.suffix.lower() in FORBIDDEN_SUFFIXES or set(rel.parts) & FORBIDDEN_DIRS:
        errors.append(f"Forbidden file: {rel}")
        continue
    if p.suffix.lower() == ".js":
        errors.append(f"Frontend JavaScript excluded: {rel}")
    if p.stat().st_size > 2_000_000:
        errors.append(f"Oversized file: {rel}")
        continue
    if p.suffix.lower() in {".py", ".json", ".yaml", ".yml", ".md", ".txt"}:
        data = p.read_bytes()
        for pattern in PATTERNS:
            if pattern.search(data):
                errors.append(f"Possible secret: {rel}")
                break
if errors:
    print("\n".join(errors), file=sys.stderr)
    raise SystemExit(1)
print("Repository guard: PASS")
