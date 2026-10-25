"""Rules execute in declared order; first match owns lifecycle."""
import json
from pathlib import Path
from datetime import datetime, timedelta, timezone
from .gmail_client import list_messages, list_labels, get_message, ensure_label, modify, trash

def load_rules(path):
    obj = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(obj, dict) or not isinstance(obj.get("filter"), list):
        raise ValueError("Expected JSON object with filter array")
    for index, rule in enumerate(obj["filter"]):
        if not isinstance(rule, dict) or not isinstance(rule.get("query"), str):
            raise ValueError(f"Invalid query in rule {index}")
        if not isinstance(rule.get("labelsToAdd", []), list) or not all(isinstance(x,str) and x for x in rule.get("labelsToAdd", [])):
            raise ValueError(f"Invalid labelsToAdd in rule {index}")
        life = rule.get("lifecycle") or {}
        if not isinstance(life, dict): raise ValueError(f"Invalid lifecycle in rule {index}")
        if life.get("enabled") and (type(life.get("days")) is not int or life["days"] < 1):
            raise ValueError(f"Invalid lifecycle.days in rule {index}")
        if life.get("action", "trash") != "trash":
            raise ValueError("Only trash lifecycle action supported")
    return obj

def _stamp(): return datetime.now(timezone.utc).isoformat()

def run_new_messages(service, rules, state, message_ids, dry_run=True):
    """Apply query rules to new messages only. Query is passed unchanged to Gmail.
    Gmail q cannot be evaluated locally; intersect each query's results with new IDs.
    """
    from .gmail_client import list_messages
    pending = set(message_ids)
    known = {x["name"]:x["id"] for x in list_labels(service)}
    outcome = {"new":len(pending), "matched":0, "modified":0, "dry_run":dry_run, "truncated":False}
    if not pending: return outcome
    winners = set()
    for idx, rule in enumerate(rules["filter"]):
        matched = set()
        page = None
        # Scan query results; for broad queries a high-volume mailbox may need many pages.
        pages_scanned = 0
        while True:
            result = list_messages(service, "ALL", rule["query"], page, 500)
            pages_scanned += 1
            matched.update(x["id"] for x in result.get("messages", []) if x["id"] in pending)
            page = result.get("nextPageToken")
            if not page: break
            if pages_scanned >= 20:
                outcome["truncated"] = True
                break
        for mid in sorted(matched):
            try: message = get_message(service, mid, "metadata")
            except Exception: continue # may have been deleted between events
            labels = set(message.get("labelIds", []))
            add = []
            for name in rule.get("labelsToAdd", []):
                lid = known.get(name) or (None if dry_run else ensure_label(service, name, known))
                if lid and lid not in labels: add.append(lid)
            remove = []
            if rule.get("move") and "INBOX" in labels: remove.append("INBOX")
            if rule.get("mark_read") and "UNREAD" in labels: remove.append("UNREAD")
            if (add or remove) and not dry_run:
                modify(service, mid, add, remove)
                outcome["modified"] += 1
            outcome["matched"] += 1
            if mid not in winners:
                winners.add(mid)
                life = rule.get("lifecycle") or {}
                if life.get("enabled") and not dry_run:
                    record = state.setdefault(mid, {"rule_index":idx})
                    record.setdefault("rule_index", idx)
                    if ("UNREAD" not in labels or "UNREAD" in remove) and not record.get("read_observed_at"):
                        record["read_observed_at"] = _stamp()
    return outcome


def evaluate_lifecycle(service, rules, state, dry_run=True):
    """Evaluate expirations even if there are no new messages; only saved IDs."""
    count = 0
    now = datetime.now(timezone.utc)
    for mid, record in list(state.items()):
        if not isinstance(record, dict) or "rule_index" not in record: continue
        idx = record["rule_index"]
        if not isinstance(idx, int) or idx >= len(rules["filter"]): continue
        life = rules["filter"][idx].get("lifecycle") or {}
        if not life.get("enabled"): continue
        try: msg = get_message(service, mid, "metadata")
        except Exception: continue
        labels = set(msg.get("labelIds", []))
        if "TRASH" in labels: continue
        if "UNREAD" not in labels and not record.get("read_observed_at") and not dry_run:
            record["read_observed_at"] = _stamp()
        if "UNREAD" in labels: continue
        stamp = record.get("read_observed_at")
        if stamp and now >= datetime.fromisoformat(stamp) + timedelta(days=life["days"]):
            if not dry_run:
                trash(service, mid)
                count += 1
    return {"trashed":count,"tracked":len(state),"dry_run":dry_run}
