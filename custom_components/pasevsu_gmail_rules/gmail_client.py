"""Gmail API access; no message content is written to disk."""
import base64
import random
import time
from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

SCOPES = ["https://www.googleapis.com/auth/gmail.modify"]

def service_from_token(token_path):
    creds = Credentials.from_authorized_user_file(token_path)
    if not creds.valid:
        if not creds.refresh_token:
            raise ValueError("OAuth refresh token missing")
        creds.refresh(Request())
        # Token intentionally not persisted: refresh again on next service construction.
    if not set(SCOPES).issubset(set(creds.scopes or [])):
        raise ValueError("gmail.modify permission required; re-authorize token")
    return build("gmail", "v1", credentials=creds, cache_discovery=False)

def execute(req):
    for attempt in range(5):
        try:
            return req.execute()
        except HttpError as exc:
            if exc.resp.status not in (429, 500, 502, 503, 504):
                raise
            delay = min(30, 2**attempt + random.random())
            time.sleep(delay)
    return req.execute()

def list_messages(service, label_id="INBOX", query="", page_token=None, limit=100):
    kw = {"userId":"me", "maxResults":min(max(int(limit),1),500)}
    if label_id and label_id != "ALL": kw["labelIds"] = [label_id]
    if query: kw["q"] = query
    if page_token: kw["pageToken"] = page_token
    return execute(service.users().messages().list(**kw))

def list_labels(service):
    return execute(service.users().labels().list(userId="me")).get("labels", [])

def get_message(service, message_id, fmt="full"):
    if fmt not in ("full", "metadata", "raw"): raise ValueError("Invalid format")
    return execute(service.users().messages().get(userId="me", id=message_id, format=fmt))

def get_attachment(service, message_id, attachment_id):
    obj = execute(service.users().messages().attachments().get(userId="me", messageId=message_id, id=attachment_id))
    return base64.urlsafe_b64decode(obj.get("data", "") + "===")

def modify(service, message_id, add=(), remove=()):
    return execute(service.users().messages().modify(userId="me", id=message_id,
                    body={"addLabelIds":list(add), "removeLabelIds":list(remove)}))

def trash(service, message_id):
    return execute(service.users().messages().trash(userId="me", id=message_id))

def ensure_label(service, label_name, known):
    if label_name in known: return known[label_name]
    obj = execute(service.users().labels().create(userId="me", body={"name":label_name,
        "labelListVisibility":"labelShow", "messageListVisibility":"show"}))
    known[label_name] = obj["id"]
    return obj["id"]


def profile(service):
    return execute(service.users().getProfile(userId="me"))

def history_since(service, history_id):
    """Gmail history cursor: collects new messages, handles all history pages."""
    ids = set()
    token = None
    latest = str(history_id)
    while True:
        kw = {"userId":"me", "startHistoryId":str(history_id), "historyTypes":["messageAdded"], "maxResults":500}
        if token: kw["pageToken"] = token
        result = execute(service.users().history().list(**kw))
        latest = str(result.get("historyId", latest))
        for event in result.get("history", []):
            for item in event.get("messagesAdded", []):
                mid = (item.get("message") or {}).get("id")
                if mid: ids.add(mid)
        token = result.get("nextPageToken")
        if not token: break
    return latest, sorted(ids)
