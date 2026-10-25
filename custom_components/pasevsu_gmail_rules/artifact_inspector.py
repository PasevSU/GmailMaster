"""Preserves ordered repeated headers and recursively describes MIME."""
import base64
import hashlib
from .gmail_client import get_attachment

def _part(part):
    body = part.get("body") or {}
    return {"part_id":part.get("partId", ""), "mime_type":part.get("mimeType", ""),
            "filename":part.get("filename", ""), "headers":part.get("headers", []),
            "size":body.get("size", 0), "attachment_id":body.get("attachmentId"),
            "children":[_part(x) for x in part.get("parts", [])]}

def inspect_message(msg):
    payload = msg.get("payload") or {}
    return {"id":msg.get("id"), "thread_id":msg.get("threadId"),
            "history_id":msg.get("historyId"), "internal_date":msg.get("internalDate"),
            "labels":msg.get("labelIds", []), "size_estimate":msg.get("sizeEstimate"),
            "snippet":msg.get("snippet", ""), "headers":payload.get("headers", []),
            "mime":_part(payload)}

def attachment_digest(service, message_id, attachment_id):
    data = get_attachment(service, message_id, attachment_id)
    return {"size":len(data), "sha256":hashlib.sha256(data).hexdigest(),
            "sha512":hashlib.sha512(data).hexdigest()}

def raw_digest(msg):
    data = base64.urlsafe_b64decode(msg.get("raw", "") + "===")
    return {"size":len(data), "sha256":hashlib.sha256(data).hexdigest(),
            "sha512":hashlib.sha512(data).hexdigest()}


def raw_message_details(msg, max_preview=250000):
    """RFC822 parsed in original header order; binary bytes never persisted."""
    from email import policy
    from email.parser import BytesParser
    data=base64.urlsafe_b64decode(msg.get("raw","")+"===")
    parsed=BytesParser(policy=policy.default).parsebytes(data)
    sep=data.find(b"\r\n\r\n")
    if sep<0:sep=data.find(b"\n\n")
    headers=[]
    for name,value in parsed.raw_items():
        headers.append({"name":name,"value":value})
    return {"id":msg.get("id"),"size":len(data),"sha256":hashlib.sha256(data).hexdigest(),
      "sha512":hashlib.sha512(data).hexdigest(),"headers":headers,
      "raw_preview":data[:max_preview].decode("utf-8",errors="replace"),
      "preview_truncated":len(data)>max_preview,
      "note":"Raw preview is decoded for display; use hashes for byte-level identity. Header order preserved."}
