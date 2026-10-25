# Architecture and lifecycle

```text
HA config entry (one Gmail account)
  ├── OAuth token → Gmail API
  ├── periodic Gmail profile/history poll
  │     ├── no change → no rules scan
  │     └── messageAdded → rule matching → label/read actions
  ├── daily lifecycle check → optional Trash
  ├── HA operational sensor
  └── admin-only WebSocket API
        ├── list labels / paged messages
        ├── inspect headers and recursive MIME
        └── calculate RAW or attachment digests on demand
```

`historyId` is saved in HA storage per config entry. Minimal lifecycle records are saved separately. Message content and attachment bytes are fetched into memory when requested and not written to files by the integration.

**No stored folder tables:** a folder's message list is returned on demand via `pasevsu_gmail/list`; a consumer frontend may display it as a table. The requested detailed message table is returned as structured JSON via `pasevsu_gmail/inspect`; no UI or JS is included.

Gmail labels are not filesystem folders. Message metadata lists are paginated with Gmail `nextPageToken`. Gmail history can expire; after an HTTP 404 the cursor is reset and a recovery/backfill feature is not yet implemented.

The sensor reports number of newly added message IDs in the last poll, not the unread count.
