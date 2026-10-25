# WebSocket API (Home Assistant authenticated)

All calls require an authenticated **HA administrator** connection and a valid `entry_id`. Use `hass.callWS(...)` from a separately maintained frontend, or the HA WebSocket API. These endpoints are not REST endpoints.

## List messages (paged)
`{"type":"pasevsu_gmail/list","entry_id":"<id>","label":"INBOX","query":"","page_token":"<optional>"}`

Result: `{"messages":[{"id":"...","thread_id":"...","date":"...","from":"...","to":"...","subject":"...","labels":["INBOX"],"size":1234}],"next_page_token":"..."}`. `label` can be a Gmail label ID or `ALL`; `query` is a Gmail search string.

## List labels
`{"type":"pasevsu_gmail/labels","entry_id":"<id>"}`

Result: Gmail label objects.

## Inspect one message
`{"type":"pasevsu_gmail/inspect","entry_id":"<id>","message_id":"<gmail_id>"}`

Result: `id`, `thread_id`, `history_id`, `internal_date`, `labels`, `size_estimate`, `snippet`, **ordered array of repeated `headers`**, and recursively nested `mime` objects (`part_id`, `mime_type`, `filename`, `headers`, `size`, `attachment_id`, `children`). Not a complete byte-for-byte RAW viewer.

## Calculate digests
`{"type":"pasevsu_gmail/digest","entry_id":"<id>","message_id":"<gmail_id>"}` computes SHA-256 and SHA-512 for RAW RFC822 bytes.

To digest one attachment, also pass `"attachment_id":"<id>"`. Result: `size`, `sha256`, `sha512`.

## Sensor status
`{"type":"pasevsu_gmail/status","entry_id":"<id>"}` returns `new_count`, `last_check`, `last_new_mail`, `last_error`, `last_result`, `history_initialized`.

## Event
`pasevsu_gmail_rules_new_mail` with `{entry_id, count}` is fired when the poll detects new message IDs.

## Limitations
No frontend files are included. No arbitrary RAW content download endpoint, no attachment download endpoint, no rule editing endpoint, and no multi-account combined mailbox endpoint in this release.
