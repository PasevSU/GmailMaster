# GmailMaster 0.6.0 — verified implementation scope

## Added
- Explicit Gmail history cursor expiry state; never silently advance cursor on 404.
- Admin-only `pasevsu_gmail/recover`: bounded 10,000-message reconciliation; cursor advances only after completed processing.
- Admin-only `pasevsu_gmail/raw_details`: SHA-256/512 over exact RFC822 bytes, ordered repeated headers, UTF-8 display preview limited to 250,000 bytes.
- Admin-only `pasevsu_gmail/thread`: on-demand thread metadata.
- Rule scan budget now fails closed instead of accepting partial matches.

## Important limitations
- Recovery of mail older than 10,000 recent messages requires external/manual handling.
- Query matching still scans Gmail search result pages; large mailboxes can hit the scan limit.
- No JavaScript, browser panel, attachment persistence, cryptographic signature validation, or true read timestamp.
- Existing 0.5.0 tools are carried forward unchanged.
- Integration tests against real Home Assistant/Gmail were not performed.
- In dry_run mode recovery still advances the cursor after simulation; do not use recover to plan a future replay.

## Security
Never commit OAuth tokens, client secrets, message exports or local storage files.
