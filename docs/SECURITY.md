# Security and privacy

- OAuth tokens are credentials. Store them outside the repository, restrict file access, and never post them publicly.
- `gmail.modify` permits modifying messages and moving them to Trash. Keep `dry_run=true` until tested.
- HA WebSocket endpoints enforce administrator status; other HA users must not be given admin roles merely to browse mail.
- MIME headers, subjects, and snippets may contain personal data. Avoid dumping WebSocket responses into logs.
- Message content is fetched on demand and not intentionally persisted to disk. Gmail API and Home Assistant may maintain their own infrastructure logs/caches outside this integration.
- SHA-256/512 digests establish byte consistency for the fetched data, **not** sender authenticity or a legally qualified timestamp. SPF/DKIM/ARC authentication results, when present, are merely mail header claims unless independently validated.
- No PGP signature verification, cryptographic provenance chain, or RFC3161 timestamp verification is implemented in this package.
- The OAuth token path acts as a per-account configuration identifier. Never share it in screenshots or issue reports if it reveals private paths.
- `historyId` expiration requires recovery; do not rely on this pre-release as sole evidence collection.
