# PasevSU Gmail Rule Manager — backend-only Home Assistant integration

**Release: 0.5.0 (pre-release / not validated against a live HA instance).** Native custom integration for Home Assistant with a Gmail history polling sensor, JSON-based rules, read-observed lifecycle policies, and authenticated WebSocket endpoints. **This GitHub package contains no JavaScript, custom panel, Lovelace card, HTML report generator or standalone web server.**

## Features and behavior

- Independent HA configuration entries for different Gmail accounts (one OAuth token path per entry).
- Gmail `users.history.list` polling using a persisted `historyId` cursor; initial poll creates baseline and does not retroactively sort existing messages.
- Rules are applied to **newly added** Gmail messages only. The JSON `query` is passed to Gmail as-is; no hard-coded domains.
- `labelsToAdd` creates labels as needed; `move` removes `INBOX`; `mark_read` removes `UNREAD`.
- Per-rule `lifecycle` can move mail to Gmail Trash after N days from **first observed read**, not the actual historical read timestamp. Lifecycle evaluation runs independently every 24 hours.
- Home Assistant `sensor` shows count of messages detected at the **last poll**, check timestamps, cursor initialization, last error and last processing result. It is **not** a continuously accumulating unread counter.
- Authenticated **administrator-only** WebSocket API for label listing, paged message metadata, detailed MIME/header inspection, and SHA-256/SHA-512 digests on request.
- No mail bodies, attachments or generated email tables are persisted to HA disk; views are generated on demand via API. OAuth token, rules and minimal lifecycle/cursor metadata are persisted.
- No IMAP connection and no duplicate IMAP session.

## Installation (manual)

1. Copy `custom_components/pasevsu_gmail_rules/` to `/config/custom_components/pasevsu_gmail_rules/`. **Do not copy the GitHub repository root into `custom_components`.**
2. Keep OAuth tokens outside the integration folder, e.g. `/config/pasevsu_gmail/gmail_accounts/user@gmail.com.json`. Do not commit tokens.
3. Copy `examples/gmail_rules.json` to `/config/pasevsu_gmail/gmail_rules.json`; edit as needed.
4. Ensure your Gmail OAuth token was granted `https://www.googleapis.com/auth/gmail.modify` and contains a usable refresh token. This package does **not** include an interactive Google login flow. OAuth authorization must be performed separately on a trusted machine.
5. Restart Home Assistant. Go to **Settings → Devices & services → Add integration → PasevSU Gmail Rule Manager**.
6. Supply absolute paths to the rules and token JSON files. Use `dry_run=true` for initial validation. Interval 5–1440 minutes; default 15.
7. Add a separate integration entry for each Gmail account, using its own token path. You may reuse one rules file or use distinct rules per account.
8. Inspect **Developer Tools → States** for `sensor.*new_mail_detected` and check HA logs for errors.

## Layout

```text
custom_components/pasevsu_gmail_rules/
  __init__.py           # lifecycle, polling, HA registration
  config_flow.py        # per-account setup/options
  sensor.py             # new mail operational sensor
  gmail_client.py       # Gmail API, retry, history and metadata
  rules_engine.py       # rules and lifecycle
  artifact_inspector.py # ordered headers, recursive MIME and hashes
  websocket_api.py      # admin-only WS backend
  const.py
  strings.json
  manifest.json
examples/gmail_rules.json
.github/workflows/validate.yml
hacs.json
README.md
docs/*.md
```

## Rules schema

```json
{
  "filter": [
    {
      "query": "from:accounts.google.com",
      "labelsToAdd": ["INBOX/Google"],
      "move": false,
      "mark_read": false,
      "lifecycle": {"enabled": false, "days": 30, "action": "trash"}
    }
  ]
}
```

`query` uses Gmail search syntax, not regex. Rules execute in order; label changes may combine. The first matching rule owns lifecycle. `move=true` does **not** move a message to a real folder; it removes the INBOX label while adding requested labels. `dry_run=true` suppresses Gmail modifications and lifecycle state changes.

## Important limits

- **Backend only:** no sidebar Gmail Explorer is registered in this release because JavaScript was explicitly excluded. Existing JS UI must be installed/maintained separately and its API contract checked against this release.
- **Polling, not push:** new messages are detected at the configured interval; `historyId` can expire. An expired cursor is re-baselined with an error attribute; missed mail is not automatically recovered.
- **No historical import:** the first run does not process old mail.
- **History `messageAdded` events** may include messages added by import or movement, not exclusively newly received INBOX mail.
- **Query scan bound:** each rule scans up to 20 pages of 500 messages; a match beyond that bound may be missed and `truncated=true` appears in the processing result.
- **Large mailboxes:** Gmail API requests can be numerous; this release has not been load-tested.
- **Token refresh:** refreshed access tokens are not written back to the token file; valid refresh credentials are required.
- **Security:** WebSocket methods require HA administrator privileges; protect HA access and OAuth token files.
- **Lifecycle:** changing rule order after lifecycle tracking begins can change which rule an existing record references. Avoid reordering active lifecycle rules until migration is implemented.
- **Not production certified:** no real HA/Gmail end-to-end testing has been performed. Enable destructive actions only after verification on a test account.

See [docs/INSTALLATION.md](docs/INSTALLATION.md), [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md), [docs/API.md](docs/API.md), [docs/SECURITY.md](docs/SECURITY.md), and [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md).

## Optional account and forensic helpers

Selected source modules from the user-provided `accaunt_helper.7z` are available under `tools/account_helper/`. They are not imported by the HA integration. See [docs/ACCOUNT_HELPER.md](docs/ACCOUNT_HELPER.md) for installation, security, source selection, and exclusions. Repository restrictions include `.gitignore`, `.gitattributes`, `.editorconfig`, `.dockerignore`, pre-commit hooks, GitHub validation, secret/mail guard, security policy, contribution guidelines, issue templates and dependency updates.
