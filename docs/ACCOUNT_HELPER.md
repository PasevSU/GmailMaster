# Account helper integration (from `accaunt_helper.7z`)

The user-supplied archive was inspected. The repository includes **selected source utilities** under `tools/account_helper/` and **excludes all OAuth credentials, token caches, account JSON files, `.auth_done.json`, private messages, Gmail FULL JSON dumps, generated reports, forensic evidence, PDFs, logs, cache files and editor-specific settings**. The archive contained substantial sensitive/generated data, which must not be published to GitHub.

## Included tools

- `add_gmail_account.py`: desktop Google OAuth flow, account selection and per-account token creation. Updated to request `gmail.modify`, use `PASEVSU_GOOGLE_CLIENT_SECRET` for the client JSON and store tokens outside the repository by default in `~/.pasevsu_gmail/gmail_accounts/` (override with `PASEVSU_GMAIL_ACCOUNTS_DIR`).
- `auth_flow.py`, `gmail_auth.py`, `gmail_sensors.py`: original standalone auth/mail scripts. They are **not** wired into HA runtime; verify local path assumptions and required scopes before use.
- `eml_index.py`, `eml_reverse.py`, `forensic_extract.py`, `forensic_report.py`, `forensic_pdf_report.py`, `pgp_sign.py`: standalone forensic utilities; optional dependencies and external binaries may be required.
- `filters.yaml`, `imap_settings.example.json`: example configuration from the source archive; `filters.yaml` is **not** automatically interpreted as the integration's `gmail_rules.json`.
- `gmail_raw_full_infotypes_package/`: source report generator and infotype catalog only, not mail content or generated HTML.

## Add an account on Windows

```powershell
$env:PASEVSU_GOOGLE_CLIENT_SECRET = 'C:\secure\client_secret.json'
$env:PASEVSU_GMAIL_ACCOUNTS_DIR = 'C:\secure\gmail_accounts'
py -3.13 -m pip install google-auth-oauthlib google-api-python-client
py -3.13 tools\account_helper\add_gmail_account.py
```

Use the resulting per-account token path in the HA integration config flow. The script is run on a trusted desktop machine with a browser; Home Assistant does not need a browser or a second IMAP connection.

## Security and limitations

- Never commit the token or OAuth client JSON. Keep files under `/config/pasevsu_gmail/` on HA, or a secured private Windows folder.
- The helper scripts are retained as **standalone source** for review and migration. They are not claimed to be fully compatible with the HA runtime or tested end to end.
- `.gitignore` is a safety net, not a guarantee: run `python scripts/repo_guard.py` before every push. Existing Git history must be checked separately.
- The original archive also contained Firebase/FCM and token-retrieval code; it is not bundled because those unrelated components expand the credential and network security surface.
