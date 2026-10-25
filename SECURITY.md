# Security policy

## Reporting
Report security issues privately to the repository maintainer using GitHub private vulnerability reporting (if enabled). Never open a public issue containing credentials, tokens, emails or personal data.

## Scope
This is a pre-release Home Assistant integration. Gmail OAuth tokens grant mailbox access; never include them in commits, releases, logs or issue attachments. Use separate account paths outside `custom_components/`.

## Disclosure and revocation
If a token was committed, revoke the Google OAuth grant immediately, rotate affected credentials, and remove the data from Git history; adding a `.gitignore` entry does not remove committed secrets.

## Authorization
WebSocket methods are intended for Home Assistant administrators only. Audit access before production use. The helper scripts under `tools/account_helper/` are independent utilities, not Home Assistant runtime modules.
