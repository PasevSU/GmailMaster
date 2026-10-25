# Installation and configuration

## Requirements
- Supported Home Assistant Core installation capable of running custom integrations. **Exact HA version compatibility has not been verified.**
- Google Gmail API enabled for the OAuth project, an OAuth Desktop client, and a refreshable token with `gmail.modify` scope.
- Internet access from Home Assistant to Google APIs.

## Home Assistant directory example

```text
/config/
  custom_components/pasevsu_gmail_rules/
    __init__.py, config_flow.py, manifest.json, ...
  pasevsu_gmail/
    gmail_rules.json
    gmail_accounts/
      user1@gmail.com.json
      user2@gmail.com.json
```

**Do not put the `gmail_accounts` directory inside the GitHub repository.** Each Gmail account needs a separate integration entry with its own token path.

## Config flow fields
- `rules_path`: absolute filesystem path, e.g. `/config/pasevsu_gmail/gmail_rules.json`
- `token_path`: absolute filesystem path, e.g. `/config/pasevsu_gmail/gmail_accounts/user1@gmail.com.json`
- `interval_minutes`: 5–1440 (default 15)
- `dry_run`: default `true`; disable only after validation

## OAuth details
The integration does not initiate browser login. Generate each token separately, authorize the appropriate Google account, and copy the token securely to HA. If a token was generated with only `gmail.readonly`, authorize again with `gmail.modify` before using write rules. Keep tokens private and do not include them in issue reports.

## First run
On first poll, the Gmail history cursor is initialized; **existing messages are not automatically scanned**. Later polling handles newly added message events. A lifecycle check also runs daily.

## Verification
1. Start with dry run enabled.
2. Send a test message matching one query to the configured Gmail account.
3. Wait for next polling interval and inspect the sensor attributes.
4. Confirm expected `matched`, `modified`, `dry_run`, `truncated` fields.
5. Only then enable writes, and test on a noncritical message.

## HACS
This repository includes `hacs.json` and the conventional `custom_components/<domain>` structure for custom repository installation. Listing in the official HACS catalog is **not** implied. Compatibility must be verified with the target HACS and HA versions.
