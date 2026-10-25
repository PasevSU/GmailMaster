# Troubleshooting

**Integration not found:** verify directory is exactly `/config/custom_components/pasevsu_gmail_rules/`, contains `manifest.json` and `__init__.py`, then restart HA.

**Missing `google_auth_oauthlib`:** this package does not need that library at runtime; it needs `google-auth` and `google-api-python-client`. The external OAuth token generation script may need `google-auth-oauthlib` in the Python interpreter used to run it.

**Token rejected:** token must be valid, refreshable, and authorized for `https://www.googleapis.com/auth/gmail.modify`.

**Sensor shows zero:** it means no new message IDs were detected during the last poll, not that the mailbox is empty. First poll initializes the cursor.

**No frontend / no sidebar panel:** intentional. This is a backend-only release with no JS.

**Rule not matching:** Gmail search syntax is used verbatim; test the same query in Gmail search. Matches beyond 20 pages may be missed.

**History cursor expired:** the sensor's `last_error` notes resynchronization; missed events are not backfilled.

**Multiple accounts:** create a separate HA integration entry per token file. One entry cannot monitor two accounts.

**`dry_run` enabled:** no label/read/trash modifications will be made.

**Lifecycle does not delete immediately:** it uses first *observed* read time and runs approximately every 24 hours.
