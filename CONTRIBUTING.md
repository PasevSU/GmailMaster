# Contributing

1. Do not submit OAuth tokens, email bodies, exported mail, forensic evidence, or private configuration.
2. Create a feature branch; add tests for any change to rule processing, history cursor behavior or lifecycle actions.
3. Run `python -m compileall -q custom_components tools/account_helper` and `python scripts/repo_guard.py`.
4. Keep Home Assistant runtime code under `custom_components/pasevsu_gmail_rules/`. Keep standalone account/forensic utilities under `tools/account_helper/`.
5. Changes to destructive Gmail actions require explicit dry-run tests and documentation.
6. Never claim compatibility or release readiness without a live Home Assistant integration test.
