# F5AuditDNS v0.6.0 validation (synthetic data)

- 164 pytest tests passed locally on Python 3.13 (145 prior + 19 rollback/change-plan regression tests).
- The new engine imported original TMSH blocks with balanced-brace parsing, generated rollback references for pools, members, servers and VSs, and preserved original Excel report sheets.
- Generated an example TXT with approval tickets, prechecks, proposed change, postchecks, restore and blocking reasons.
- Sensitive and missing backups are not exported as full recreate commands; SHA256 manifests detect modified backups.
- TMSH SSH capture tests use mocks only. Actual BIG-IP SSH, TMOS 17.5.1.11 syntax and operational restore validation are **not** covered by local automated tests.
- **No configuration changes, deletion or publication to PyPI occurred during testing.**
