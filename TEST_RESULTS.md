# F5AuditDNS v0.5.4 — Validation summary

- **145 pytest tests passed locally** on Linux/Python 3.13, including all 136 v0.5.3 regression tests and nine v0.5.4 focused UI checks.
- **Headless Chromium visual smoke test passed locally** with a fully synthetic 295-Wide-IP graph: 25-service pagination (12 pages), selecting service 31, switching Focused/Overview, bounded expansion, page navigation, exact search focusing service 173, empty-result behavior and shared-pool dependency navigation for 295 services. No JavaScript page errors.
- Node.js `--check` passed for the rendered viewer scripts. Wheel (`.whl`) and source distribution (`.tar.gz`) built locally.
- Windows 3.9/3.12 and Ubuntu 3.9/3.12 GitHub Actions: **pending at preparation time**; not presumed to pass.
- No real TMOS environment validated in this change. No API writes or configuration operations introduced.
- Test inputs include only synthetic hostnames and documentation IPs; real RAW snapshots were not committed.
