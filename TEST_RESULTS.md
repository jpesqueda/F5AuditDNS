# F5AuditDNS v0.5.2 — Local Validation Results (English)

- **106 automated tests passed** against fully synthetic DNS and LTM RAW fixtures.
- All original v0.4.0, reference-engine v0.5.0, search v0.5.1 and new unified TXT simulation tests passed.
- The single `--file` workflow creates both yellow highlights and **unapproved** FreedIP / Pool Impact simulations for valid IP/endpoint entries.
- `--search-only` preserves visual-search-only mode, while `--freed-ip-file` remains supported as optional extra evidence.
- GSLB VS / object names are not treated as IP decommission evidence. Endpoint matching requires compatible port and route domain.
- All original 13 worksheets, four reference worksheets, and optional FreedIP and Search Results are preserved (19 sheets with both options).
- Original Verdict, Cleanup Candidates and Approval Status=PENDING remain independent of the new simulation.
- Wheel and sdist built locally through setuptools PEP 517 `build_meta`, and a synthetic end-to-end Excel report generated.
- No live TMOS system was used. All tmsh change commands remain `NOT RUN`. No GitHub or PyPI release was published.

## Run tests

```powershell
py -m pip install -e ".[dev]"
py -m pytest -q
```

## Next release gate

Validate representative sanitized BIG-IP DNS and LTM snapshots on the target
TMOS version. Run GitHub Actions Windows/Linux CI and `twine check` on the
release artifacts before any public release.
