# F5AuditDNS — Project Context (v0.5.4)

- Maintained from the original GitHub v0.4.0 source distribution; no rewrite of the REST client, collector or conservative LTM matcher.
- Read-only: collection GET, token authentication POST only, offline analysis, non-executable tmsh references.
- Preserve all original 13 report sheets and columns, plus Reference Map, Object Inventory, Pool Impact, Cleanup Procedure and optional FreedIP.
- `freedip.py` imports TXT/CSV/XLSX evidence and does not approve decommission.
- `reference_engine.py` extends Audit after v0.4.0 health/LTM/cleanup evaluation.
- Simulations are flagged with PENDING approvals and cautious empty-pool dependencies.
- Accurate rollback requires externally saved original configuration; sanitized REST data cannot guarantee exact restoration.
- No production data, credentials or trusted publisher tokens in distributed fixtures.
- Collect against one BIG-IP DNS per run; no DNS-peer or Sync Group comparison.
- Current development version 0.5.4; v0.5.3 is published on PyPI. v0.5.4 release requires passing CI.

See `README.md` and `docs/REFERENCE_ENGINE.md` for CLI and safety guidance.

- `search.py` supports object/VS/endpoint lookup and cell-level Excel highlighting from existing RAW; `--file` highlights all lookup terms and uses valid IP/endpoint entries as unapproved FreedIP simulation evidence; `--search-only` disables automatic evidence.
- Bilingual README for PyPI, English/Spanish user guides, engineering and publication docs, and bilingual CLI help.
- Search Results is optional and adds no cleanup approval or status changes.

- `diagram.py`, `diagram_html.py`, and `diagram_mock.py` provide the offline topology visualization without new collector REST calls. Snapshot health and dynamic reference evidence remain conservative.

- v0.5.4 focused topology uses only offline HTML/JS; pages 25 services and 25 child objects, preserves all canonical graph JSON and collected RAW snapshots.
