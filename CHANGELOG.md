# Changelog

## [0.5.4] — 2026-11-24 (development; awaiting CI and PyPI release)

- Make **Focused View** the default for large GSLB maps: one Wide IP and its dependency chain at a readable zoom, with a 25-entry paginated Service Explorer.
- Add FQDN/IP/VS/Server/DC search that automatically focuses matching services; retain partition and health filters.
- Keep full **Overview** for all partitions and unlinked/audit categories, but collapse and page oversized branches; bound Expand to visible groups.
- Add inspector **Show Dependencies** navigation for resources shared by multiple Wide IPs; no graph data or CSV/Excel content is removed.
- Add 295-Wide-IP synthetic stress regression, Node.js syntax test, and local Chromium browser smoke tests.
- No BIG-IP changes and no new collector endpoints. All tmsh references remain NOT RUN.


## [0.5.3] — 2026-11-24 (published to PyPI)

- Add offline `diagram --from-raw DIR` mode and `--diagram --raw DIR` alias without changing collector behavior.
- Add global fullPath-indexed topology graph across partitions, preserving Direct and Last Resort Wide IP references, shared Pool Members, GSLB VS, Servers, Data Centers, and health-monitor dependencies.
- Add conservative orphan/review classification and snapshot-only health propagation; do not infer iQuery outages from missing telemetry.
- Export portable `gtm_topology.json` and an interactive horizontal HTML tree with Bézier links, zoom/pan, search, partition/status filters, object inspector, sanitized REST JSON and NOT RUN references.
- Add synthetic `--mock` with three partitions, optional LTM inventory evidence, `--format`, `--open`, `--no-raw-inspector` and `--d3-js` for embedding local D3 v7.
- Preserve all original analysis/Excel functions; add bilingual diagram documentation and regression tests.

## [0.5.2] — 2026-11-20 (development; not published)

- A single repeatable `analyze --file FILE` (TXT/CSV/XLSX) now highlights yellow and uses valid IP/endpoint entries for unapproved FreedIP/Pool Impact simulation.
- Object and GSLB VS names remain search-only; `--search-only` restores the previous highlight-only behavior.
- Preserve `--freed-ip-file` for explicit additional evidence and deduplicate repeated IP/port/route-domain combinations.
- Preserve all Verdict, Approval Status=PENDING, sheets, stats and evidence. Commands remain NOT RUN, with no device changes.
- Fix per-member Cleanup Readiness evidence source selection and add synthetic tests + bilingual documentation.


## [0.5.1] — 2026-11-20 (development; not published)

- Add offline `analyze --virtual-server NAME` (alias `--vs`) and `--object NAME` (alias `--search`) queries with exact object-name and address-aware IP/port/route-domain matching.
- Add repeatable `analyze --file FILE` for TXT, CSV and XLSX multi-column search; do not confuse it with the existing `--freed-ip-file` decommission evidence option.
- Highlight matching identity/destination cells in **yellow** without filtering existing report sheets or altering `Verdict`, `Approval Status`, simulation or cleanup decisions.
- Add optional **Search Results** worksheet/CSV with exact sheet/row/column, input source and FOUND / NOT FOUND evidence.
- Keep the 13 original worksheets, four v0.5.0 extension sheets and optional FreedIP intact.
- Add bilingual English/Spanish README suitable for PyPI long description, two full usage guides, engineering reference and publishing instructions in both languages, and bilingual CLI `--help`.
- Add English and Spanish metadata classifiers and project links, plus offline synthetic search regression tests.
- No live BIG-IP configuration operations and no PyPI publication.

## [0.5.0] — 2026-11-20 (development; not published)

- Preserve all 13 original workbook sheets, columns and v0.4.0 operational status/LTM matching.
- Add **Reference Map**, **Object Inventory**, **Pool Impact**, **Cleanup Procedure**, plus optional **FreedIP**.
- Cross-reference direct Wide IP and Last Resort relationships independently, accounting for missing and dynamic references.
- Add multi-pool GSLB Virtual Server references, parent/server dependencies, per-object read-only prechecks and postchecks.
- Simulate marked IP removal without changing Verdict or recording approval; every Approval Status starts PENDING.
- Support `analyze --freed-ip-file FILE` with strict TXT/CSV/XLSX multi-column parsing, IP, port and route-domain matching.
- Make every modification/rollback example `NOT RUN`; explicitly mark rollback as **ROLLBACK INCOMPLETE** when exact pre-change tmsh config is unavailable.
- Retain CLI validate, collect, analyze, `--no-stats`, LTM automatic and explicit mapping, `--ltm-coverage-complete` and CSV/Excel output.
- Reuse older RAW DNS snapshots for new graph analysis. No new live configuration endpoints are required.
- Maintain an offline synthetic test suite; never commit production snapshots or secrets.

## [0.4.0] — 2026-11-16

- Capture read-only GSLB operational statistics via `/stats` with explicit collection-health diagnostics.
- Split destination address into IP, port, route domain and service.
- Improve LTM correlation by IP/port/route-domain and retain virtual-server name mismatch evidence.
- Distinguish `UNKNOWN` from `NOT OBSERVED` and preserve LTM health and connection counters.


## [0.3.0] — 2026-11-12

- Analyze exactly one BIG-IP DNS at a time; DNS peer and Sync Group audits are out of scope.
- Add repeated `--ltm-raw-dir DIR`, recursively discovering any number of original F5Audit LTM RAW snapshots.
- Display `LTM Location`, evidence, scanned count and sources in member/virtual/server reports, without assuming an HA topology.
- Require explicit `--ltm-coverage-complete` before promoting an absence across auto-discovered inventories to a cleanup candidate.
- Preserve `--ltm-raw GSLB_SERVER=DIR` for explicit and evidence-rich comparisons.
- Add `NOT RUN:` text references for Delete and Rollback on in-use and noncandidate GSLB Pools, Pool Members, Virtual Servers, and Servers. No actions run.
- Keep Cleanup Candidates restricted to eligible, reviewed candidates; add `LTM Inventories` worksheet (13 sheets).
- Deduplicate repeated LTM host snapshots by most recent collection; reject corrupt/partial evidence for removal decisions.
- Validate with automated unit/integration tests using 1 and 10 simulated LTM snapshots.


## [0.2.0] — 2026-11-11

- Add Verdict / Notes / Delete / Rollback to GSLB inventories, and a dedicated Cleanup Candidates sheet (12 total).
- Compare GSLB Members and Virtual Servers against one or more **explicitly mapped** original F5Audit LTM raw snapshots (`--ltm-raw GSLB_SERVER=PATH`).
- Identify absent LTM Virtual Servers only when destination/name are absent in a complete LTM inventory and DNS/LTM collection timestamps are close (48h default).
- Classify unreferenced GSLB Pools as ORPHAN only when all static/dynamic relationship checks are complete.
- Suggest tmsh member removal/re-add and GSLB Virtual Server removal/re-add; guard application-owned objects and discovery-managed Virtual Servers. Pool rollback requires prior full config backup.
- Preserve strictly read-only collection and offline analysis: commands are never executed.
- Include fictional DNS + LTM snapshots for end-to-end cleanup demonstration and 32 automated tests.

## [0.1.2] — 2026-11-11

- Shorten automatic snapshot folder timestamps to `YYYYMMDD_HHMM` (minutes instead of seconds).
- Keep full device hostname, preserve custom `-o` behavior and the copy-paste `analyze` command.
- Avoid overwriting two snapshots started within the same minute by adding `_02`, `_03`, etc.
- Update README, `--help` and regression tests.

## [0.1.1] — 2026-11-11

- Optional `-o/--save-raw` for `collect`; automatic timestamped folder in current directory.
- Discover device hostname with a GET request to `/mgmt/tm/sys/global-settings` and safely fall back to the `-ho` input if unavailable.
- Avoid collisions and never silently overwrite previous snapshots.
- Always display the next `f5auditdns analyze --from-raw ... -o DNS_Audit.xlsx` command after saving the snapshot.
- Add IPv4 and management-FQDN examples with `--insecure` to top-level and subcommand help, plus README.
- Add offline regression tests for new CLI behavior.

## [0.1.0] — 2026-11-11

Initial separate F5AuditDNS prototype based on the philosophy (not the full LTM logic) of F5Audit 0.7.0.

- Read-only iControl REST connection and token authentication (original F5Audit MIT client adapted).
- `validate`, `collect`, `analyze` commands.
- GSLB object collection: Wide IPs, Pools, Pool Members, Servers, Data Centers, GSLB Virtual Servers.
- Support A, AAAA, CNAME, MX, NAPTR, SRV record types.
- Optional inventory of GTM monitors, listeners, iRules, topology, regions, prober pools.
- Offline JSON snapshots with collection identifiers and completeness tracking.
- Conservative correlation and manual review; no delete scripts.
- Excel report with 11 sheets and CSV exports.
- Simulated dataset and tests.

**Validation status:** local tests and simulated reports only. Not tested against live TMOS.

## 0.6.0 — TMSH-backed rollback and controlled cleanup procedures

- Add `backup-tmsh` read-only SSH capture using trusted OpenSSH host keys. Original configurations are confidential and stay local; BIG-IP is not modified.
- Add `analyze --tmsh-backup-dir` to enrich every original audit sheet with captured object definitions, SHA256 source evidence, and `NOT RUN` rollback references for GSLB Wide IPs, pools, members, GSLB Servers, virtual servers and Data Centers.
- Missing, ambiguous, sensitive or unavailable definitions stay `ROLLBACK INCOMPLETE`/manual review. Captured `tmsh list` blocks are **never** claimed as already tested restoration commands.
- Add `--approval-file` and `--procedure-txt` to export a **non-executable** TXT procedure for selected pools and members: ticket, prechecks, dependencies, proposed change, postchecks, rollback and restore verification.
- Block proposed pool deletion when any members remain unapproved or a Wide IP/Last Resort/dynamic dependency is present. Approval alone never bypasses safety gates.
- Preserve existing `collect`, `analyze`, `diagram`, all worksheets, FreedIP and LTM evidence. No production data in tests or examples.
