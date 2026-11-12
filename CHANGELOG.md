# Changelog

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
