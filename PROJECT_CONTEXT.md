# PROJECT_CONTEXT — F5AuditDNS

## Project
Independent, read-only Python collector and offline cleanup planning utility for F5 BIG-IP DNS / GTM GSLB. Inspired by the F5Audit LTM approach. Possible future cross-project integration but **no dependency on F5Audit LTM**.

## Current Version
`0.3.0` — Independent one-DNS cleanup audit with automatic multi-LTM RAW discovery, LTM Location and NOT RUN reference commands. Not yet validated against a production BIG-IP DNS.

## Environment
Windows 10/11, Python 3.9+, PowerShell. Also cross-platform Python code.
Libraries: `requests`, `openpyxl`; optional `pytest` for tests. No Linux requirement.

## Design rules
- **Never modify BIG-IP configuration.** GET-only REST for data; hardcoded POST for token login.
- Preserve snapshot source and completeness metadata.
- Unknown/incomplete != unused/down/orphan.
- Generate vetted candidate Delete/Rollback text but NEVER execute; incomplete/unknown/dynamic references block candidate promotion.
- Keep `f5auditdns` namespace, CLI and Git repository independent from F5Audit LTM.
- CLI flags and source docs in English; user-facing README in Spanish.
- Use documentation/test IPs: 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24.

## Features
- validate: BIG-IP DNS REST read permissions.
- collect: GSLB Wide IPs, Pools, Servers, Data Centers and known subcollections; optional monitors, listeners, topology, regions, probers, rules.
- analyze: offline correlation from JSON and Excel/CSV reporting.
- snapshot collection_id; prevent silent overwrite/mixing.
- evidence-aware ambiguity handling and no formula injection.

## CLI
`f5auditdns validate -ho IP_OR_FQDN -u USER [--insecure]`
`f5auditdns collect -ho IP_OR_FQDN -u USER [-o DIR] [--insecure] [--scope core|all] [--verbose]`
`f5auditdns analyze --from-raw DIR [-o FILE.xlsx] [--ltm-raw SERVER=LTMDIR ...] [--ltm-raw-dir DIR ...] [--ltm-coverage-complete] [--max-snapshot-gap-hours 48]`
`f5auditdns analyze --from-raw DIR --format csv -o DIR`

## Behavior (v0.3.0)
- The auto-generated timestamp uses minute precision (`YYYYMMDD_HHMM`), with `_02`, `_03`, etc. for same-minute collisions.
- Omit `-o` on collect to auto-create `f5auditDNS_raw_HOSTNAME_YYYYMMDD_HHMM` under current working directory. Detect device hostname with read-only `/mgmt/tm/sys/global-settings` and fallback to `-ho` on error.
- End `collect` by printing the exact `analyze --from-raw` command for that folder (Excel in invocation directory).
- `--help` covers both management IP and FQDN, including `--insecure`.

## Files
- `f5auditdns/client.py`: adapted from MIT F5Audit LTM.
- `f5auditdns/collector.py`: API and snapshots.
- `f5auditdns/analyzer.py`: GSLB relationships.
- `f5auditdns/cleanup.py`: manual-review-first cleanup decisions, proposed commands.
- `f5auditdns/ltm_compare.py`: explicit GSLB mapping or automatic recursive LTM raw discovery.
- `tests/test_ltm_auto_scan.py`: multi-device and safety regression tests.
- `f5auditdns/report.py`: Excel/CSV.
- `f5auditdns/cli.py`: argparse.
- `examples/raw_simulado/`: synthetic sample.
- `tests/test_auditdns.py`: unit tests.

## Boundaries
Not in scope: DNSSEC, DNS Express, DNS cache and zones; stats history; DNS HA/sync validation; multi-DNS peer analysis; automatically deleting objects or fully reconstructing arbitrary configuration. No automatic execution.

## Roadmap
0.2.x TMOS compatibility + reliable status/monitor/partition handling.
0.3 automatic multi-LTM snapshot search and reference-only cleanup commands (implemented).
0.4 multiple F5 DNS / consolidated report.
0.5 DNS Services.
Later: cross-project DNS-to-LTM relationships.

## v0.3.0 Safety and community design
- Run `analyze` against a single DNS RAW folder; no DNS-to-DNS sync comparisons.
- `--ltm-raw-dir` may contain one to hundreds of valid original F5Audit LTM RAW directories.
- An address present in any LTM is positive evidence; an address not found across an incomplete set cannot prove removal.
- Only explicit GSLB Server mappings or an operator's `--ltm-coverage-complete` confirmation (with complete fresh data) permit negative candidate scoring.
- `Delete` and `Rollback` are always annotated `NOT RUN:` and are NEVER executed. Full rollback is NOT guaranteed from REST.
- LTM Location is the physical device hostname, NOT the logical GSLB Server or backend Node.
- Command identifiers are sanitized to prevent executable injection.
