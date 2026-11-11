# PROJECT_CONTEXT — F5AuditDNS

## Project
Independent, read-only Python audit utility for F5 BIG-IP DNS / GTM GSLB. Inspired by the F5Audit LTM approach. Possible future cross-project integration but **no dependency on F5Audit LTM**.

## Current Version
`0.1.2` — CLI improvements on the first functional offline-tested prototype. Not yet validated against a production BIG-IP DNS.

## Environment
Windows 10/11, Python 3.9+, PowerShell. Also cross-platform Python code.
Libraries: `requests`, `openpyxl`; optional `pytest` for tests. No Linux requirement.

## Design rules
- **Never modify BIG-IP configuration.** GET-only REST for data; hardcoded POST for token login.
- Preserve snapshot source and completeness metadata.
- Unknown/incomplete != unused/down/orphan.
- Avoid automatic delete recommendations; explicit manual review.
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
`f5auditdns analyze --from-raw DIR -o FILE.xlsx`
`f5auditdns analyze --from-raw DIR --format csv -o DIR`

## Behavior (v0.1.2)
- The auto-generated timestamp uses minute precision (`YYYYMMDD_HHMM`), with `_02`, `_03`, etc. for same-minute collisions.
- Omit `-o` on collect to auto-create `f5auditDNS_raw_HOSTNAME_YYYYMMDD_HHMM` under current working directory. Detect device hostname with read-only `/mgmt/tm/sys/global-settings` and fallback to `-ho` on error.
- End `collect` by printing the exact `analyze --from-raw` command for that folder (Excel in invocation directory).
- `--help` covers both management IP and FQDN, including `--insecure`.

## Files
- `f5auditdns/client.py`: adapted from MIT F5Audit LTM.
- `f5auditdns/collector.py`: API and snapshots.
- `f5auditdns/analyzer.py`: GSLB relationships.
- `f5auditdns/report.py`: Excel/CSV.
- `f5auditdns/cli.py`: argparse.
- `examples/raw_simulado/`: synthetic sample.
- `tests/test_auditdns.py`: unit tests.

## Boundaries
Not in scope: DNSSEC, DNS Express, DNS cache and zones; stats history; HA/sync validation; multi-host and snapshot comparison; deleting objects; rollback generation.

## Roadmap
0.2 TMOS compatibility + reliable status/monitor/partition handling.
0.3 snapshot comparison.
0.4 multiple F5 DNS / consolidated report.
0.5 DNS Services.
Later: cross-project DNS-to-LTM relationships.
