# Reference Engine v0.5.2 — Engineering Notes

## Sources of truth

The immutable JSON snapshot stores configuration under `gtm_wideip_*`, `gtm_pool_*`, `pool_members::<type>::<pool>`, `gtm_server`, `server_virtuals::<server>`, and ancillary keys. Existing operational `/stats` datasets are preserved. The reporting engine does **not** change the collector's endpoint scope in this release.

The v0.4.0 `analyze()` and `enrich_cleanup()` results remain the primary source for current health, LTM matches and conservative verdicts. `build_reference_report()` runs *after* that pipeline and enriches records without dropping any original fields.

Static Wide IP references are taken from `wideip_pools::*` and `wideip_pools_cname::*`, not from the report's combined `Pools` string. `lastResortPool` is emitted independently with type `LAST RESORT`. A Wide IP may have both types pointing at the same pool. Missing subcollections are unknown and not treated as empty.

For each pool, member refs come from `pool_members::<record>::<fullPath>`. A complete collection is verified against `endpoint_results` before computing counts. If a member dataset is absent or rejected, the simulation displays `INVENTORY INCOMPLETE - NO SIMULATION`; it must not show `0 remaining`.

For each GSLB Virtual Server the graph includes *all* matching Pool Members and parent GSLB Server. `virtualServerDiscovery`, `dependsOn`, `monitor`, and unknown dynamic references are explicitly noted. A referenced VS gets a `KEEP / REMOVE N POOL MEMBER REFERENCE(S) FIRST` advisory. A dynamic discovery mode adds a separate warning.

## FreedIP evidence

TXT/CSV/XLSX files are parsed with strict, documented IP tokens, deduplicated by IP/port/route domain. A matching bare IP only produces `IP ONLY - REVIEW`; full endpoint records are still review-only. Simulated marked-member counts are never approval status and **never modify** `Verdict` or the original `Cleanup Candidates` classification.

## Rollback

Config properties collected in REST are sanitized. They are not equivalent to exact `tmsh list ... all-properties` output because omitted/inherited defaults, provisioning/partitions, parent references, ordering and secrets may not be recoverable. Reference restores are prefixed `NOT RUN:` and labeled `ROLLBACK INCOMPLETE`. No automatic recreation is treated as exact. Production operations require approved pre-change backup and manually validated inverse changes.

## Data confidentiality

No snapshot, report, source reference workbook or production FQDN is included in this project release. Fixtures use documentation-only IP ranges and fictitious names. Never publish real RAW, FreedIP, UCS, secrets or screenshots.

## Release gate

- Inherited test suite v0.4.0 passes.
- New tests check direct vs Last Resort, multi-pool VS, incomplete inventory, simulation, XLSX/CSV/TXT inputs, route domains, port 0, rollback warning, and non-executable commands.
- Required Excel sheet names and inherited columns are verified.
- Validate representative data against BIG-IP TMOS before PyPI publication.

## Offline search highlighting v0.5.2

`search.py` loads TXT/CSV/XLSX search values, recognizes full IPs/endpoints and
object/VS names, and returns exact evidence-column matches only. A --file IP query may provide explicitly unapproved FreedIP evidence for
Pool Impact simulation, while name-only searches are highlighting only.
No query changes an existing cleanup verdict or approvals.
The report exporter colors matching identity/destination cells yellow, and
creates a searchable `Search Results` worksheet (plus CSV when relevant).
A fully qualified server:VS criterion is scoped to that server. No cell
with commands, credentials or free-form notes is searched or rewritten.
