# F5AuditDNS — Read-only BIG-IP DNS / GSLB Cleanup Auditor

**Version:** `0.5.2` (development package; not yet published to PyPI)  
**Requirements:** Python 3.9+, Windows / Linux / macOS  
**Project:** https://github.com/jpesqueda/F5AuditDNS

F5AuditDNS reads BIG-IP DNS/GSLB configuration through iControl REST, saves an offline JSON snapshot, reconstructs object references, compares GSLB virtual-server destinations against any number of existing F5Audit LTM snapshots, and generates an evidence-based Excel or CSV cleanup report.

**READ ONLY:** No configuration commands are sent to BIG-IP. The only POST made during collection is to the token-login endpoint. All `tmsh` change examples in reports are prefixed `NOT RUN:`. Neither a decommissioned-IP entry nor a `Verdict` authorizes deletion. Use a dedicated read-only account and an approved change process.

## Architecture and boundaries

```text
BIG-IP DNS (one appliance per collect)
  Wide IP ──DIRECT / LAST RESORT──> GSLB Pool
                                      │
                                      └─> Pool Member ──> GSLB Server ──> GSLB Virtual Server
                                                                          │
                                                                          └─ Destination IP + Port + Route Domain
                                                                                     │
                                                             Optional F5Audit LTM RAW directory (1..N)
                                                             Matching LTM Virtual Servers, not backend nodes
```

A BIG-IP DNS GSLB Virtual Server belongs to a `gtm server`; it is not an `ltm virtual` object. A `gtm pool` member references a GSLB virtual, not an LTM backend node. The same virtual can appear in multiple pools. Object inventory, configuration availability, LTM presence and actual live traffic are distinct concepts.

## Installation

```powershell
py -m pip install .
py -m f5auditdns --version
py -m f5auditdns --help
```

For development:

```powershell
py -m pip install -e ".[dev]"
py -m pytest -q
```

The package keeps the original `requests`, `openpyxl` and `pytest` (dev-only) dependencies.

## Offline object search and yellow highlighting (v0.5.2)

Search the **existing RAW** using any of these optional `analyze` flags. No new
collection or BIG-IP connection is necessary:

```powershell
# A single GSLB Virtual Server (short name):
f5auditdns analyze --from-raw ".\dns_raw" --virtual-server "vs_app" -o ".\VS_Search.xlsx"

# Specific GSLB Server + Virtual Server (avoid collisions across servers):
f5auditdns analyze --from-raw ".\dns_raw" --virtual-server "/Common/GDL-F5:/Common/vs_app" -o ".\Scoped_VS.xlsx"

# One generic object or IP:
f5auditdns analyze --from-raw ".\dns_raw" --object "/Common/pool_app" -o ".\Pool_Search.xlsx"

# A spreadsheet/TXT/CSV list (multiple columns accepted):
f5auditdns analyze `
  --from-raw ".\dns_raw" `
  --ltm-raw-dir ".\ltm_raws" `
  --file ".\freed_ips.txt" `
  -o ".\DNS_Highlighted.xlsx"
```

`--vs` is an alias of `--virtual-server`, and `--search` is an alias of
`--object`. `--file` is repeatable. Search is **not a filtering option**: the
complete original report is retained. Matching identity/destination cells are
highlighted in yellow, and a new **Search Results** sheet lists found and not
found terms, sheets, row numbers, and matching columns. A bare IP is matched as
an address, not a substring; an IP:port:route-domain term must match the
specified endpoint fields. Search findings do **not** change `Verdict`,
`Approval Status`, or simulations. The original sheets remain in the same order.

**Updated single-file mode:** `--file FILE` highlights objects in yellow and feeds valid IP/endpoint values into the **unapproved** `FreedIP` and `Pool Impact` simulation. Object names and virtual-server names are highlighting targets only. Use `--file FILE --search-only` to avoid simulation. `--freed-ip-file` remains available as optional additional evidence. This never changes `Verdict` or `Approval Status=PENDING`.

## CLI

### Validate read access

```powershell
f5auditdns validate -ho 192.0.2.20 -u auditor
f5auditdns validate -ho dns01.example.test -u auditor --insecure
```

Credentials are prompted securely unless `-p` or `F5AUDITDNS_PASSWORD` is provided. TLS verification is enabled by default; reserve `--insecure` for authorized environments.

### Collect a fresh DNS snapshot (live REST reads)

```powershell
f5auditdns collect -ho dns01.example.test -u auditor
f5auditdns collect -ho 192.0.2.20 -u auditor --insecure -o .\dns_raw_new
f5auditdns collect -ho dns01.example.test -u auditor --scope core -o .\dns_config_only --no-stats
```

Without `-o`, `collect` creates a unique `f5auditDNS_raw_<hostname>_<YYYYMMDD_HHMM>` folder. Operational `/stats` requests are enabled unless `--no-stats` is selected. If an endpoint fails, the failure is recorded, not converted to a zero value. The CLI prints the exact next `analyze` command.

### Analyze previous snapshots offline

```powershell
f5auditdns analyze --from-raw .\dns_raw -o .\DNS_Review.xlsx

f5auditdns analyze `
  --from-raw ".\dns_raw" `
  --ltm-raw-dir ".\all_ltm_raw" `
  -o ".\DNS_LTM_Correlation.xlsx"

f5auditdns analyze `
  --from-raw ".\dns_raw" `
  --ltm-raw-dir ".\all_ltm_raw" `
  --file ".\decommissioned_ips.txt" `
  -o ".\DNS_Cleanup_Simulation.xlsx"
```

You can repeat `--ltm-raw-dir DIR` for multiple root directories, recursively. Each valid F5Audit LTM inventory is scanned. When one GSLB endpoint appears on both members of an LTM HA pair, both locations are shown. Existing `--ltm-raw GSLB_SERVER=PATH`, `--max-snapshot-gap-hours HOURS` and CSV export remain supported.

`--ltm-coverage-complete` is an *operator attestation* that every relevant LTM is represented by a complete and sufficiently recent snapshot. It does not discover or verify missing appliances and it does **not** approve any change:

```powershell
f5auditdns analyze --from-raw .\dns_raw --ltm-raw-dir .\all_ltm_raw `
  --ltm-coverage-complete --freed-ip-file .\decommissioned_ips.txt `
  -o .\DNS_Cleanup_Review.xlsx
```

### FreedIP file (optional)

Accepts `.txt`, `.csv` or `.xlsx`; several Excel/CSV columns are supported. Example contents:

```text
192.0.2.200
198.51.100.100:443
192.0.2.42%3:8443
[2001:db8::44%5]:443
```

Strict IP parsing ignores headers and arbitrary text. Sources are recorded as file/row/column, with deduplicated entries. A plain IP matches by IP only and is always **review evidence, not proof of a decommissioned endpoint**. Even IP:port:route-domain evidence is never sufficient by itself to authorize deletion. `FreedIP` entries only drive a simulated pool-member removal count; every approval begins `PENDING`.

## Workbook structure

Thirteen original sheets are retained in their original order. This release adds four new sheets; `FreedIP` appears only when a valid list is supplied.

| Sheet | Purpose |
| --- | --- |
| Summary | Existing inventory, collection health, candidate and simulation totals |
| Wide IP Findings | Existing Wide IP health and rules + direct/last-resort references, prechecks, delete and rollback references |
| GSLB Pool Findings | Existing health/counters + member inventory, simulated impact and dependency prechecks |
| Pool Members | Each member in each pool, endpoint and LTM evidence, FreedIP match, approval, full pool references and `NOT RUN` examples |
| GSLB Servers | Server/DC inventories, virtual inventory, pool usage, parent cleanup references |
| GSLB Virtual Servers | GSLB server-scoped VS, multiple pool refs, monitor/discovery/dependency caution, LTM evidence and change references |
| Data Centers | DC/server relationships, topology/prober prechecks, non-executable change references |
| DNS Chains | Wide IP → Pool → Member → GSLB Server → VS with pre/postchecks |
| Cleanup Candidates | Original conservative candidate list, still requiring review |
| LTM Inventories | Every F5Audit LTM inventory used, timestamps, role and coverage warnings |
| Manual Review | Unknown/missing/dynamic references and collection gaps |
| Auxiliary Inventory | Existing monitors, rules, listeners, topology, regions, probers and safe reference commands |
| Collection Health | Original per-endpoint REST success/permission/failure data |
| **Reference Map** | Both dependency directions, explicit direct/last-resort relationship types, unlinked objects and confidence |
| **Object Inventory** | All collected configuration/operational dataset entries, including objects outside DNS chains |
| **Pool Impact** | Current count, marked (simulated) count, remaining count, Wide IP dependents, prechecks and approval |
| **Cleanup Procedure** | Ordered, read-only plan with precheck, change-reference, postcheck and rollback columns |
| **FreedIP** *(optional)* | Strictly parsed source entries and review-only status |

All original report columns stay in place; new attributes are appended to corresponding sheets. Any `Health = NOT OBSERVED` indicates unavailable data, **not** downtime. Operational counters are cumulative and cannot prove recent inactivity. Offline-but-present LTM virtual servers remain for manual review.

## Cleanup safety rules

1. Configuration presence, operational health, LTM existence, route domain and direct/dynamic DNS use are independently assessed.
2. `PRESENT` on one or more LTM snapshots means the VIP still exists in the scanned inventory; `NOT_FOUND_IN_SCANNED_LTMS` alone cannot prove removal.
3. A different VS name but identical IP+port+route-domain is positive existence evidence; an IP-only match or different port is not equivalent.
4. A pool with no **direct** Wide IP references may still be used as **Last Resort**, by iRules, topology or dynamically. A pool simulated empty remains `REVIEW EMPTY POOL`, never auto-delete.
5. A GSLB Virtual Server referenced by multiple pools cannot be removed until all approved references have been handled. Auto-discovered VS objects might reappear.
6. All proposed `tmsh` commands are plain report text prefixed `NOT RUN:`. Shell grep checks are for a human operator in bash, not for the tmsh interactive shell.
7. `ROLLBACK INCOMPLETE` is the only safe claim when the original full `tmsh list ... all-properties` / approved configuration backup is missing. The tool collects sanitized REST properties but cannot reconstruct every inherited, secret, ordering or TMOS-specific property. The presence of a partial `create` command never changes that status.
8. No audit results or backup files containing production inventory, secrets or tokens belong in GitHub commits, issues or PyPI releases.

## Example report from fabricated fixtures

```powershell
f5auditdns analyze --from-raw .\examples\raw_cleanup_simulado `
  --ltm-raw-dir .\examples\ltm_raws_multi_simulado `
  --freed-ip-file .\examples\decommissioned_ips_SIMULATED.txt `
  -o .\DNS_Cleanup_SIMULATED.xlsx
```

No physical BIG-IP is required for `analyze`. The supplied fixtures exclusively use documentation-only IP blocks and `.example.test` names. Do not confuse examples with production-ready change scripts.

## Development and packaging

```powershell
py -m pytest -q
py -m pip install build twine
py -m build
py -m twine check dist/*
```

GitHub Actions workflows for CI, TestPyPI and PyPI remain in `.github/workflows`. A PyPI release must be tagged only after all relevant tests pass and a reviewer verifies real-world TMOS compatibility. Version `0.5.2` has not been published by this project package.

## Limitations

- No live execution, deletion, approval, DNS query-rate history or guaranteed exact rollback.
- Without old snapshot `/stats` data, states stay `NOT OBSERVED` or `UNKNOWN` as appropriate. A fresh `collect` is needed for the new operational fields, **not** for the new reference report.
- iRules, distributed applications, topology and discovery can contain dependencies not reconstructible from sanitized REST JSON alone; such cases remain for human review.
- One BIG-IP DNS is collected/analyzed per run; DNS peers and synchronization are deliberately out of scope.
- Tested with fabricated fixtures and inherited v0.4.0 regression suites; TMOS-version-specific command behavior must be validated before maintenance windows.

## Sources

F5 BIG-IP iControl REST endpoint reference: https://clouddocs.f5.com/api/icontrol-rest/APIRef_tm_gtm.html

F5 BIG-IP TMOS concepts and command reference: https://clouddocs.f5.com/cli/tmsh-reference/latest/

License: MIT. `NOTICE.md` retains attribution for the inherited REST client.
