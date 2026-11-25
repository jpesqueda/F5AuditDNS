# F5AuditDNS — GSLB Diagram Mode (v0.5.3)

## v0.5.4 — Focused, paginated topology viewer

After opening the generated `f5_dns_topology.html`, **Focused** is selected automatically. Its left **Service Explorer** displays one Wide IP at a time and offers a page of **25 services**. Search by FQDN, destination IP, GSLB Server, Virtual Server or Data Center, filter by partition or state and click the matching entry. The graph shows the selected dependency chain without removing any objects from `gtm_topology.json`.

- **Focused**: one service at a time, readable minimum zoom, paginated oversized child groups.
- **Overview**: all partitions and audit/unlinked categories, collapsed by default. Expand only visible paginated groups (25 children per group); switch to another overview page via arrow buttons.
- **Inspector / Show Dependencies**: see up to 20 Wide IPs that use the inspected object; select a Wide IP to focus its chain.
- **Search**: the explorer matches descendant properties as well as Wide IP names. Search selects the first matching service; selecting a different result changes the focus.
- **All data preserved**: the graph JSON and full Excel audit are unaffected. These are views of an offline snapshot, not live device health.

Generate the HTML from an existing RAW; no new `collect` is needed:

```powershell
f5auditdns diagram --from-raw ".\DNS_RAW" --ltm-raw-dir ".\LTM_RAW" -o ".\GSLB_Topology" --open
```

**READ ONLY / OFFLINE.** This mode extends the existing F5AuditDNS collector and analyzer. No new privileged collector, live REST session, backend service, or web server is required.

## Quick start

```powershell
# First collect as you normally would (only when you need a fresh snapshot).
f5auditdns collect -ho dns01.example.test -u auditor -o ".\DNS_RAW"

# Generate portable HTML and JSON using the saved snapshot.
f5auditdns diagram --from-raw ".\DNS_RAW" -o ".\GSLB_Topology"

# Exact convenience syntax requested for compatibility:
f5auditdns --diagram --raw ".\DNS_RAW"

# Include offline LTM location/health evidence if available.
f5auditdns diagram --from-raw ".\DNS_RAW" --ltm-raw-dir ".\LTM_RAW" -o ".\GSLB_Topology"

# Create fully fictional mock topology without connecting to any appliance.
f5auditdns diagram --mock -o ".\Demo"
```

The output directory contains:

- `gtm_topology.json` — canonical GSLB objects, relationship edges and a display-friendly service tree.
- `f5_dns_topology.html` — portable interactive dashboard. Open locally in a browser.

The HTML supports a horizontal collapsible tree with Bézier links, zoom/pan, partitions, search, status filters, audit/unlinked objects, an object inspector with full paths, monitored status, LTM evidence, sanitized snapshot REST JSON, and **NOT RUN** command references. The graph is duplicated only for display; all canonical objects remain distinct in the JSON.

## Full offline D3.js v7 mode

The exported HTML includes an offline SVG renderer that needs **no network** and no extra Python dependencies. When served over HTTP(S), it can use D3.js v7 from the official CDN if permitted. To create a **single HTML with the actual D3.js v7 library embedded** (no CDN request even on HTTP), download the official `d3.v7.min.js` from https://d3js.org/d3.v7.min.js using your organization's approved software download process, then run:

```powershell
f5auditdns diagram --from-raw ".\DNS_RAW" --d3-js ".\d3.v7.min.js" -o ".\GSLB_Topology"
```

The `--d3-js` file is a third-party runtime asset; download it from the official project, preserve its ISC license notice and validate the file according to your organization’s supply-chain process. F5AuditDNS does **not** download remote JavaScript while generating a topology.

## Additional flags

```text
--from-raw DIR, --raw DIR     Existing F5AuditDNS DNS snapshot
--ltm-raw-dir DIR             Recursively read F5Audit LTM snapshots (repeatable)
--mock                        Synthetic multi-partition sample; no RAW required
--device-label NAME           Override display name, keeping original snapshot metadata
-o, --out DIR                 Output folder (or explicit *.html / *.json filename)
--format both|html|json       Generate both by default
--d3-js FILE                  Embed locally supplied official D3 v7 bundle
--no-raw-inspector            Hide per-object REST JSON in exported HTML/JSON
--open                        Open locally generated HTML in the default browser
```

## Graph structure and evidence

Service view: `BIG-IP → Partition → Wide IP → Pool → Pool Member → GSLB Virtual Server → GSLB Server → Data Center`, with additional monitor links where their configuration has been collected. The audit branch contains all other inventory objects, including potentially orphaned pools, servers, Data Centers, monitors, rules, listeners, and Topology records.

All objects are indexed using `fullPath` and their record type where needed. References across `/Prod_GSLB`, `/DMZ_Externo`, and `/Common` are counted globally; an object defined in `/Common` cannot be misclassified as unused just because it is referenced by another partition.

- **REFERENCED** — an incoming reference is documented in the captured RAW.
- **NO VERIFIED REFERENCES IN SNAPSHOT** — no known incoming references were found and the audited static/dynamic datasets report complete; this is only a *snapshot-scoped result*, not decommission approval.
- **POSSIBLE INDIRECT REFERENCES** — dynamic rules, topology records or distributed-app references may refer to the object.
- **INVENTORY INCOMPLETE** — required datasets or subcollections were not fully available.
- **NO ACTIVE POOL MEMBERS FOUND — REVIEW** — a server has no resolved incoming Pool Member path; it may still be required for discovery, probes, standby or DR.

An orphan assessment **never authorizes deletion**. The inspector's suggested `tmsh` command is prefixed **NOT RUN**, is not executed, and must be validated and separately approved. A safe exact rollback requires `tmsh list ... all-properties` or a verified prechange backup.

## Runtime health and iQuery limitations

- Device state and statistics come from the stored `collect` snapshot, never a live view.
- `AVAILABLE`, `OFFLINE`, `UNAVAILABLE` and `DISABLED` retain their observed meaning when provided; `DEGRADED` is a derived visual aggregate, not a native F5 status code.
- A link turns amber for partial failure and red for a confirmed failed service branch; unknown status stays unknown.
- Missing `iQuery`/`big3d` connectivity must **not** be interpreted as an outage. Explicitly reported iQuery fields are displayed separately; negative health without clear iQuery evidence does not prove iQuery loss.
- The collector sanitizes credentials and opaque iRule definitions; the HTML inspector only embeds sanitized properties, not the complete original sensitive configuration.
- In some TMOS versions REST endpoints or stats fields differ. Check `Collection Health` in the original Excel and validate the diagram against TMUI before relying on an operational conclusion.
- For extra caution before sharing, use `--no-raw-inspector`. Even without raw properties, graph names and IPs can reveal infrastructure information: keep exports inside approved storage.

## Development / testing

```powershell
py -m pip install -e ".[dev]"
py -m pytest -q
f5auditdns diagram --mock -o .\Demo
```

No changes are made to the original `collect`, `analyze`, `validate` behavior or workbook layout.
