"""Conservative GSLB cleanup evidence and tmsh proposal generation.

No commands are executed. Commands are for change-request review ONLY.
Never infer that a DNS resource is retired from a DOWN health check alone.
Full restoration of arbitrary BIG-IP configuration requires a pre-change
backup: an API snapshot does not preserve every explicit/inherited property.
"""
from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any, TYPE_CHECKING

from .collector import RECORD_TYPES, Snapshot, object_id
from .ltm_compare import LtmInventory, LtmScan

if TYPE_CHECKING:
    from .analyzer import Audit

# Restrict object identifiers to simple safe tmsh tokens; no command separators,
# quotes, whitespace, shell expansion or control characters permitted.
_SAFE = re.compile(r"^/[A-Za-z0-9_.%~-]+(?:/[A-Za-z0-9_.%~:-]+)*$")
_SAFE_MEMBER = re.compile(r"^/?[A-Za-z0-9_.%~/-]+:/?[A-Za-z0-9_.%~/-]+$")
SUPPORTED_RRS = set(RECORD_TYPES)


def safe_object(value: str) -> bool:
    return bool(_SAFE.fullmatch(str(value)))


def safe_member(value: str) -> bool:
    return bool(_SAFE_MEMBER.fullmatch(str(value))) and all(x not in value for x in (";", "\n", "\r", "{", "}"))


def rollback_member(rr: str, pool: str, member: str, data: dict[str, Any]) -> str:
    """Render a limited, explicit member re-add; refuse unsupported settings.

    Original configuration must be captured before removing a member. The
    command is supplementary, not a substitute for full rollback procedures.
    """
    command = f"tmsh modify gtm pool {rr} {pool} members add {{ {member} {{"
    attrs = []
    if data.get("enabled") is True:
        attrs.append("enabled")
    elif data.get("disabled") is True:
        attrs.append("disabled")
    for key, tmsh_key in (("ratio", "ratio"), ("memberOrder", "member-order")):
        val = data.get(key)
        if val is not None and str(val).isdigit():
            attrs.append(f"{tmsh_key} {val}")
    # Monitors, topology, dependencies, app-service and custom properties are
    # not reliably reconstructed from flattened REST member responses.
    return command + (" " + " ".join(attrs) if attrs else "") + " } }"


def prepared_member_commands(rr: str, pool: str, member: str, obj: dict[str, Any]) -> tuple[str, str]:
    if rr not in SUPPORTED_RRS or not safe_object(pool) or not safe_member(member):
        return "", "REVIEW REQUIRED: unusual identifier; inspect tmsh manually"
    if obj.get("appService") or obj.get("app-service"):
        return "", "REVIEW REQUIRED: member is owned by an application service"
    delete = f"tmsh modify gtm pool {rr} {pool} members delete {{ {member} }}"
    backup = f"tmsh list gtm pool {rr} {pool} all-properties"
    restore = rollback_member(rr, pool, member, obj)
    return delete, f"# BEFORE DELETE: {backup}\n# Review member attributes before re-adding\n{restore}\n# Verify against saved full tmsh config"


def prepared_pool_commands(rr: str, pool: str, obj: dict[str, Any], members: list[dict[str, Any]]) -> tuple[str, str]:
    if rr not in SUPPORTED_RRS or not safe_object(pool) or obj.get("appService"):
        return "", "REVIEW REQUIRED: complex or application-managed Pool"
    delete = f"tmsh delete gtm pool {rr} {pool}"
    # Do NOT fabricate a full create command from incomplete REST fields.
    rollback = (f"# BEFORE DELETE: tmsh list gtm pool {rr} {pool} all-properties\n"
                "# ROLLBACK: restore the exact saved Pool configuration using an approved tmsh/config backup\n"
                "# No safe one-line create command can be guaranteed from REST alone")
    return delete, rollback



def prepared_virtual_commands(server: str, vs: str, data: dict[str, Any], server_data: dict[str, Any]) -> tuple[str, str]:
    """Reference-only tmsh actions; discovery and dependencies must be checked."""
    if not safe_object(server) or not safe_object(vs) or data.get("appService") or server_data.get("appService"):
        return "", "REVIEW REQUIRED: invalid identifier or iApp ownership"
    command = f"tmsh modify gtm server {server} virtual-servers delete {{ {vs} }}"
    restore = f"# BEFORE DELETE: tmsh list gtm server {server} all-properties\n"
    dest = str(data.get("destination") or data.get("address") or "")
    if dest and re.fullmatch(r"[A-Za-z0-9.:%_-]+", dest):
        restore += ("# PARTIAL ROLLBACK EXAMPLE ONLY: other settings MUST be restored from saved config\n"
                    f"tmsh modify gtm server {server} virtual-servers add {{ {vs} {{ destination {dest} }} }}\n")
    else:
        restore += "# ROLLBACK: recreate using the exact saved virtual-server settings\n"
    restore += "# Auto-discovery may recreate or manage this VS; validate dependencies and configuration backup"
    return command, restore


def prepared_server_commands(server: str, data: dict[str, Any]) -> tuple[str, str]:
    """GSLB Server deletion is not the same as deleting a physical LTM device."""
    if not safe_object(server) or data.get("appService"):
        return "", "REVIEW REQUIRED: invalid identifier or iApp ownership"
    return (f"tmsh delete gtm server {server}",
            f"# BEFORE DELETE: tmsh list gtm server {server} all-properties\n"
            "# ROLLBACK: recreate the entire GSLB Server from a saved, verified configuration\n"
            "# This includes datacenter, addresses, virtuals, monitors, discovery and dependencies")


def non_executable_reference(value: str, missing: str) -> str:
    """Make every report action visibly NON-executable, including comments."""
    if not value:
        value = missing
    return "\n".join("NOT RUN: " + line for line in str(value).splitlines())


def status_is_down(value: str) -> bool:
    return str(value).strip().upper() in {"OFFLINE", "DOWN", "UNAVAILABLE", "RED", "FALSE"}


def _pool_member_datasets_complete(snap: Snapshot) -> bool:
    for rr in RECORD_TYPES:
        for p in snap.datasets.get(f"gtm_pool_{rr}", []):
            key = f"pool_members::{rr}::{object_id(p)}"
            if snap.meta.get("endpoint_results", {}).get(key) != "OK" or not isinstance(snap.datasets.get(key), list):
                return False
    return True


def _wideip_associations_complete(snap: Snapshot) -> bool:
    for rr in RECORD_TYPES:
        for w in snap.datasets.get(f"gtm_wideip_{rr}", []):
            key = f"wideip_pools::{rr}::{object_id(w)}"
            if snap.meta.get("endpoint_results", {}).get(key) != "OK":
                return False
    return True


def _core_complete(snap: Snapshot) -> bool:
    required = ["gtm_server", "gtm_datacenter"]
    required += [f"gtm_{kind}_{rr}" for rr in RECORD_TYPES for kind in ("pool", "wideip")]
    return all(snap.meta.get("endpoint_results", {}).get(k) == "OK" for k in required)


def _dynamic_guard(snap: Snapshot) -> bool:
    results = snap.meta.get("endpoint_results", {})
    return (snap.meta.get("scope") != "all"
            or results.get("gtm_rule") != "OK"
            or results.get("gtm_distributed_app") != "OK"
            or bool(snap.datasets.get("gtm_rule"))
            or bool(snap.datasets.get("gtm_distributed_app"))
            or any(bool(w.get("rules") or w.get("rulesReference"))
                   for rr in RECORD_TYPES for w in snap.datasets.get(f"gtm_wideip_{rr}", [])))


def _split_member_ref(raw: str, known_servers: set[str]) -> tuple[str, str]:
    """Resolve only exact server prefix; avoid splitting /Common/... at
    arbitrary colons or treating IPv6 as a server name.
    """
    matches = sorted(((server, raw[len(server) + 1:]) for server in known_servers
                      if raw.startswith(server + ":") and raw[len(server) + 1:]),
                     key=lambda x: len(x[0]), reverse=True)
    if len(matches) == 1:
        return matches[0]
    if len(matches) > 1 and len(matches[0][0]) > len(matches[1][0]):
        return matches[0]
    return "", ""


def _snapshot_gap_hours(dns_ts: str, ltm_ts: str) -> float | None:
    try:
        a = datetime.fromisoformat(dns_ts.replace("Z", "+00:00"))
        b = datetime.fromisoformat(ltm_ts.replace("Z", "+00:00"))
        if a.tzinfo is None or b.tzinfo is None:
            return None
        return abs((a.astimezone(timezone.utc) - b.astimezone(timezone.utc)).total_seconds()) / 3600
    except (TypeError, ValueError):
        return None


def enrich_cleanup(audit: Audit, snap: Snapshot,
                   ltm_snapshots: dict[str, LtmInventory] | None = None,
                   max_snapshot_gap_hours: float = 48,
                   ltm_scan: LtmScan | None = None,
                   ltm_coverage_complete: bool = False) -> None:
    """Add change-review fields to existing reports without changing collector."""
    ltm_snapshots = ltm_snapshots or {}
    results = snap.meta.get("endpoint_results", {})
    all_core = _core_complete(snap)
    all_members = _pool_member_datasets_complete(snap)
    all_assocs = _wideip_associations_complete(snap)
    dynamic = _dynamic_guard(snap)
    static_complete = all_core and all_members and all_assocs and not dynamic

    pool_objects = {(rr, object_id(obj)): obj for rr in RECORD_TYPES
                    for obj in snap.datasets.get(f"gtm_pool_{rr}", [])}
    server_objects = {object_id(s): s for s in snap.datasets.get("gtm_server", [])}
    dns_virtuals = {}
    for server in server_objects:
        for v in snap.datasets.get(f"server_virtuals::{server}", []) or []:
            dns_virtuals[(server, object_id(v))] = v

    def locate(server: str, vs: str, obj: dict[str, Any] | None) -> dict[str, Any]:
        """Use explicit mapping where supplied; otherwise search every scanned LTM.

        Global absence is insufficient evidence unless the operator explicitly
        asserts complete coverage with --ltm-coverage-complete.
        """
        obj = obj or {}
        inv = ltm_snapshots.get(server)
        if not obj:
            return {"comparison": "UNVERIFIABLE", "location": "", "sources": "",
                    "timestamp": "", "checked": len(ltm_scan.inventories) if ltm_scan else int(inv is not None),
                    "negative_ok": False, "fresh": False, "mode": "NO DNS VIRTUAL"}
        dest = str(obj.get("destination") or obj.get("address") or "")
        target = str(obj.get("ltmName") or "")
        if inv:
            comparison = inv.compare(vs, dest, target)
            gap = _snapshot_gap_hours(str(snap.meta.get("collected_at") or ""), inv.timestamp)
            return {"comparison": comparison, "location": inv.host if comparison in (
                    "PRESENT", "ADDRESS_PRESENT_DIFFERENT_NAME", "NAME_PRESENT_ADDRESS_DIFFERS") else "",
                    "sources": inv.directory, "timestamp": inv.timestamp, "checked": 1,
                    "negative_ok": True, "fresh": gap is not None and gap <= max_snapshot_gap_hours,
                    "mode": "EXPLICIT"}
        if ltm_scan and ltm_scan.inventories:
            matched = ltm_scan.search(vs, dest, target)
            gaps = [_snapshot_gap_hours(str(snap.meta.get("collected_at") or ""), i.timestamp)
                    for i in ltm_scan.inventories]
            fresh = all(g is not None and g <= max_snapshot_gap_hours for g in gaps)
            # Even duplicate snapshot warnings may hide topology ambiguities;
            # do not promote a negative result when discovery is not clean.
            discovery_clean = not ltm_scan.warnings
            matched.update({"negative_ok": ltm_coverage_complete and discovery_clean,
                            "fresh": fresh, "mode": "AUTO SEARCH"})
            return matched
        return {"comparison": "NOT_COMPARED", "location": "", "sources": "",
                "timestamp": "", "checked": 0, "negative_ok": False, "fresh": False,
                "mode": "NONE"}

    def evidence_columns(row: dict[str, Any], match: dict[str, Any]) -> None:
        row["LTM Comparison"] = match["comparison"]
        row["LTM Location"] = match["location"]
        row["LTM Source"] = match["sources"]
        row["LTM Snapshot UTC"] = match["timestamp"]
        row["LTM Scanned"] = match["checked"]
        row["LTM Search Mode"] = match["mode"]

    def setup(row: dict[str, Any], verdict: str, notes: str, delete: str = "", rollback: str = "") -> None:
        row["Verdict"] = verdict
        row["Notes"] = notes
        row["Delete"] = non_executable_reference(delete or row.get("_ref_delete", ""),
                                                 "No safe deletion command: manual inspection required") if (
                                                 "_ref_delete" in row or delete) else ""
        row["Rollback"] = non_executable_reference(rollback or row.get("_ref_rollback", ""),
                                                   "Restore from verified pre-change backup") if (
                                                   "_ref_rollback" in row or rollback) else ""

    for row in audit.wideips:
        if row["Config"] == "DISABLED":
            setup(row, "INACTIVE", "Wide IP administratively disabled; confirm change/DR requirements")
        elif str(row["Finding"]).startswith("REVIEW"):
            setup(row, "MANUAL REVIEW", "No trusted association or no pool linked; possible DNS fallback/rule")
        elif status_is_down(row["Health"]):
            setup(row, "MANUAL REVIEW", "Health DOWN does not prove Wide IP decommissioned")
        else:
            setup(row, "IN USE", "Wide IP has a configured reference; no deletion proposed")

    for row in audit.members:
        rr, pool, raw = row["Type"].lower(), row["Pool"], row["Member"]
        raw_data = next((item for item in snap.datasets.get(f"pool_members::{rr}::{pool}", [])
                         if str(item.get("fullPath") or item.get("name") or item.get("virtualServer") or "") == raw), {})
        row["_ref_delete"], row["_ref_rollback"] = prepared_member_commands(rr, pool, raw, raw_data)
        row["LTM Location"] = ""
        row["LTM Scanned"] = len(ltm_scan.inventories) if ltm_scan else len(ltm_snapshots)
        server = str(row.get("GSLB Server") or "")
        vs = str(row.get("Virtual Server") or "")
        # Some GSLB pool members remain after their server-side VS disappears.
        # In that case the original resolver will be UNRESOLVED, so recover
        # only an exact GSLB Server prefix from the collected inventory.
        if not server and rr in ("a", "aaaa"):
            server, vs = _split_member_ref(raw, set(server_objects))
            if server:
                row["GSLB Server"] = server
                row["Virtual Server"] = vs
                row["Mapping"] = "DNS_VIRTUAL_MISSING" if results.get(f"server_virtuals::{server}") == "OK" else "UNVERIFIED"
        if rr not in ("a", "aaaa"):
            setup(row, "MANUAL REVIEW", f"{rr.upper()} member may be a static record; no LTM VS comparison")
            row["LTM Comparison"] = "NOT_APPLICABLE"
            continue
        if not server or not vs or server not in server_objects:
            setup(row, "UNRELIABLE", "Cannot resolve GSLB Server/Virtual Server uniquely")
            row["LTM Comparison"] = "UNVERIFIED"
            continue
        if results.get(f"server_virtuals::{server}") != "OK":
            setup(row, "UNRELIABLE", "GSLB Server Virtual Server inventory unavailable")
            row["LTM Comparison"] = "UNVERIFIED"
            continue
        dns_virtual = dns_virtuals.get((server, vs))
        if not dns_virtual:
            base = "Pool Member refers to a GSLB Virtual Server absent from the collected GSLB Server inventory"
        else:
            base = "Pool Member references an existing GSLB Virtual Server"
        evidence = locate(server, vs, dns_virtual)
        comp = evidence["comparison"]
        evidence_columns(row, evidence)
        notes = (base + f"; LTM search={evidence['mode']}; result={comp}; "
                 f"snapshots_checked={evidence['checked']}")
        if comp == "NOT_COMPARED":
            verdict = "MANUAL REVIEW" if not dns_virtual or status_is_down(row["Health"]) else "IN USE"
            notes += "; no LTM inventories given: use --ltm-raw-dir DIR"
        elif comp in ("PRESENT", "ADDRESS_PRESENT_DIFFERENT_NAME"):
            verdict = "IN USE" if evidence["fresh"] and not status_is_down(row["Health"]) else "MANUAL REVIEW"
            notes += f"; found at {evidence['location']}; validate if stale/health differs"
        elif comp == "NAME_PRESENT_ADDRESS_DIFFERS":
            verdict = "MANUAL REVIEW"
            notes += "; VS name exists, but destination differs; possible migration"
        elif comp in ("NOT_FOUND", "NOT_FOUND_IN_SCANNED_LTMS"):
            if static_complete and dns_virtual and evidence["fresh"] and evidence["negative_ok"]:
                verdict = "OFFLINE (decommission candidate)"
                notes += "; ALL required evidence provided; verify live device, HA, DNS/DR before change"
            else:
                verdict = "MANUAL REVIEW"
                notes += "; absence in scanned inventory is NOT proof of removal; coverage/staleness or references unverified"
        else:
            verdict = "MANUAL REVIEW"
        if verdict == "OFFLINE (decommission candidate)" and not row["_ref_delete"]:
            verdict = "MANUAL REVIEW"
            notes += "; command safety check failed"
        setup(row, verdict, notes)

    for row in audit.pools:
        rr, pool = row["Type"].lower(), row["Pool"]
        obj = pool_objects.get((rr, pool), {})
        members = snap.datasets.get(f"pool_members::{rr}::{pool}")
        row["_ref_delete"], row["_ref_rollback"] = prepared_pool_commands(rr, pool, obj, members or [])
        referenced = bool(row["Referenced by"])
        if not referenced and static_complete:
            cmd, restore = prepared_pool_commands(rr, pool, obj, members)
            if cmd:
                setup(row, "ORPHAN", "No Wide IP/last-resort reference; complete static catalogs and no GTM iRules/distributed apps. Confirm dependencies before change", cmd, restore)
            else:
                setup(row, "MANUAL REVIEW", "Pool appears orphaned but complex ownership/identifier requires manual change plan")
        elif not referenced:
            setup(row, "MANUAL REVIEW", "No direct Wide IP reference; missing/dynamic dependencies prevent ORPHAN verdict")
        elif members is None:
            setup(row, "UNRELIABLE", "Pool members could not be collected")
        elif row["Config"] == "DISABLED":
            setup(row, "INACTIVE", "Pool disabled but referenced; may be reserved for DR")
        elif status_is_down(row["Health"]):
            setup(row, "MANUAL REVIEW", "Pool DOWN but referenced; no deletion based on health alone")
        elif not members:
            setup(row, "MANUAL REVIEW", "Pool referenced but has zero members")
        else:
            setup(row, "IN USE", "Pool referenced by Wide IP or Last Resort Pool")

    member_refs = {(m.get("GSLB Server"), m.get("Virtual Server")) for m in audit.members}
    for row in audit.virtuals:
        srv, vs = row["Server"], row["Virtual Server"]
        server = server_objects.get(srv, {})
        discovery = str(server.get("virtualServerDiscovery") or "unknown").lower()
        refs = [m for m in audit.members if (m.get("GSLB Server"), m.get("Virtual Server")) == (srv, vs)]
        source = dns_virtuals.get((srv, vs), {})
        row["_ref_delete"], row["_ref_rollback"] = prepared_virtual_commands(srv, vs, source, server)
        evidence = locate(srv, vs, source)
        comparison = evidence["comparison"]
        evidence_columns(row, evidence)
        if discovery != "disabled":
            setup(row, "MANUAL REVIEW", f"Discovery mode={discovery}; GSLB Virtual Server may be automatically managed/recreated")
        elif comparison in ("NOT_FOUND", "NOT_FOUND_IN_SCANNED_LTMS") and static_complete and (
                evidence["fresh"] and evidence["negative_ok"]):
            notes = ("Virtual Server absent from verified LTM snapshot coverage; "
                     "confirm live state, HA, DNS and DR dependencies before removal")
            if refs:
                notes += f"; remove {len(refs)} referencing GSLB Pool Member(s) FIRST"
            if row["_ref_delete"]:
                setup(row, "OFFLINE (decommission candidate)", notes)
            else:
                setup(row, "MANUAL REVIEW", notes + "; command safety check failed")
        elif comparison in ("NAME_PRESENT_ADDRESS_DIFFERS", "ADDRESS_PRESENT_DIFFERENT_NAME"):
            setup(row, "MANUAL REVIEW", f"GSLB vs LTM name/destination mismatch: {comparison}; may be a migration")
        elif comparison == "PRESENT" and not evidence["fresh"]:
            setup(row, "MANUAL REVIEW", "LTM Virtual Server found but its snapshot is too old or timestamp unknown")
        elif refs:
            setup(row, "IN USE" if comparison in ("PRESENT", "NOT_COMPARED") else "MANUAL REVIEW",
                  "GSLB Virtual Server referenced by a Pool Member; LTM comparison=" + comparison)
        elif not all_members or not all_core:
            setup(row, "UNRELIABLE", "Pool Member inventory is incomplete")
        else:
            setup(row, "MANUAL REVIEW", "No Pool Member reference; check depends-on, topology, discovery and iRules; LTM=" + comparison)

    # A referenced Pool with every member retired is not automatically orphaned:
    # removing it would also require updating its Wide IP associations.
    for pool in audit.pools:
        if pool["Verdict"] == "IN USE":
            linked = [m for m in audit.members if m["Pool"] == pool["Pool"] and m["Type"] == pool["Type"]]
            if linked and all(m.get("Verdict") == "OFFLINE (decommission candidate)" for m in linked):
                setup(pool, "OFFLINE (decommission candidate)",
                      "All Pool Members are LTM-absent candidates, but the Pool is still referenced by a Wide IP; "
                      "remove members, assess last resort and detach Wide IP before considering Pool removal")

    for row in audit.servers:
        server = row["Server"]
        row["_ref_delete"], row["_ref_rollback"] = prepared_server_commands(server, server_objects.get(server, {}))
        matched_locations = sorted({x.strip() for v in audit.virtuals if v["Server"] == server
                                    for x in v.get("LTM Location", "").split(",") if x.strip()})
        row["LTM Location"] = ", ".join(matched_locations)
        row["LTM Comparison"] = "PRESENT" if matched_locations else (
            "NO_MATCH_IN_SCANNED_LTMS" if ltm_scan and ltm_scan.inventories else "NOT_COMPARED")
        if row.get("Referenced by member"):
            setup(row, "IN USE", "GSLB Server is referenced by a Pool Member")
        else:
            setup(row, "MANUAL REVIEW", "No direct members found; GSLB Server may provide discovery, probes or dependencies")
    for row in audit.datacenters:
        if row["Server count"]:
            setup(row, "IN USE", "Data Center has GSLB Servers")
        else:
            setup(row, "MANUAL REVIEW", "No GSLB Servers listed; topology or other dependencies possible")

    for row in audit.chains:
        member = next((m for m in audit.members if m["Pool"] == row["Pool"] and m["Member"] == row["Member"]
                       and m["Type"] == row["Type"]), None)
        pool = next((p for p in audit.pools if p["Pool"] == row["Pool"] and p["Type"] == row["Type"]), None)
        source = member or pool
        row["LTM Location"] = (source or {}).get("LTM Location", "")
        row["LTM Comparison"] = (source or {}).get("LTM Comparison", "")
        setup(row, str((source or {}).get("Verdict", "MANUAL REVIEW")),
              str((source or {}).get("Notes", "No resolved resource")))

    audit.candidates = []
    for label, group, name_col in (("POOL MEMBER", audit.members, "Member"),
                                   ("GSLB VIRTUAL SERVER", audit.virtuals, "Virtual Server"),
                                   ("POOL", audit.pools, "Pool")):
        for row in group:
            # Reference actions exist for ALL objects, but the candidates tab
            # includes ONLY classifications that merit cleanup consideration.
            if (row.get("Verdict") == "ORPHAN" if label == "POOL" else
                row.get("Verdict") == "OFFLINE (decommission candidate)") and (
                    row.get("Delete", "").startswith("NOT RUN: tmsh ")):
                audit.candidates.append({
                    "Type": label, "Object": row[name_col], "GSLB Pool": row.get("Pool", ""),
                    "GSLB Server": row.get("GSLB Server", row.get("Server", "")),
                    "LTM Location": row.get("LTM Location", ""),
                    "LTM Comparison": row.get("LTM Comparison", ""),
                    "Record Type": row.get("Type", ""), "Verdict": row["Verdict"],
                    "Notes": row["Notes"], "Delete": row["Delete"], "Rollback": row["Rollback"],
                })

    for group in (audit.members, audit.virtuals, audit.pools, audit.servers):
        for row in group:
            row.pop("_ref_delete", None)
            row.pop("_ref_rollback", None)

    inventory = list(ltm_snapshots.values())
    if ltm_scan:
        inventory += [x for x in ltm_scan.inventories if x.directory not in {i.directory for i in inventory}]
    for inv in inventory:
        audit.ltm_inventory.append({
            "Hostname": inv.host, "Snapshot UTC": inv.timestamp, "Raw Folder": inv.directory,
            "Virtual Servers": len(inv.virtuals), "Status": "VALID",
        })
    if ltm_scan:
        for warning in ltm_scan.warnings:
            audit.ltm_inventory.append({"Hostname": "", "Snapshot UTC": "", "Raw Folder": "",
                                        "Virtual Servers": "", "Status": warning})

    audit.summary.extend([
        {"Metric": "Cleanup candidates with reference commands", "Value": len(audit.candidates)},
        {"Metric": "F5Audit LTM snapshots loaded", "Value": len(inventory)},
        {"Metric": "LTM automatic inventory coverage confirmed", "Value": "YES" if ltm_coverage_complete else "NO"},
        {"Metric": "LTM snapshot validation warnings", "Value": len(ltm_scan.warnings) if ltm_scan else 0},
        {"Metric": "Maximum allowed snapshot gap (hours)", "Value": max_snapshot_gap_hours},
        {"Metric": "GSLB static reference analysis complete", "Value": "YES" if static_complete else "NO"},
        {"Metric": "Operations executed on BIG-IP", "Value": "NONE (read-only)"},
    ])
    # Replace the old hard-coded statement: commands are now generated as TEXT.
    for row in audit.summary:
        if row["Metric"] == "Deletion actions":
            row["Value"] = "PROPOSED AS TEXT ONLY; NEVER EXECUTED"
