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
from .ltm_compare import LtmInventory

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
    for key, tmsh_key in (("ratio", "ratio"), ("memberOrder", "member-order"),
                          ("priority", "priority"), ("weight", "weight"), ("port", "port")):
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
                   max_snapshot_gap_hours: float = 48) -> None:
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

    def setup(row: dict[str, Any], verdict: str, notes: str, delete: str = "", rollback: str = "") -> None:
        row["Verdict"] = verdict
        row["Notes"] = notes
        row["Delete"] = delete
        row["Rollback"] = rollback

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
        inv = ltm_snapshots.get(server)
        if inv is None:
            comp = "NOT_COMPARED"
            notes = base + "; supply --ltm-raw GSLB_SERVER=PATH to compare with F5Audit LTM"
            verdict = "MANUAL REVIEW" if not dns_virtual or status_is_down(row["Health"]) else "IN USE"
        else:
            dest = str((dns_virtual or {}).get("destination") or (dns_virtual or {}).get("address") or "")
            ltm_name = str((dns_virtual or {}).get("ltmName") or "")
            # If DNS VS is absent, there is no destination to cross-check:
            # lacking this address means we cannot prove it was deleted.
            comp = inv.compare(vs, dest, ltm_name) if dns_virtual else "UNVERIFIABLE"
            notes = f"{base}; LTM snapshot {inv.host} at {inv.timestamp}; result={comp}"
            age_gap = _snapshot_gap_hours(str(snap.meta.get("collected_at") or ""), inv.timestamp)
            if comp == "NOT_FOUND" and static_complete and dns_virtual and age_gap is not None and age_gap <= max_snapshot_gap_hours:
                verdict = "OFFLINE (decommission candidate)"
                notes += "; candidate only after verifying live F5 and deployment/DR plan"
            elif comp == "PRESENT" and dns_virtual:
                verdict = "IN USE" if not status_is_down(row["Health"]) else "MANUAL REVIEW"
            else:
                verdict = "MANUAL REVIEW"
        row["LTM Comparison"] = comp
        row["LTM Source"] = inv.directory if inv else ""
        row["LTM Snapshot UTC"] = inv.timestamp if inv else ""
        if verdict == "OFFLINE (decommission candidate)":
            command, restore = prepared_member_commands(rr, pool, raw, raw_data)
            if not command:
                verdict = "MANUAL REVIEW"
                notes += "; cannot safely render tmsh command"
            setup(row, verdict, notes, command, restore)
        else:
            setup(row, verdict, notes)

    for row in audit.pools:
        rr, pool = row["Type"].lower(), row["Pool"]
        obj = pool_objects.get((rr, pool), {})
        members = snap.datasets.get(f"pool_members::{rr}::{pool}")
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
        inv = ltm_snapshots.get(srv)
        source = dns_virtuals.get((srv, vs), {})
        comparison = inv.compare(vs, str(row.get("Destination") or ""), str(source.get("ltmName") or "")) if inv else "NOT_COMPARED"
        row["LTM Comparison"] = comparison
        if discovery != "disabled":
            setup(row, "MANUAL REVIEW", f"Discovery mode={discovery}; object may be automatically managed")
        elif comparison == "NOT_FOUND" and static_complete and (
                inv is not None and (gap := _snapshot_gap_hours(str(snap.meta.get("collected_at") or ""), inv.timestamp)) is not None
                and gap <= max_snapshot_gap_hours):
            notes = ("Not present in explicitly mapped LTM Virtual Server inventory; "
                     "confirm live state and business/DR dependencies before removal")
            if refs:
                notes += f"; remove {len(refs)} referencing GSLB Pool Member(s) FIRST"
            if safe_object(srv) and safe_object(vs) and not source.get("appService") and not server.get("appService"):
                delete = f"tmsh modify gtm server {srv} virtual-servers delete {{ {vs} }}"
                restore = f"# BEFORE DELETE: tmsh list gtm server {srv} all-properties\n"
                dest = str(row.get("Destination") or "")
                # Do not pretend to recreate a complete VS if its REST response
                # does not include a usable destination and settings.
                if dest and re.fullmatch(r"[A-Za-z0-9.:%_-]+", dest):
                    restore += (f"# RE-ADD: review and complete original properties\n"
                                f"tmsh modify gtm server {srv} virtual-servers add {{ {vs} {{ destination {dest} }} }}\n")
                restore += "# Verify against saved complete tmsh configuration"
                setup(row, "OFFLINE (decommission candidate)", notes, delete, restore)
            else:
                setup(row, "MANUAL REVIEW", notes + "; complex owner/identifier prevents command proposal")
        elif comparison in ("NAME_PRESENT_ADDRESS_DIFFERS", "ADDRESS_PRESENT_DIFFERENT_NAME"):
            setup(row, "MANUAL REVIEW", f"GSLB vs LTM destination mismatch: {comparison}; may have been renamed or moved")
        elif refs:
            setup(row, "IN USE" if comparison in ("PRESENT", "NOT_COMPARED") else "MANUAL REVIEW",
                  "GSLB Virtual Server is referenced by a Pool Member")
        elif not all_members or not all_core:
            setup(row, "UNRELIABLE", "Pool Member inventory is incomplete")
        else:
            setup(row, "MANUAL REVIEW", "No Pool Member reference; check depends-on, topology, discovery and iRules")

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
        setup(row, str((source or {}).get("Verdict", "MANUAL REVIEW")),
              str((source or {}).get("Notes", "No resolved resource")))

    audit.candidates = []
    for label, group, name_col in (("POOL MEMBER", audit.members, "Member"),
                                       ("GSLB VIRTUAL SERVER", audit.virtuals, "Virtual Server"),
                                       ("POOL", audit.pools, "Pool")):
        for row in group:
            if row.get("Delete"):
                audit.candidates.append({"Type": label, "Object": row[name_col], "GSLB Pool": row.get("Pool", ""), "GSLB Server": row.get("Server", ""),
                    "Record Type": row.get("Type", ""), "Verdict": row["Verdict"], "Notes": row["Notes"],
                    "Delete": row["Delete"], "Rollback": row["Rollback"]})

    audit.summary.extend([
        {"Metric": "Cleanup candidates with tmsh proposal", "Value": len(audit.candidates)},
        {"Metric": "F5Audit LTM snapshots supplied", "Value": len(ltm_snapshots)},
        {"Metric": "Maximum allowed snapshot gap (hours)", "Value": max_snapshot_gap_hours},
        {"Metric": "GSLB static reference analysis complete", "Value": "YES" if static_complete else "NO"},
        {"Metric": "Operations executed on BIG-IP", "Value": "NONE (read-only)"},
    ])
    # Replace the old hard-coded statement: commands are now generated as TEXT.
    for row in audit.summary:
        if row["Metric"] == "Deletion actions":
            row["Value"] = "PROPOSED AS TEXT ONLY; NEVER EXECUTED"
