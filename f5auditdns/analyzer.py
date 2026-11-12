"""Conservative, auditable correlation of BIG-IP DNS GSLB objects.

No finding in this module is an authorization to delete an object. The
algorithm distinguishes missing evidence from truly empty relationships.
"""
from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

from .collector import Snapshot, RECORD_TYPES, object_id


@dataclass
class Audit:
    summary: list[dict[str, Any]] = field(default_factory=list)
    wideips: list[dict[str, Any]] = field(default_factory=list)
    pools: list[dict[str, Any]] = field(default_factory=list)
    members: list[dict[str, Any]] = field(default_factory=list)
    servers: list[dict[str, Any]] = field(default_factory=list)
    virtuals: list[dict[str, Any]] = field(default_factory=list)
    datacenters: list[dict[str, Any]] = field(default_factory=list)
    chains: list[dict[str, Any]] = field(default_factory=list)
    manual_review: list[dict[str, Any]] = field(default_factory=list)
    auxiliary: list[dict[str, Any]] = field(default_factory=list)
    collection_health: list[dict[str, Any]] = field(default_factory=list)
    candidates: list[dict[str, Any]] = field(default_factory=list)


def normalize_path(value: Any, partition: str = "Common") -> str:
    """Resolve a simple relative BIG-IP name without conflating partitions."""
    text = str(value or "").strip()
    if not text:
        return ""
    return text if text.startswith("/") else f"/{partition}/{text}"


def ref_name(ref: Any) -> str:
    if isinstance(ref, str):
        return ref
    if isinstance(ref, dict):
        return str(ref.get("fullPath") or ref.get("name") or ref.get("pool") or "")
    return ""


def names_of(value: Any) -> list[str]:
    if isinstance(value, list):
        return [x for x in (ref_name(item) for item in value) if x]
    if isinstance(value, dict):
        if isinstance(value.get("items"), list):
            return names_of(value["items"])
        return [ref_name(value)] if ref_name(value) else []
    if isinstance(value, str) and value.strip():
        return [value.strip()]
    return []


def config_state(obj: dict[str, Any]) -> str:
    """Configuration enable/disable is not the same as service health UP/DOWN."""
    disabled = obj.get("disabled")
    enabled = obj.get("enabled")
    if disabled is True or str(disabled).lower() in ("true", "yes"):
        return "DISABLED"
    if enabled is False or str(enabled).lower() in ("false", "no"):
        return "DISABLED"
    return "ENABLED" if enabled is True or str(enabled).lower() in ("true", "yes") else "UNKNOWN"


def health_state(obj: dict[str, Any]) -> str:
    """Read only actual health fields; never infer health from 'enabled'."""
    status = obj.get("status")
    if isinstance(status, dict):
        for key in ("availabilityState", "status", "state"):
            if status.get(key):
                return str(status[key]).upper()
    for key in ("availabilityState", "availability", "statusAvailability"):
        if obj.get(key):
            return str(obj[key]).upper()
    return "UNKNOWN"


def add_manual(audit: Audit, kind: str, name: str, reason: str, severity: str = "REVIEW") -> None:
    audit.manual_review.append({"Type": kind, "Object": name, "Priority": severity, "Reason": reason})


def _partition(obj: dict[str, Any]) -> str:
    return str(obj.get("partition") or obj.get("tmPartition") or "Common")


def _member_raw_name(member: dict[str, Any]) -> str:
    return str(member.get("fullPath") or member.get("name") or member.get("virtualServer") or "")


def resolve_member(raw: str, server_virtuals: dict[tuple[str, str], str]) -> tuple[str, str, str]:
    """Match /Partition/Server:/Partition/VS only when the match is unique.

    A pool member can have a nested path. Use exact /server:vs pairs where
    available; do not guess on ambiguous names. Return (server, vs, status).
    """
    raw = str(raw).strip()
    if not raw:
        return ("", "", "UNKNOWN")
    matches = []
    for (server, vs), _ in server_virtuals.items():
        canonical = server + ":" + vs
        short_server = server.rsplit("/", 1)[-1]
        short_vs = vs.rsplit("/", 1)[-1]
        choices = {canonical, f"{server}:{short_vs}", f"{short_server}:{vs}",
                   f"{short_server}:{short_vs}"}
        if raw in choices or raw.endswith(canonical):
            matches.append((server, vs))
    matches = list(set(matches))
    if len(matches) == 1:
        return (*matches[0], "MATCHED")
    return ("", "", "AMBIGUOUS" if len(matches) > 1 else "UNRESOLVED")


def analyze(snap: Snapshot, ltm_snapshots=None, max_snapshot_gap_hours: float = 48) -> Audit:
    a = Audit()
    datasets, results = snap.datasets, snap.meta.get("endpoint_results", {})
    core_keys = [f"gtm_{kind}_{rr}" for rr in RECORD_TYPES for kind in ("wideip", "pool")]
    core_keys += ["gtm_datacenter", "gtm_server"]
    missing_core = [k for k in core_keys if results.get(k) != "OK"]
    any_dynamic = bool(datasets.get("gtm_rule")) or bool(datasets.get("gtm_distributed_app"))
    dynamic_coverage_unknown = snap.meta.get("scope") != "all" or any(
        results.get(k) != "OK" for k in ("gtm_rule", "gtm_distributed_app")
    )

    for key, state in sorted(results.items()):
        a.collection_health.append({"Dataset": key, "Status": state,
                                    "Endpoint": snap.meta.get("endpoint_paths", {}).get(key, "")})
        if state != "OK":
            add_manual(a, "COLLECTION", key, f"Dataset incomplete: {state}", "DATA GAP")

    pools_by_key: dict[tuple[str, str], dict[str, Any]] = {}
    wideip_pools: dict[tuple[str, str], list[tuple[str, str]]] = defaultdict(list)
    reverse_pool_refs: dict[tuple[str, str], set[str]] = defaultdict(set)
    unresolved_pool_refs: list[tuple[str, str, str]] = []

    # Index *all* pool types before resolving A/CNAME last-resort references.
    for rr in RECORD_TYPES:
        for obj in datasets.get(f"gtm_pool_{rr}", []):
            pools_by_key[(rr, object_id(obj))] = obj
    for rr in RECORD_TYPES:
        for obj in datasets.get(f"gtm_wideip_{rr}", []):
            wid = object_id(obj)
            part = _partition(obj)
            associations_key = f"wideip_pools::{rr}::{wid}"
            pool_rows = datasets.get(associations_key)
            if pool_rows is None:
                # Some API versions use a direct 'pools' property in the parent.
                inline = obj.get("pools")
                pool_rows = inline if isinstance(inline, list) else None
            refs: list[tuple[str, str]] = []
            if pool_rows is not None:
                for p in pool_rows:
                    name = ref_name(p)
                    if name:
                        refs.append((rr, normalize_path(name, str(p.get("partition") or part) if isinstance(p, dict) else part)))
                extra = datasets.get(f"wideip_pools_cname::{rr}::{wid}", [])
                for p in extra:
                    name = ref_name(p)
                    if name:
                        refs.append(("cname", normalize_path(name, str(p.get("partition") or part) if isinstance(p, dict) else part)))
            elif obj.get("poolsCname"):
                for n in names_of(obj["poolsCname"]):
                    refs.append(("cname", normalize_path(n, part)))
            last_resort = str(obj.get("lastResortPool") or "").strip()
            if last_resort and last_resort.lower() not in ("none", "none "):
                target = normalize_path(last_resort, part)
                # Last resort may be an A or CNAME pool; only resolve when unique.
                options = [(ty, target) for ty in (rr, "cname") if (ty, target) in pools_by_key]
                options = list(dict.fromkeys(options))
                if len(options) == 1:
                    refs.append(options[0])
                else:
                    unresolved_pool_refs.append((rr, wid, f"Last resort pool {target}: not uniquely resolved"))
            refs = list(dict.fromkeys(refs))
            wideip_pools[(rr, wid)] = refs
            for key in refs:
                reverse_pool_refs[key].add(f"{rr.upper()} {wid}")
            a.wideips.append({
                "Type": rr.upper(), "Wide IP": wid, "Config": config_state(obj),
                "Health": health_state(obj), "Pools": ", ".join(f"{t.upper()}:{n}" for t, n in refs),
                "Pool count": len(refs), "Last resort": last_resort,
                "Rules": ", ".join(names_of(obj.get("rules"))),
                "Finding": "REVIEW: pool links unavailable" if pool_rows is None else
                           "REVIEW: no pool reference" if not refs else "REFERENCED",
            })
            if pool_rows is None:
                add_manual(a, "WIDE IP", wid, "Pool association is missing/unknown (not assumed empty)", "DATA GAP")
            elif not refs:
                add_manual(a, "WIDE IP", wid, "No GSLB Pool reference found; validate intended behavior")
            if config_state(obj) == "DISABLED":
                add_manual(a, "WIDE IP", wid, "Wide IP is disabled; not automatically unused")
            if obj.get("rules"):
                add_manual(a, "WIDE IP", wid, "iRules may select GSLB pools dynamically")
            for typ, target in refs:
                if (typ, target) not in pools_by_key:
                    unresolved_pool_refs.append((rr, wid, f"Referenced Pool {typ.upper()}:{target} not in collected inventory"))

    for rr, wid, reason in unresolved_pool_refs:
        add_manual(a, "WIDE IP", wid, reason, "DATA GAP")

    servers: dict[str, dict[str, Any]] = {object_id(s): s for s in datasets.get("gtm_server", [])}
    datacenters: dict[str, dict[str, Any]] = {object_id(d): d for d in datasets.get("gtm_datacenter", [])}
    server_virtuals: dict[tuple[str, str], str] = {}
    virtuals_per_server: dict[str, int | None] = {}
    for server, obj in servers.items():
        vlist = datasets.get(f"server_virtuals::{server}")
        virtuals_per_server[server] = len(vlist) if isinstance(vlist, list) else None
        if vlist is None:
            add_manual(a, "SERVER", server, "Virtual Server subcollection unknown", "DATA GAP")
            continue
        for v in vlist:
            vname = object_id(v)
            server_virtuals[(server, vname)] = str(v.get("destination") or v.get("address") or "")
            a.virtuals.append({"Server": server, "Virtual Server": vname,
                               "Destination": str(v.get("destination") or v.get("address") or ""),
                               "Port": v.get("port", ""), "Config": config_state(v),
                               "Health": health_state(v)})

    pool_member_counts: dict[tuple[str, str], int | None] = {}
    referenced_servers: set[str] = set()
    member_unresolved = False
    for (rr, path), p in sorted(pools_by_key.items()):
        mkey = f"pool_members::{rr}::{path}"
        members = datasets.get(mkey)
        pool_member_counts[(rr, path)] = len(members) if isinstance(members, list) else None
        for member in members or []:
            raw = _member_raw_name(member)
            server, virtual, resolution = resolve_member(raw, server_virtuals)
            if resolution != "MATCHED":
                member_unresolved = True
                add_manual(a, "POOL MEMBER", raw or path, f"Server/Virtual mapping: {resolution}", "DATA GAP")
            else:
                referenced_servers.add(server)
            a.members.append({"Type": rr.upper(), "Pool": path, "Member": raw,
                              "GSLB Server": server, "Virtual Server": virtual,
                              "Destination": server_virtuals.get((server, virtual), ""),
                              "Mapping": resolution, "Config": config_state(member),
                              "Health": health_state(member)})
        refs = sorted(reverse_pool_refs[(rr, path)])
        if members is None:
            finding = "MANUAL REVIEW: members unknown"
        elif not members:
            finding = "MANUAL REVIEW: no members"
        elif not refs:
            finding = "MANUAL REVIEW: no direct Wide IP reference"
        else:
            finding = "REFERENCED"
        if not refs:
            add_manual(a, "POOL", path, "No direct Wide IP/last-resort reference. iRules and other dependencies may exist.")
        if members is None:
            add_manual(a, "POOL", path, "Pool Member subcollection unavailable", "DATA GAP")
        elif not members:
            add_manual(a, "POOL", path, "Pool has zero members; check fallback/maintenance design")
        a.pools.append({"Type": rr.upper(), "Pool": path, "Config": config_state(p),
                        "Health": health_state(p), "Member count": pool_member_counts[(rr, path)],
                        "Referenced by": ", ".join(refs), "Monitor": str(p.get("monitor") or ""),
                        "Method": str(p.get("loadBalancingMode") or ""), "Finding": finding})

    server_to_dc: dict[str, list[str]] = defaultdict(list)
    for sid, s in sorted(servers.items()):
        dc = normalize_path(s.get("datacenter"), _partition(s))
        if dc:
            server_to_dc[dc].append(sid)
        count = virtuals_per_server[sid]
        finding = "REFERENCED" if sid in referenced_servers else "MANUAL REVIEW: no mapped member"
        a.servers.append({"Server": sid, "Data Center": dc, "Product": s.get("product", ""),
                          "Virtual Server count": count, "Config": config_state(s),
                          "Health": health_state(s), "Referenced by member": sid in referenced_servers,
                          "Finding": finding})
        if count == 0:
            add_manual(a, "SERVER", sid, "No GSLB Virtual Servers; validate discovery and intended role")
        if dc and dc not in datacenters:
            add_manual(a, "SERVER", sid, f"Data Center {dc} unavailable in inventory", "DATA GAP")
        if sid not in referenced_servers and not member_unresolved:
            add_manual(a, "SERVER", sid, "No mapped GSLB Pool Member; could be backup/prober/discovery")
    for dcid, dc in sorted(datacenters.items()):
        associated = server_to_dc.get(dcid, [])
        a.datacenters.append({"Data Center": dcid, "Server count": len(associated),
                              "Servers": ", ".join(associated), "Config": config_state(dc),
                              "Health": health_state(dc),
                              "Finding": "MANUAL REVIEW: no servers" if not associated else "REFERENCED"})
        if not associated:
            add_manual(a, "DATA CENTER", dcid, "No GSLB Server references; may still have topology/prober role")

    member_by_pool = defaultdict(list)
    for member in a.members:
        member_by_pool[(member["Type"].lower(), member["Pool"])].append(member)
    for w in a.wideips:
        pairs = wideip_pools.get((w["Type"].lower(), w["Wide IP"]), [])
        if not pairs:
            a.chains.append({"Type": w["Type"], "Wide IP": w["Wide IP"], "Pool": "",
                             "Member": "", "Server": "", "Virtual Server": "", "Destination": "", "Note": "NO RESOLVED POOLS"})
        for ptype, pname in pairs:
            linked = member_by_pool.get((ptype, pname), [])
            if not linked:
                a.chains.append({"Type": w["Type"], "Wide IP": w["Wide IP"],
                                 "Pool": pname, "Member": "", "Server": "", "Virtual Server": "",
                                 "Destination": "", "Note": "NO MEMBERS OR UNAVAILABLE DATA"})
            for m in linked:
                a.chains.append({"Type": w["Type"], "Wide IP": w["Wide IP"],
                                 "Pool": pname, "Member": m["Member"],
                                 "Server": m["GSLB Server"], "Virtual Server": m["Virtual Server"],
                                 "Destination": m["Destination"], "Note": m["Mapping"]})

    for key, values in sorted(datasets.items()):
        if key.startswith(("gtm_monitor_", "gtm_listener", "gtm_rule", "gtm_topology",
                           "gtm_region", "gtm_prober_pool", "gtm_distributed_app")):
            for item in values if isinstance(values, list) else []:
                a.auxiliary.append({"Dataset": key, "Object": object_id(item),
                                    "Config": config_state(item), "Description": str(item.get("description") or "")})
    a.summary = [
        {"Metric": "Host", "Value": snap.meta.get("host", "")},
        {"Metric": "Collection timestamp UTC", "Value": snap.meta.get("collected_at", "")},
        {"Metric": "Scope", "Value": snap.meta.get("scope", "")},
        {"Metric": "Wide IPs", "Value": len(a.wideips)},
        {"Metric": "GSLB Pools", "Value": len(a.pools)},
        {"Metric": "GSLB Pool Members", "Value": len(a.members)},
        {"Metric": "GSLB Servers", "Value": len(a.servers)},
        {"Metric": "GSLB Virtual Servers", "Value": len(a.virtuals)},
        {"Metric": "Data Centers", "Value": len(a.datacenters)},
        {"Metric": "Manual review entries", "Value": len(a.manual_review)},
        {"Metric": "Failed or unknown datasets", "Value": sum(v != "OK" for v in results.values())},
        {"Metric": "Complete core catalog", "Value": "YES" if not missing_core else "NO"},
        {"Metric": "Can independently establish lack of use", "Value": "NO - requires historical and operational validation"},
        {"Metric": "Deletion actions", "Value": "NEVER GENERATED"},
    ]
    if missing_core:
        add_manual(a, "GLOBAL", "COLLECTION", "Core inventory incomplete; no unused classification is safe", "DATA GAP")
    if any_dynamic or dynamic_coverage_unknown:
        add_manual(a, "GLOBAL", "DYNAMIC REFERENCES",
                   "iRules/distributed apps present or not collected; direct object references may be incomplete")
    from .cleanup import enrich_cleanup
    enrich_cleanup(a, snap, ltm_snapshots, max_snapshot_gap_hours)
    return a
