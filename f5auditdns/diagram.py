"""Offline, evidence-preserving BIG-IP DNS/GSLB topology graph.

No network calls and no BIG-IP changes are performed. Identifiers retain their
full partition paths. Potential dynamic references are conservatively flagged;
absence of a direct edge is never proof that deletion is safe.
"""
from __future__ import annotations

import json
import re
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .analyzer import Audit, analyze, names_of, normalize_path, resolve_member
from .cleanup import safe_object
from .collector import RECORD_TYPES, Snapshot, _for_disk, object_id

CORE_PREFIXES = ("gtm_datacenter", "gtm_server") + tuple(
    f"gtm_{kind}_{rr}" for rr in RECORD_TYPES for kind in ("wideip", "pool")
)
CONNECTIVITY = {"AVAILABLE", "OFFLINE", "UNAVAILABLE", "DISABLED", "UNKNOWN", "NOT OBSERVED"}
DYNAMIC_KEYS = ("gtm_rule", "gtm_topology", "gtm_distributed_app")
MONITOR_BASE = {"bigip", "gateway_icmp", "gateway-icmp", "default", "none"}


def partition_of(path: str) -> str:
    """Use the actual first path element; never assume /Common."""
    parts = str(path).strip("/").split("/")
    return "/" + (parts[0] if len(parts) > 1 else "Common")


def canonical(ref: Any, owner: str = "/Common") -> str:
    if isinstance(ref, dict):
        name = ref.get("fullPath") or ref.get("name") or ref.get("pool") or ""
        fallback = "/" + str(ref.get("partition") or owner.strip("/"))
    else:
        name, fallback = ref or "", owner
    text = str(name).strip()
    if not text or text.lower() in {"none", "default", "disabled"}:
        return ""
    return text if text.startswith("/") else fallback.rstrip("/") + "/" + text


def split_member_name(raw: str, known_servers: set[str]) -> tuple[str, str]:
    """Resolve server prefix without splitting IPv6 destinations at colons."""
    for server in sorted(known_servers, key=len, reverse=True):
        if raw.startswith(server + ":"):
            remainder = raw[len(server) + 1:]
            if remainder:
                return server, canonical(remainder, partition_of(server))
    return "", ""


def _monitor_refs(obj: dict[str, Any], paths: set[str]) -> set[str]:
    text = str(obj.get("monitor") or "")
    # Monitor expressions can contain 'min 1 of { /Common/monitor1 ... }'.
    # Only exact full paths are accepted. Unqualified names use the partition.
    values = set(re.findall(r"(?<!\w)/[\w.%-]+(?:/[\w.%:-]+)+", text))
    if text.strip() and not values and text.strip() not in {"default", "none"}:
        values.add(canonical(text.strip(), partition_of(object_id(obj))))
    return {x for x in values if x in paths}


def _explicit_pool_refs(obj: dict[str, Any], all_pools: dict[tuple[str, str], str],
                        owner: str, rr: str = "") -> set[str]:
    """Find only explicit object references, not arbitrary text/name substrings."""
    found: set[str] = set()
    for key, val in obj.items():
        normalized = re.sub(r"[^a-z]", "", key.lower())
        if normalized not in {"pool", "pools", "poolname", "poolref", "poolreference",
                              "lastresortpool", "destinationpool", "namepool"}:
            continue
        values = val if isinstance(val, list) else [val]
        for item in values:
            if isinstance(item, dict) and "items" in item:
                values.extend(item["items"] if isinstance(item["items"], list) else [])
                continue
            path = canonical(item, owner)
            if not path:
                continue
            candidates = [nid for (type_, name), nid in all_pools.items()
                          if name == path and (not rr or rr == type_)]
            # All possible pool types are recorded, never a guessed single one.
            found.update(candidates)
    return found


def _truncated_json(value: Any, kind: str = "", limit: int = 16000) -> dict[str, Any]:
    """Keep a sanitised object for the inspector; bound enormous payloads."""
    safe = _for_disk(value, "gtm_rule" if kind == "IRULE" else "diagram_raw")
    packed = json.dumps(safe, ensure_ascii=False, default=str)
    if len(packed) > limit:
        return {"_redacted_note": "Snapshot object too large for embedded inspector; view local RAW JSON.",
                "_size_chars": len(packed), "fullPath": safe.get("fullPath", "") if isinstance(safe, dict) else ""}
    return safe if isinstance(safe, dict) else {"value": safe}


def _delete_reference(kind: str, name: str, rr: str = "", parent: str = "") -> str:
    if kind == "VIRTUAL_SERVER":
        if not safe_object(parent) or not safe_object(name):
            return "REVIEW REQUIRED: tmsh identifier must be validated"
        return f"NOT RUN: tmsh modify gtm server {parent} virtual-servers delete {{ {name} }}"
    prefix = {"WIDE_IP": "wideip", "POOL": "pool", "GSLB_SERVER": "server",
              "DATA_CENTER": "datacenter", "MONITOR": "monitor"}.get(kind)
    if not prefix or not safe_object(name):
        return "REVIEW REQUIRED: no validated delete syntax for this object"
    if kind == "MONITOR" and rr not in {"http", "https", "tcp", "tcp-half-open", "udp", "bigip", "gateway-icmp", "external"}:
        return "REVIEW REQUIRED: monitor type not validated"
    typ = " " + rr if rr else ""
    return f"NOT RUN: tmsh delete gtm {prefix}{typ} {name}"


@dataclass
class DiagramGraph:
    nodes: dict[str, dict[str, Any]] = field(default_factory=dict)
    edges: list[dict[str, str]] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    _dedup_edges: set[tuple[str, str, str]] = field(default_factory=set)

    def node(self, nid: str, kind: str, path: str, data: dict[str, Any],
             *, rr: str = "", health: dict[str, Any] | None = None,
             parent: str = "") -> str:
        reported = health or {}
        h = str(reported.get("Health") or "NOT OBSERVED").upper()
        conf = str(reported.get("Config") or "UNKNOWN").upper()
        if h not in CONNECTIVITY:
            h = "UNKNOWN"
        # This graph does not treat enablement as proof of operational health.
        value = {
            "id": nid, "kind": kind, "fullPath": path,
            "name": path.rsplit("/", 1)[-1], "partition": partition_of(path),
            "recordType": rr.upper(), "health": h, "config": conf,
            "effectiveHealth": h, "healthSource": reported.get("Health Source", "NOT COLLECTED"),
            "availability": reported.get("Availability", ""),
            "statusReason": str(reported.get("Status Reason") or ""),
            "ltmLocation": str(reported.get("LTM Location") or ""),
            "ltmHealth": str(reported.get("LTM Health") or ""),
            "ltmComparison": str(reported.get("LTM Comparison") or ""),
            "iquery": "NOT OBSERVED", "orphanStatus": "NOT ASSESSED",
            "referenceCount": 0,
            "monitor": str(data.get("monitor") or ""),
            "method": str(data.get("loadBalancingMode") or ""),
            "virtualServerDiscovery": str(data.get("virtualServerDiscovery") or ""),
            "deleteReference": _delete_reference(kind, path, rr, parent),
            "rollback": "ROLLBACK INCOMPLETE: requires full saved tmsh list ... all-properties",
            "raw": _truncated_json(data, kind),
        }
        if kind == "POOL_MEMBER":
            value["deleteReference"] = "NOT RUN: # Remove only after reviewing the member's parent Pool and dependencies"
        if kind in {"TOPOLOGY", "IRULE", "REGION", "PROBER_POOL", "OTHER"}:
            value["deleteReference"] = "REVIEW REQUIRED: inspect type-specific configuration and references"
        if kind == "GSLB_SERVER":
            reason = value["statusReason"].lower()
            check = " ".join(str(data.get(k) or "") for k in ("iqueryState", "iQueryState", "iqueryStatus", "iQueryStatus")).lower()
            if check.strip() in ("up", "connected", "available"):
                value["iquery"] = "CONNECTED (REPORTED)"
            elif check.strip() in ("down", "disconnected", "offline"):
                value["iquery"] = "DISCONNECTED (REPORTED)"
            elif any(t in reason for t in ("iquery", "big3d", "gtmd")):
                value["iquery"] = "REVIEW STATUS REASON: " + value["statusReason"]
        self.nodes[nid] = value
        return nid

    def edge(self, src: str, dst: str, relation: str, certainty: str = "EXACT") -> None:
        if src not in self.nodes or dst not in self.nodes:
            self.warnings.append(f"Unresolved {relation}: {src} -> {dst}")
            return
        key = (src, dst, relation)
        if key not in self._dedup_edges:
            self._dedup_edges.add(key)
            self.edges.append({"source": src, "target": dst, "relation": relation,
                               "certainty": certainty,
                               "crossPartition": str(self.nodes[src]["partition"] != self.nodes[dst]["partition"]).lower()})


def _index_rows(audit: Audit, attr: str, *keys: str) -> dict[tuple[Any, ...], dict[str, Any]]:
    return {tuple(x.get(key, "") for key in keys): x for x in getattr(audit, attr)}


def _complete(snap: Snapshot) -> tuple[bool, bool, list[str]]:
    results = snap.meta.get("endpoint_results", {})
    missing = [k for k in CORE_PREFIXES if results.get(k) != "OK"]
    for rr in RECORD_TYPES:
        for p in snap.datasets.get(f"gtm_pool_{rr}", []):
            key = f"pool_members::{rr}::{object_id(p)}"
            if results.get(key) != "OK":
                missing.append(key)
        for w in snap.datasets.get(f"gtm_wideip_{rr}", []):
            key = f"wideip_pools::{rr}::{object_id(w)}"
            if results.get(key) != "OK":
                missing.append(key)
    dynamic_missing = [k for k in DYNAMIC_KEYS if results.get(k) != "OK"]
    missing.extend(dynamic_missing)
    scope_complete = snap.meta.get("scope") == "all" and not missing
    dynamic_present = any(bool(snap.datasets.get(k)) for k in DYNAMIC_KEYS)
    dynamic_present |= any(bool(w.get("rules") or w.get("rulesReference"))
                           for rr in RECORD_TYPES for w in snap.datasets.get(f"gtm_wideip_{rr}", []))
    return scope_complete, dynamic_present, sorted(set(missing))


def _calculate_health(graph: DiagramGraph) -> None:
    """Propagate observed child health conservatively up the service chain.

    A missing monitor/iQuery statistic never becomes OFFLINE by inference.
    A degraded result is derived only from available and failed members.
    """
    relations = {"DIRECT_POOL", "LAST_RESORT", "DIRECT_CNAME", "HAS_MEMBER",
                 "MEMBER_TARGET", "DEFINED_ON", "IN_DATACENTER"}
    children: dict[str, list[str]] = defaultdict(list)
    for edge in graph.edges:
        if edge["relation"] in relations and edge["certainty"] == "EXACT":
            children[edge["source"]].append(edge["target"])
    cache: dict[str, str] = {}

    def effective(nid: str, trail: set[str]) -> str:
        if nid in cache:
            return cache[nid]
        node = graph.nodes[nid]
        observed = node["health"]
        if node["config"] == "DISABLED" or observed == "DISABLED":
            cache[nid] = "DISABLED"
            return cache[nid]
        if nid in trail:
            return "UNKNOWN"
        kids = children[nid]
        if not kids:
            cache[nid] = observed
            return observed
        states = [effective(x, trail | {nid}) for x in kids]
        downs = sum(v in {"OFFLINE", "UNAVAILABLE"} for v in states)
        ups = sum(v == "AVAILABLE" for v in states)
        degraded = sum(v == "DEGRADED" for v in states)
        uncertain = sum(v in {"UNKNOWN", "NOT OBSERVED", "DISABLED"} for v in states)
        # Direct observed availability may override missing child states, but
        # explicit errors are still surfaced when some branches are available.
        if (downs or degraded) and (ups or degraded):
            output = "DEGRADED"
        elif downs and not uncertain and downs == len(states):
            output = "OFFLINE"
        elif observed == "AVAILABLE":
            output = "AVAILABLE"
        elif observed in {"OFFLINE", "UNAVAILABLE"}:
            output = observed
        elif ups and not uncertain and ups == len(states):
            output = "AVAILABLE"
        else:
            output = "UNKNOWN" if observed == "UNKNOWN" else "NOT OBSERVED"
        cache[nid] = output
        return output

    for nid in graph.nodes:
        graph.nodes[nid]["effectiveHealth"] = effective(nid, set())
        graph.nodes[nid]["healthDerivation"] = ("OBSERVED" if graph.nodes[nid]["health"] == cache[nid]
                                                 else "DERIVED FROM REFERENCES — REVIEW")


def _sys_version(snap: Snapshot) -> dict[str, str]:
    """Read collected sys/version properties without guessing a TMOS release."""
    raw = snap.datasets.get("sys_version")
    out: dict[str, str] = {}

    def walk(value: Any, depth: int = 0) -> None:
        if depth > 8 or len(out) == 3:
            return
        if isinstance(value, dict):
            for key, item in value.items():
                label = str(key).lower()
                if label in {"version", "build", "product"}:
                    val = item.get("description") if isinstance(item, dict) else item
                    if isinstance(val, (str, int, float)) and str(val).strip():
                        out[label] = str(val).strip()[:80]
                if isinstance(item, (dict, list)):
                    walk(item, depth+1)
        elif isinstance(value, list):
            for item in value[:100]:
                walk(item, depth+1)
    walk(raw)
    return out


def build_diagram(snap: Snapshot, audit: Audit | None = None) -> dict[str, Any]:
    """Produce a portable JSON graph and a navigable tree from an existing RAW.

    This never authenticates to BIG-IP, fetches from network, or executes tmsh.
    """
    audit = audit or analyze(snap)
    graph = DiagramGraph()
    datasets = snap.datasets
    pool_rows = _index_rows(audit, "pools", "Type", "Pool")
    wide_rows = _index_rows(audit, "wideips", "Type", "Wide IP")
    member_rows = _index_rows(audit, "members", "Type", "Pool", "Member")
    vs_rows = _index_rows(audit, "virtuals", "Server", "Virtual Server")
    server_rows = _index_rows(audit, "servers", "Server")
    dc_rows = _index_rows(audit, "datacenters", "Data Center")
    all_pools: dict[tuple[str, str], str] = {}
    all_wideips: dict[tuple[str, str], str] = {}
    servers: dict[str, str] = {}
    virtuals: dict[tuple[str, str], str] = {}
    dcs: dict[str, str] = {}
    monitors: dict[str, str] = {}

    for obj in datasets.get("gtm_datacenter", []):
        path = object_id(obj)
        dcs[path] = graph.node("datacenter|" + path, "DATA_CENTER", path, obj,
                               health=dc_rows.get((path,)))
    for obj in datasets.get("gtm_server", []):
        path = object_id(obj)
        servers[path] = graph.node("server|" + path, "GSLB_SERVER", path, obj,
                                   health=server_rows.get((path,)))
    for rr in RECORD_TYPES:
        for obj in datasets.get(f"gtm_pool_{rr}", []):
            path = object_id(obj)
            all_pools[(rr, path)] = graph.node(f"pool|{rr}|{path}", "POOL", path, obj, rr=rr,
                                              health=pool_rows.get((rr.upper(), path)))
        for obj in datasets.get(f"gtm_wideip_{rr}", []):
            path = object_id(obj)
            all_wideips[(rr, path)] = graph.node(f"wideip|{rr}|{path}", "WIDE_IP", path, obj,
                                                rr=rr, health=wide_rows.get((rr.upper(), path)))

    # Ensure every GSLB VS is indexed regardless of Pool membership.
    for path in servers:
        for obj in datasets.get(f"server_virtuals::{path}", []) or []:
            name = object_id(obj)
            nid = f"vs|{path}|{name}"
            virtuals[(path, name)] = graph.node(nid, "VIRTUAL_SERVER", name, obj,
                                                health=vs_rows.get((path, name)), parent=path)
            row = vs_rows.get((path, name), {})
            graph.nodes[nid]["destination"] = row.get("Destination", "")
            graph.nodes[nid]["ip"] = row.get("Destination IP", "")
            graph.nodes[nid]["port"] = row.get("Port", "")
            graph.nodes[nid]["routeDomain"] = row.get("Route Domain", "")
            graph.edge(nid, servers[path], "DEFINED_ON")
            graph.nodes[nid]["server"] = path
    for obj in datasets.get("gtm_server", []):
        path = object_id(obj)
        dc = canonical(obj.get("datacenter"), partition_of(path))
        if dc and dc in dcs:
            graph.edge(servers[path], dcs[dc], "IN_DATACENTER")
        elif dc:
            graph.warnings.append(f"Server {path} references absent Data Center {dc}")

    for key, rows in datasets.items():
        if not key.startswith("gtm_monitor_") or not isinstance(rows, list):
            continue
        rr = key.split("gtm_monitor_", 1)[1]
        for obj in rows:
            path = object_id(obj)
            nid = "monitor|" + rr + "|" + path
            graph.node(nid, "MONITOR", path, obj, rr=rr)
            monitors[path] = nid

    # Optional source objects keep dynamic/indirect relationships inspectable.
    for dataset_key, kind in (("gtm_rule", "IRULE"), ("gtm_topology", "TOPOLOGY"),
                              ("gtm_region", "REGION"), ("gtm_prober_pool", "PROBER_POOL"),
                              ("gtm_listener", "LISTENER"), ("gtm_distributed_app", "OTHER")):
        for obj in datasets.get(dataset_key, []) or []:
            path = object_id(obj)
            nid = f"{dataset_key}|{path}"
            graph.node(nid, kind, path, obj)

    for rr in RECORD_TYPES:
        for obj in datasets.get(f"gtm_wideip_{rr}", []):
            wid = object_id(obj)
            wnode = all_wideips[(rr, wid)]
            owner = partition_of(wid)
            key = f"wideip_pools::{rr}::{wid}"
            refs = datasets.get(key)
            if not isinstance(refs, list):
                refs = obj.get("pools") if isinstance(obj.get("pools"), list) else []
            for item in refs:
                name = canonical(item, owner)
                for typ in (rr,):
                    target = all_pools.get((typ, name))
                    if target:
                        graph.edge(wnode, target, "DIRECT_POOL")
                    elif name:
                        graph.warnings.append(f"Unresolved pool reference: {wid} -> {typ}:{name}")
            cname = datasets.get(f"wideip_pools_cname::{rr}::{wid}")
            if not isinstance(cname, list):
                cname = obj.get("poolsCname") if isinstance(obj.get("poolsCname"), list) else []
            for item in cname:
                name = canonical(item, owner)
                if ("cname", name) in all_pools:
                    graph.edge(wnode, all_pools[("cname", name)], "DIRECT_CNAME")
            fallback = canonical(obj.get("lastResortPool"), owner)
            if fallback:
                for typ in (rr, "cname"):
                    if (typ, fallback) in all_pools:
                        graph.edge(wnode, all_pools[(typ, fallback)], "LAST_RESORT")
            for rule in names_of(obj.get("rules")):
                path = canonical(rule, owner)
                match = f"gtm_rule|{path}"
                if match in graph.nodes:
                    graph.edge(wnode, match, "USES_RULE")
            for mon in _monitor_refs(obj, set(monitors)):
                graph.edge(wnode, monitors[mon], "USES_MONITOR")

    # Build member identities preserving Pool membership and duplicate VS usage.
    for rr in RECORD_TYPES:
        for pool in datasets.get(f"gtm_pool_{rr}", []):
            pname = object_id(pool)
            parent = all_pools.get((rr, pname))
            if not parent:
                continue
            for n, member in enumerate(datasets.get(f"pool_members::{rr}::{pname}", []) or []):
                raw = str(member.get("fullPath") or member.get("name") or member.get("virtualServer") or "")
                key = f"member|{rr}|{pname}|{n}"
                # IDs are unique per pool: the same VS in another Pool is NOT merged.
                member_data = member_rows.get((rr.upper(), pname, raw), {})
                graph.node(key, "POOL_MEMBER", raw or f"{pname}/unnamed-{n}", member,
                           rr=rr, health=member_data)
                graph.nodes[key]["parentPool"] = pname
                # The member belongs to its Pool partition, although its
                # server:virtual target can live in a different partition.
                graph.nodes[key]["partition"] = partition_of(pname)
                graph.nodes[key]["targetPartition"] = partition_of(raw)
                graph.nodes[key]["destination"] = member_data.get("Destination", "")
                graph.nodes[key]["ip"] = member_data.get("Destination IP", "")
                graph.nodes[key]["port"] = member_data.get("Port", "")
                graph.nodes[key]["routeDomain"] = member_data.get("Route Domain", "")
                graph.edge(parent, key, "HAS_MEMBER")
                linked_server, linked_vs, status = resolve_member(raw, {k: "" for k in virtuals})
                if status != "MATCHED":
                    linked_server, linked_vs = split_member_name(raw, set(servers))
                if (linked_server, linked_vs) in virtuals:
                    graph.edge(key, virtuals[(linked_server, linked_vs)], "MEMBER_TARGET")
                else:
                    graph.warnings.append(f"Pool member unresolved: {pname} / {raw} ({status})")
            for mon in _monitor_refs(pool, set(monitors)):
                graph.edge(parent, monitors[mon], "USES_MONITOR")

    for obj in datasets.get("gtm_server", []):
        sid = object_id(obj)
        for mon in _monitor_refs(obj, set(monitors)):
            graph.edge(servers[sid], monitors[mon], "USES_MONITOR")
    for (sid, vid), nid in virtuals.items():
        obj = next((v for v in datasets.get(f"server_virtuals::{sid}", []) or [] if object_id(v) == vid), {})
        for mon in _monitor_refs(obj, set(monitors)):
            graph.edge(nid, monitors[mon], "USES_MONITOR")
        depends = obj.get("dependsOn") or obj.get("depends-on") or []
        if isinstance(depends, (list, dict, str)):
            for ref in (depends if isinstance(depends, list) else [depends]):
                raw = ref.get("name") or ref.get("fullPath") if isinstance(ref, dict) else ref
                other = canonical(raw, partition_of(vid))
                target = virtuals.get((sid, other))
                if target:
                    graph.edge(nid, target, "DEPENDS_ON")

    # Preserve explicit Data Center -> Prober Pool assignments, including
    # cross-partition dependencies that might otherwise look unreferenced.
    prober_nodes = {node['fullPath']: nid for nid, node in graph.nodes.items()
                    if node['kind'] == 'PROBER_POOL'}
    for obj in datasets.get('gtm_datacenter', []) or []:
        dcid = object_id(obj)
        prober = canonical(obj.get('proberPool') or obj.get('prober-pool'), partition_of(dcid))
        if prober and prober in prober_nodes:
            graph.edge(dcs[dcid], prober_nodes[prober], 'USES_PROBER_POOL')

    # Explicit Topology record fields can name Data Centers, Regions and
    # Servers. Treat these as possible dependencies until the actual tmsh
    # topology expression is verified on the relevant TMOS version.
    target_types = {'datacenter': 'DATA_CENTER', 'region': 'REGION',
                    'proberpool': 'PROBER_POOL', 'server': 'GSLB_SERVER'}
    referenced_targets = {(n['kind'], n['fullPath']): nid for nid, n in graph.nodes.items()}
    for obj in datasets.get('gtm_topology', []) or []:
        source = 'gtm_topology|' + object_id(obj)
        for key, raw in obj.items():
            typ = re.sub('[^a-z]', '', str(key).lower())
            target_kind = target_types.get(typ)
            if not target_kind:
                continue
            values = raw if isinstance(raw, list) else [raw]
            for item in values:
                target = canonical(item, partition_of(object_id(obj)))
                dst = referenced_targets.get((target_kind, target))
                if dst:
                    graph.edge(source, dst, 'TOPOLOGY_OR_DYNAMIC_OBJECT', 'POSSIBLE')

    # Some Topology records may explicitly reference a Pool; only create
    # definite edges when a typed fullPath is found, not substring guesses.
    for source_key in ("gtm_topology", "gtm_rule", "gtm_distributed_app"):
        for obj in datasets.get(source_key, []) or []:
            sid = f"{source_key}|{object_id(obj)}"
            if sid not in graph.nodes:
                continue
            pool_hits = _explicit_pool_refs(obj, all_pools, partition_of(object_id(obj)))
            for target in sorted(pool_hits):
                graph.edge(sid, target, "TOPOLOGY_OR_DYNAMIC_POOL", "POSSIBLE")

    # Orphan evidence is type-specific; NEVER equate no direct edge with
    # a safe-to-delete object. Cross-partition links count normally.
    complete, dynamic, missing = _complete(snap)
    if missing:
        graph.warnings.append(f"Incomplete inventory: {', '.join(missing[:20])}")
    if dynamic:
        graph.warnings.append("GTM rules, topology and/or distributed applications exist: indirect references may be unresolved")
    incoming: dict[str, list[dict[str, str]]] = defaultdict(list)
    for edge in graph.edges:
        incoming[edge["target"]].append(edge)
    active_vs = {edge["target"] for edge in graph.edges if edge["relation"] == "MEMBER_TARGET"}
    active_servers = {edge["target"] for edge in graph.edges if edge["relation"] == "DEFINED_ON"
                      and edge["source"] in active_vs}
    for nid, node in graph.nodes.items():
        kind = node["kind"]
        refs = [e for e in incoming[nid] if e["relation"] in {
            "DIRECT_POOL", "DIRECT_CNAME", "LAST_RESORT", "MEMBER_TARGET",
            "DEFINED_ON", "IN_DATACENTER", "USES_MONITOR", "USES_RULE", "USES_PROBER_POOL",
            "TOPOLOGY_OR_DYNAMIC_POOL", "TOPOLOGY_OR_DYNAMIC_OBJECT", "DEPENDS_ON"}]
        node["referenceCount"] = len(refs)
        node["references"] = [{"source": graph.nodes[x["source"]]["fullPath"],
                                "relation": x["relation"], "certainty": x["certainty"]} for x in refs]
        if kind == "GSLB_SERVER" and nid not in active_servers:
            node["orphanStatus"] = "NO ACTIVE POOL MEMBERS FOUND — REVIEW"
        elif kind == "VIRTUAL_SERVER" and nid not in active_vs:
            node["orphanStatus"] = "NO DIRECT POOL MEMBER REFERENCES"
        elif kind == "WIDE_IP" or kind == "POOL_MEMBER":
            node["orphanStatus"] = "NOT APPLICABLE"
        elif kind == "MONITOR" and (node["partition"] == "/Common" and
                                      (node["name"].lower().replace("-", "_") in MONITOR_BASE
                                       or node["name"].lower() == node["recordType"].lower())):
            node["orphanStatus"] = "SYSTEM/BASE MONITOR — EXCLUDED"
        elif any(x["certainty"] == "EXACT" for x in refs):
            node["orphanStatus"] = "REFERENCED"
        elif refs:
            node["orphanStatus"] = "POSSIBLE INDIRECT REFERENCES"
        elif not complete:
            node["orphanStatus"] = "INVENTORY INCOMPLETE"
        elif dynamic:
            node["orphanStatus"] = "POSSIBLE INDIRECT REFERENCES"
        else:
            node["orphanStatus"] = "NO VERIFIED REFERENCES IN SNAPSHOT"
        # Basic monitor/config evidence is distinct from observed runtime stats.
        node["reviewRequired"] = node["orphanStatus"] not in {
            "REFERENCED", "NOT APPLICABLE", "SYSTEM/BASE MONITOR — EXCLUDED"}
    _calculate_health(graph)

    # Build two branches per partition, preserving *all* inventory items in
    # the audit side when not reachable from any Wide IP chain.
    expansion = {"DIRECT_POOL", "DIRECT_CNAME", "LAST_RESORT", "HAS_MEMBER",
                 "MEMBER_TARGET", "DEFINED_ON", "IN_DATACENTER", "USES_MONITOR", "USES_RULE",
                 "USES_PROBER_POOL", "DEPENDS_ON"}
    children_by_id: dict[str, list[tuple[str, str]]] = defaultdict(list)
    for edge in graph.edges:
        if edge["relation"] in expansion:
            children_by_id[edge["source"]].append((edge["target"], edge["relation"]))
    reached: set[str] = set()

    def tree_entry(nid: str, root_partition: str, visited: frozenset[str],
                   relation: str = "", depth: int = 0) -> dict[str, Any]:
        node = graph.nodes[nid]
        reached.add(nid)
        entry = {"id": nid, "kind": node["kind"], "label": node["name"],
                 "fullPath": node["fullPath"], "partition": node["partition"],
                 "recordType": node["recordType"], "health": node["effectiveHealth"],
                 "relation": relation, "crossPartition": node["partition"] != root_partition,
                 "children": []}
        if depth >= 8 or nid in visited:
            entry["limited"] = True
            return entry
        # Cap per-chain *depth*, not global nodes; preserve all inventory in graph.
        entry["children"] = [tree_entry(other, root_partition, visited | {nid}, typ, depth + 1)
                             for other, typ in sorted(children_by_id.get(nid, []))]
        return entry

    partitions = sorted({n["partition"] for n in graph.nodes.values()})
    forest = []
    for part in partitions:
        entries = [tree_entry(nid, part, frozenset()) for (rr, path), nid in sorted(all_wideips.items())
                   if partition_of(path) == part]
        forest.append({"id": "partition|" + part, "kind": "PARTITION", "label": part,
                       "partition": part, "health": "NOT OBSERVED", "children": [
                           {"id": "branch|live|" + part, "kind": "BRANCH", "label": "Wide IP services",
                            "partition": part, "children": entries},
                           {"id": "branch|audit|" + part, "kind": "BRANCH", "label": "Audit / unlinked objects",
                            "partition": part, "children": []}]})
    for entry in forest:
        part = entry["partition"]
        orphan = [nid for nid, node in sorted(graph.nodes.items())
                  if node["partition"] == part and nid not in reached and node["kind"] != "POOL_MEMBER"]
        entry["children"][1]["children"] = [tree_entry(nid, part, frozenset(), "NOT CONNECTED TO WIDE IP") for nid in orphan]

    version = _sys_version(snap)
    device_label = snap.meta.get("device_hostname") or snap.meta.get("host") or "UNKNOWN"
    report = {
        "schema": "f5auditdns.diagram.v1",
        "metadata": {
            "device": device_label,
            "tmosVersion": version.get("version", "NOT COLLECTED"),
            "tmosBuild": version.get("build", ""),
            "tmosProduct": version.get("product", "BIG-IP"),
            "collectedUTC": snap.meta.get("collected_at") or "",
            "snapshotToolVersion": snap.meta.get("tool_version") or "",
            "scope": snap.meta.get("scope") or "unknown",
            "readOnly": True, "approval": "PENDING",
            "coreAndDynamicInventoryComplete": complete,
            "dynamicReferencesExist": dynamic,
            "missingDatasets": missing,
            "iquery": "Per-server iQuery not inferred; only explicitly reported evidence is displayed",
            "healthCaveat": "Derived statuses are snapshot-only. Missing iQuery/monitor evidence is not treated as offline.",
        },
        "summary": {
            "nodes": len(graph.nodes), "edges": len(graph.edges), "partitions": len(partitions),
            "wideIPs": len(all_wideips), "pools": len(all_pools), "poolMembers": sum(n["kind"] == "POOL_MEMBER" for n in graph.nodes.values()),
            "virtualServers": len(virtuals), "servers": len(servers),
            "reviewObjects": sum(n["reviewRequired"] for n in graph.nodes.values()),
        },
        "nodes": list(graph.nodes.values()), "edges": graph.edges,
        "tree": {"id": "device", "kind": "DEVICE",
                 "label": device_label,
                 "health": "NOT OBSERVED", "children": forest},
        "warnings": list(dict.fromkeys(graph.warnings))[:1000],
    }
    return report


def write_diagram_json(data: dict[str, Any], path: str | Path) -> Path:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(data, ensure_ascii=False, indent=2, default=str), encoding="utf-8")
    return target
