"""Generate a fully simulated BIG-IP DNS snapshot; no device access needed."""
from pathlib import Path
from uuid import uuid4
from datetime import datetime, timezone

from f5auditdns.collector import Snapshot, RECORD_TYPES, now

out = Path(__file__).with_name("raw_simulado")
if any(out.iterdir()):
    raise SystemExit(f"{out} must be empty; avoid overwriting previous evidence")

datasets = {
    "gtm_datacenter": [
        {"name": "DC_GDL", "partition": "Common", "fullPath": "/Common/DC_GDL", "enabled": True},
        {"name": "DC_QRO", "partition": "Common", "fullPath": "/Common/DC_QRO", "enabled": True},
    ],
    "gtm_server": [
        {"name": "GDL-F5", "partition": "Common", "fullPath": "/Common/GDL-F5", "datacenter": "/Common/DC_GDL", "product": "bigip", "enabled": True},
        {"name": "QRO-F5", "partition": "Common", "fullPath": "/Common/QRO-F5", "datacenter": "/Common/DC_QRO", "product": "bigip", "enabled": True},
    ],
    "server_virtuals::/Common/GDL-F5": [
        {"name": "vs_app", "fullPath": "/Common/vs_app", "destination": "192.0.2.100:443", "enabled": True},
    ],
    "server_virtuals::/Common/QRO-F5": [
        {"name": "vs_app", "fullPath": "/Common/vs_app", "destination": "198.51.100.100:443", "enabled": True},
    ],
    "gtm_wideip_a": [
        {"name": "app.empresa.example", "partition": "Common", "fullPath": "/Common/app.empresa.example", "enabled": True,
         "lastResortPool": "/Common/pool_fallback"},
        {"name": "old.empresa.example", "partition": "Common", "fullPath": "/Common/old.empresa.example", "disabled": True},
    ],
    "wideip_pools::a::/Common/app.empresa.example": [{"name": "pool_app", "partition": "Common"}],
    "wideip_pools::a::/Common/old.empresa.example": [],
    "gtm_pool_a": [
        {"name": "pool_app", "partition": "Common", "fullPath": "/Common/pool_app", "enabled": True,
         "loadBalancingMode": "round-robin"},
        {"name": "pool_dormant", "partition": "Common", "fullPath": "/Common/pool_dormant", "enabled": True,
         "loadBalancingMode": "global-availability"},
    ],
    "pool_members::a::/Common/pool_app": [
        {"name": "/Common/GDL-F5:/Common/vs_app", "enabled": True},
        {"name": "/Common/QRO-F5:/Common/vs_app", "enabled": True},
    ],
    "pool_members::a::/Common/pool_dormant": [],
    "gtm_pool_cname": [{"name": "pool_fallback", "partition": "Common", "fullPath": "/Common/pool_fallback", "enabled": True}],
    "pool_members::cname::/Common/pool_fallback": [],
    "gtm_rule": [], "gtm_distributed_app": [],
    "gtm_listener": [{"name": "dns-udp", "partition": "Common", "address": "203.0.113.53", "port": 53, "ipProtocol": "udp"}],
    "gtm_topology": [], "gtm_region": [], "gtm_prober_pool": [],
}
for rr in RECORD_TYPES:
    datasets.setdefault(f"gtm_wideip_{rr}", [])
    datasets.setdefault(f"gtm_pool_{rr}", [])
    for w in datasets[f"gtm_wideip_{rr}"]:
        datasets.setdefault(f"wideip_pools::{rr}::{w['fullPath']}", [])
    for p in datasets[f"gtm_pool_{rr}"]:
        datasets.setdefault(f"pool_members::{rr}::{p['fullPath']}", [])

# Sample is intentionally a synthetic snapshot, not a report of real device state.
meta = {
    "tool": "f5auditdns", "schema_version": 1, "tool_version": "0.1.0",
    "collection_id": str(uuid4()), "host": "SIMULATED-DNS-01", "collected_at": now(),
    "scope": "all", "endpoint_results": {k: "OK" for k in datasets},
    "endpoint_paths": {k: "SIMULATED" for k in datasets}, "warnings": [],
    "sample_data": True,
}
snap = Snapshot(meta)
snap.datasets = datasets
snap.write(out)
print(f"Simulated snapshot generated at {out}")
