"""Generate fictional DNS and LTM snapshots demonstrating cleanup comparisons.

Run from project root: python examples/create_cleanup_demo.py
No network access required. No private infrastructure details.
"""
from __future__ import annotations

import json
from pathlib import Path

from f5auditdns.collector import Snapshot

ROOT = Path(__file__).resolve().parent
source = Snapshot.read(ROOT / "raw_simulado")
source.meta["collection_id"] = "simulated-dns-cleanup-2026-v02"
source.meta["host"] = "dns01.example.test"
source.meta["device_hostname"] = "dns01.example.test"
source.meta["collected_at"] = "2026-11-11T20:05:00+00:00"
source.datasets["gtm_server"][0]["virtualServerDiscovery"] = "disabled"
source.datasets["server_virtuals::/Common/GDL-F5"].append({
    "name": "vs_retired", "fullPath": "/Common/vs_retired",
    "destination": "192.0.2.200:443", "enabled": True,
})
source.datasets["gtm_pool_a"].extend([
    {"name": "pool_retired", "fullPath": "/Common/pool_retired", "enabled": True,
     "loadBalancingMode": "round-robin"},
    {"name": "pool_orphan", "fullPath": "/Common/pool_orphan", "enabled": False,
     "loadBalancingMode": "round-robin"},
])
source.datasets["pool_members::a::/Common/pool_retired"] = [
    {"name": "/Common/GDL-F5:/Common/vs_retired", "enabled": True, "ratio": 1},
]
source.datasets["pool_members::a::/Common/pool_orphan"] = []
source.datasets["gtm_wideip_a"].append({
    "name": "retired.example.test", "fullPath": "/Common/retired.example.test", "enabled": True,
})
source.datasets["wideip_pools::a::/Common/retired.example.test"] = [{
    "name": "pool_retired", "partition": "Common"
}]
for key in ["pool_members::a::/Common/pool_retired", "pool_members::a::/Common/pool_orphan",
            "wideip_pools::a::/Common/retired.example.test"]:
    source.meta["endpoint_results"][key] = "OK"
    source.meta["endpoint_paths"][key] = "simulated"
source.meta["success_count"] = sum(x == "OK" for x in source.meta["endpoint_results"].values())
source.meta["warning_count"] = sum(x != "OK" for x in source.meta["endpoint_results"].values())
source.write(ROOT / "raw_cleanup_simulado")

ltm = ROOT / "ltm_raw_gdl_simulado"
ltm.mkdir(exist_ok=True)
(ltm / "_meta.json").write_text(json.dumps({
    "host": "ltm-gdl.example.test", "collected_at": "2026-11-11T20:05:00+00:00",
    "aborted": None, "denied": [], "missing_endpoints": []
}, indent=2), encoding="utf-8")
(ltm / "auth_partition.json").write_text(json.dumps({
    "key": "auth_partition", "data": [{"name": "Common"}]
}, indent=2), encoding="utf-8")
(ltm / "ltm_virtual@Common.json").write_text(json.dumps({
    "key": "ltm_virtual@Common", "data": [
        {"fullPath": "/Common/vs_app", "partition": "Common", "destination": "/Common/192.0.2.100:443"}
    ]
}, indent=2), encoding="utf-8")
print("Generated fictional GSLB and LTM raw snapshots.")
