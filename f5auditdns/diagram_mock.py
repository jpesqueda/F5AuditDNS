"""Fully synthetic, offline GSLB fixture for demoing the diagram mode.

Documentation IP ranges only (RFC 5737). Not a real BIG-IP inventory.
"""
from __future__ import annotations

from uuid import uuid4

from . import __version__
from .collector import RECORD_TYPES, Snapshot


def mock_snapshot() -> Snapshot:
    """Return a multi-partition mock with cross-partition references and failover."""
    snap = Snapshot({
        "tool": "f5auditdns", "schema_version": 1, "tool_version": __version__,
        "collection_id": str(uuid4()), "host": "dns01.example.test",
        "device_hostname": "dns01.example.test", "collected_at": "2026-11-24T12:00:00+00:00",
        "scope": "all", "endpoint_results": {}, "endpoint_paths": {},
        "stats_collected_at": {}, "operational_stats": "SKIPPED", "warnings": [],
    })
    def store(key, data):
        snap.datasets[key] = data
        snap.meta["endpoint_results"][key] = "OK"
    store("sys_version", {"entries": {"0": {"nestedStats": {"entries": {
        "Version": {"description": "17.5.1"},
        "Build": {"description": "0.0.1"},
        "Product": {"description": "BIG-IP"}}}}}})
    store("gtm_datacenter", [
        {"fullPath": "/Common/DC_PRIMARY", "name": "DC_PRIMARY", "partition": "Common"},
        {"fullPath": "/DMZ_Externo/DC_BACKUP", "name": "DC_BACKUP", "partition": "DMZ_Externo"},
        {"fullPath": "/Common/DC_UNUSED", "name": "DC_UNUSED", "partition": "Common"},
    ])
    store("gtm_server", [
        {"fullPath": "/Common/LTM_PRIMARY", "name": "LTM_PRIMARY", "partition": "Common",
         "datacenter": "/Common/DC_PRIMARY", "product": "bigip", "virtualServerDiscovery": "disabled",
         "status": {"availabilityState": "available", "statusReason": "Service up"}},
        {"fullPath": "/DMZ_Externo/LTM_DR", "name": "LTM_DR", "partition": "DMZ_Externo",
         "datacenter": "/DMZ_Externo/DC_BACKUP", "product": "bigip", "virtualServerDiscovery": "enabled",
         "status": {"availabilityState": "offline", "statusReason": "Monitor reported down (iQuery not verified)"}},
    ])
    store("server_virtuals::/Common/LTM_PRIMARY", [
        {"fullPath": "/Common/vs_web", "name": "vs_web", "partition": "Common",
         "destination": "/Common/192.0.2.10:443", "monitor": "/Common/tcp_443",
         "status": {"availabilityState": "available"}},
        {"fullPath": "/Common/vs_admin", "name": "vs_admin", "partition": "Common",
         "destination": "/Common/192.0.2.20:8443", "status": {"availabilityState": "available"}},
    ])
    store("server_virtuals::/DMZ_Externo/LTM_DR", [
        {"fullPath": "/DMZ_Externo/vs_web_dr", "name": "vs_web_dr", "partition": "DMZ_Externo",
         "destination": "/Common/198.51.100.10:443", "monitor": "/Common/tcp_443",
         "status": {"availabilityState": "offline"}},
    ])
    pool1 = {"fullPath": "/Prod_GSLB/pool_web", "name": "pool_web", "partition": "Prod_GSLB",
             "monitor": "/Common/tcp_443", "loadBalancingMode": "round-robin", "enabled": True}
    pool2 = {"fullPath": "/Prod_GSLB/pool_dr", "name": "pool_dr", "partition": "Prod_GSLB",
             "loadBalancingMode": "global-availability", "enabled": True}
    pool3 = {"fullPath": "/Common/pool_unused", "name": "pool_unused", "partition": "Common",
             "enabled": True}
    store("gtm_pool_a", [pool1, pool2, pool3])
    store("pool_members::a::/Prod_GSLB/pool_web", [
        {"fullPath": "/Common/LTM_PRIMARY:/Common/vs_web", "enabled": True,
         "status": {"availabilityState": "available"}},
        {"fullPath": "/DMZ_Externo/LTM_DR:/DMZ_Externo/vs_web_dr", "enabled": True,
         "status": {"availabilityState": "offline"}},
    ])
    store("pool_members::a::/Prod_GSLB/pool_dr", [
        {"fullPath": "/DMZ_Externo/LTM_DR:/DMZ_Externo/vs_web_dr", "enabled": True,
         "status": {"availabilityState": "offline"}},
    ])
    store("pool_members::a::/Common/pool_unused", [])
    wideip = {"fullPath": "/Prod_GSLB/www.example.test", "name": "www.example.test",
              "partition": "Prod_GSLB", "lastResortPool": "/Prod_GSLB/pool_dr",
              "enabled": True}
    store("gtm_wideip_a", [wideip])
    store("wideip_pools::a::/Prod_GSLB/www.example.test", [
        {"fullPath": "/Prod_GSLB/pool_web"}])
    for rr in RECORD_TYPES:
        if rr != "a":
            store(f"gtm_pool_{rr}", [])
            store(f"gtm_wideip_{rr}", [])
    store("gtm_monitor_tcp", [{"fullPath": "/Common/tcp_443", "name": "tcp_443",
                                "partition": "Common", "defaultsFrom": "/Common/tcp"},
                               {"fullPath": "/Common/custom_unused", "name": "custom_unused",
                                "partition": "Common"}])
    for key in ("gtm_rule", "gtm_topology", "gtm_distributed_app", "gtm_region",
                "gtm_prober_pool", "gtm_listener"):
        store(key, [])
    return snap
