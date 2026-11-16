"""Collect BIG-IP DNS GSLB configuration into a versioned, offline JSON snapshot.

Only iControl REST GET requests are used for configuration collection.  Authentication
uses the login endpoint provided by F5ReadOnlyClient (one POST for token issuance).
Incomplete/denied endpoints are explicitly recorded; never synthesize empty data.
"""
from __future__ import annotations

import json
import logging
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlsplit
from uuid import uuid4

from .client import F5APIError, F5ClientError, F5ReadOnlyClient
from . import __version__
from .operational import stats_rows

log = logging.getLogger("f5auditdns.collector")
RECORD_TYPES = ("a", "aaaa", "cname", "mx", "naptr", "srv")
MONITOR_TYPES = ("http", "https", "tcp", "tcp-half-open", "udp", "gateway-icmp", "bigip", "external")
# Some monitor types (notably 'dns') may not be supported in a given version.
CORE_PATHS = {
    "gtm_datacenter": "/mgmt/tm/gtm/datacenter",
    "gtm_server": "/mgmt/tm/gtm/server",
}
OPTIONAL_PATHS = {
    "gtm_listener": "/mgmt/tm/gtm/listener",
    "gtm_topology": "/mgmt/tm/gtm/topology",
    "gtm_region": "/mgmt/tm/gtm/region",
    "gtm_prober_pool": "/mgmt/tm/gtm/prober-pool",
    "gtm_rule": "/mgmt/tm/gtm/rule",
    "gtm_distributed_app": "/mgmt/tm/gtm/distributed-app",
}


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def object_id(obj: dict[str, Any]) -> str:
    """Return canonical identifier using partition, name, and optional subpath."""
    if obj.get("fullPath"):
        p = str(obj["fullPath"])
        return p if p.startswith("/") else "/" + p
    partition = obj.get("partition") or obj.get("tmPartition") or "Common"
    sub = str(obj.get("subPath") or "").strip("/")
    name = str(obj.get("name") or "").lstrip("/")
    return "/" + "/".join(str(s) for s in (partition, sub, name) if s)


def safe_api_path(link: str) -> str | None:
    """Extract the relative management path from an F5 subcollection link.

    Explicitly discard the hostname to prevent credentials being sent to an
    attacker-controlled URL returned by a compromised endpoint.
    """
    path = urlsplit(link).path
    return path if path.startswith("/mgmt/tm/gtm/") else None


def inline_items(obj: dict[str, Any], name: str) -> list[dict[str, Any]] | None:
    """Read an embedded array or expanded REST subcollection; None means unknown."""
    api_name = "virtual-servers" if name == "virtualServers" else name
    direct = obj.get(name, obj.get(api_name))
    if isinstance(direct, list):
        return [x if isinstance(x, dict) else {"name": str(x)} for x in direct]
    ref = obj.get(name + "Reference", obj.get(api_name + "Reference"))
    if isinstance(ref, dict) and isinstance(ref.get("items"), list):
        return [x if isinstance(x, dict) else {"name": str(x)} for x in ref["items"]]
    return None


def _for_disk(value: Any, dataset: str) -> Any:
    """Drop credential fields and opaque content not required for DNS audits."""
    if isinstance(value, list):
        return [_for_disk(item, dataset) for item in value]
    if not isinstance(value, dict):
        return value
    out = {}
    for key, item in value.items():
        name = re.sub("[^a-z0-9]", "", str(key).lower())
        if (any(word in name for word in ("password", "passphrase", "credential", "privatekey",
                                           "authtoken", "authkey", "apikey", "secret"))
                or name in {"authorization", "cookie", "setcookie", "token", "community", "username", "send", "sendstring"}
                or (dataset == "gtm_rule" and name in {"apianonymous", "definition", "script", "rule"})):
            continue
        out[key] = _for_disk(item, dataset)
    return out


class SnapshotError(Exception):
    """Snapshot missing, corrupted, or incompatible with this program."""


class Snapshot:
    """In-memory collection with disk persistence of individual datasets."""

    def __init__(self, meta: dict[str, Any] | None = None):
        self.meta: dict[str, Any] = meta or {}
        self.datasets: dict[str, Any] = {}

    def write(self, directory: str | Path) -> None:
        path = Path(directory)
        path.mkdir(parents=True, exist_ok=True)
        existing = list(path.iterdir())
        if existing:
            raise SnapshotError(f"Destination not empty: {path}. Use a new --save-raw directory.")
        (path / "_meta.json").write_text(json.dumps(self.meta, indent=2), encoding="utf-8")
        for n, (key, data) in enumerate(sorted(self.datasets.items())):
            name = re.sub(r"[^a-zA-Z0-9._-]", "_", key)
            (path / f"{n:04d}_{name}.json").write_text(
                json.dumps({"collection_id": self.meta.get("collection_id"), "key": key, "data": _for_disk(data, key)}, indent=2),
                encoding="utf-8",
            )

    @classmethod
    def read(cls, directory: str | Path) -> "Snapshot":
        folder = Path(directory)
        try:
            meta = json.loads((folder / "_meta.json").read_text(encoding="utf-8"))
        except (FileNotFoundError, ValueError) as exc:
            raise SnapshotError(f"Invalid snapshot metadata in {folder}") from exc
        if meta.get("tool") != "f5auditdns" or not meta.get("collection_id"):
            raise SnapshotError("Snapshot was not created by F5AuditDNS or has no collection_id.")
        snap = cls(meta)
        for file in folder.glob("*.json"):
            if file.name == "_meta.json":
                continue
            try:
                payload = json.loads(file.read_text(encoding="utf-8"))
                if payload.get("collection_id") != meta["collection_id"]:
                    raise SnapshotError(f"Mixed or corrupted snapshots: {file.name}")
                key = payload["key"]
                if key in snap.datasets:
                    raise SnapshotError(f"Duplicate snapshot dataset key: {key}")
                snap.datasets[key] = payload["data"]
            except (ValueError, KeyError) as exc:
                raise SnapshotError(f"Invalid dataset in {file.name}") from exc
        # A missing dataset must be identified rather than silently treated as empty.
        expected = {k for k, v in meta.get("endpoint_results", {}).items() if v == "OK"}
        missing = expected - snap.datasets.keys()
        if missing:
            raise SnapshotError(f"Dataset files missing for {sorted(missing)[:5]}")
        return snap


class Collector:
    """Read GSLB configuration and relevant subcollections from a BIG-IP."""

    def __init__(self, client: F5ReadOnlyClient, host: str, scope: str = "all", *, collect_stats: bool = True):
        if scope not in ("core", "all"):
            raise ValueError("scope must be core or all")
        self.client, self.scope = client, scope
        self.collect_stats = collect_stats
        self._details_cache: dict[str, dict[str, Any] | None] = {}
        self.snapshot = Snapshot({
            "tool": "f5auditdns", "schema_version": 1, "tool_version": __version__,
            "collection_id": str(uuid4()), "host": host, "collected_at": now(),
            "scope": scope, "endpoint_results": {}, "endpoint_paths": {},
            "warnings": [], "stats_collected_at": {},
            "operational_stats": "ENABLED" if collect_stats else "SKIPPED",
        })

    def _get(self, key: str, path: str, *, collection: bool = True, optional: bool = False,
             params: dict[str, Any] | None = None) -> Any | None:
        if key in self.snapshot.meta["endpoint_results"]:
            return self.snapshot.datasets.get(key)
        try:
            data = self.client.get_collection(path, params=params) if collection else self.client.get(path, params=params)
        except F5APIError as exc:
            status = f"HTTP_{exc.status_code}"
            self.snapshot.meta["endpoint_results"][key] = status
            self.snapshot.meta["endpoint_paths"][key] = path
            self.snapshot.meta["warnings"].append(f"{key}: {status} ({path})")
            log.warning("Cannot collect %s: %s", key, status)
            return None
        self.snapshot.meta["endpoint_results"][key] = "OK"
        self.snapshot.meta["endpoint_paths"][key] = path
        self.snapshot.datasets[key] = data
        log.info("Collected %-38s %d objects", key, len(data) if isinstance(data, list) else 1)
        return data

    def _subcollection(self, parent: dict[str, Any], field: str, key: str) -> None:
        embedded = inline_items(parent, field)
        # Collection items often omit subcollections. Load the expanded detail
        # once before treating an absent relationship as unknown.
        api_field = "virtual-servers" if field == "virtualServers" else field
        ref = parent.get(field + "Reference", parent.get(api_field + "Reference"))
        if embedded is None and not (isinstance(ref, dict) and ref.get("link")):
            detail_path = safe_api_path(str(parent.get("selfLink") or ""))
            if detail_path:
                if detail_path not in self._details_cache:
                    detail_key = "detail::" + detail_path
                    obj = self._get(detail_key, detail_path, collection=False,
                                    params={"expandSubcollections": "true"})
                    self._details_cache[detail_path] = obj if isinstance(obj, dict) else None
                detail = self._details_cache[detail_path]
                if detail:
                    embedded = inline_items(detail, field)
                    ref = detail.get(field + "Reference", detail.get(api_field + "Reference"))
        if embedded is not None:
            self.snapshot.datasets[key] = embedded
            self.snapshot.meta["endpoint_results"][key] = "OK"
            self.snapshot.meta["endpoint_paths"][key] = "embedded"
            return
        if isinstance(ref, dict) and ref.get("link"):
            path = safe_api_path(str(ref["link"]))
            if path:
                self._get(key, path)
                return
        # Field absent is **not** the same as an empty association.
        self.snapshot.meta["endpoint_results"][key] = "UNKNOWN"
        self.snapshot.meta["endpoint_paths"][key] = "not advertised by API"
        self.snapshot.meta["warnings"].append(f"{key}: subcollection not present; treated as UNKNOWN")

    def _stats(self, key: str, path: str) -> str:
        """Stats errors never turn a working configuration inventory into a failed collect."""
        meta = self.snapshot.meta
        try:
            payload = self.client.get(path)
            if not isinstance(payload, dict) or not any(k in payload for k in ("entries", "nestedStats", "items")):
                state = "UNRECOGNIZED STATS"
            else:
                rows = stats_rows(payload)
                self.snapshot.datasets[key] = rows
                state = "OK"
        except F5APIError as exc:
            state = f"HTTP_{exc.status_code}"
        except F5ClientError:
            state = "REQUEST FAILED"
        meta["endpoint_results"][key] = state
        meta["endpoint_paths"][key] = path
        meta["stats_collected_at"][key] = now()
        if state != "OK":
            log.info("Operational stats unavailable for %s: %s", key, state)
        return state

    @staticmethod
    def _resource_path(base: str, obj: dict[str, Any]) -> str:
        link = safe_api_path(str(obj.get("selfLink") or ""))
        if link and link.startswith(base + "/") and "/" not in link[len(base) + 1:].rstrip("/"):
            return link.rstrip("/")
        encoded = "~" + "~".join(quote(part, safe=":") for part in object_id(obj).strip("/").split("/"))
        return base + "/" + encoded

    def _collect_operational(self) -> None:
        data = self.snapshot.datasets
        for family in ("datacenter", "server"):
            if data.get("gtm_" + family):
                self._stats("stats_" + family, f"/mgmt/tm/gtm/{family}/stats")
        for rr in RECORD_TYPES:
            for family in ("wideip", "pool"):
                objects = data.get(f"gtm_{family}_{rr}", [])
                if not objects:
                    continue
                base = f"/mgmt/tm/gtm/{family}/{rr}"
                state = self._stats(f"stats_{family}_{rr}", base + "/stats")
                # Older TMOS can support an individual pool stats resource even
                # when the typed collection does not provide statistics.
                if family == "pool" and (state in ("HTTP_400", "HTTP_404", "HTTP_405", "HTTP_501", "UNRECOGNIZED STATS")
                                         or (state == "OK" and not data.get(f"stats_pool_{rr}"))):
                    for obj in objects:
                        self._stats(f"stats_pool_{rr}::{object_id(obj)}", self._resource_path(base, obj) + "/stats")
            for pool in data.get(f"gtm_pool_{rr}", []):
                pid = object_id(pool)
                if data.get(f"pool_members::{rr}::{pid}"):
                    base = self._resource_path(f"/mgmt/tm/gtm/pool/{rr}", pool)
                    self._stats(f"stats_pool_members::{rr}::{pid}", base + "/members/stats")
        for server in data.get("gtm_server", []):
            sid = object_id(server)
            if data.get(f"server_virtuals::{sid}"):
                base = self._resource_path("/mgmt/tm/gtm/server", server)
                self._stats(f"stats_server_virtuals::{sid}", base + "/virtual-servers/stats")

    def collect(self) -> Snapshot:
        # If the management connection fails during a long collection, retain
        # successfully collected datasets and explicitly flag the interruption.
        try:
            self._get("sys_version", "/mgmt/tm/sys/version", collection=False, optional=True)
            self._get("gtm_datacenter", CORE_PATHS["gtm_datacenter"])
            servers = self._get("gtm_server", CORE_PATHS["gtm_server"])
            for record_type in RECORD_TYPES:
                wkey, pkey = f"gtm_wideip_{record_type}", f"gtm_pool_{record_type}"
                wideips = self._get(wkey, f"/mgmt/tm/gtm/wideip/{record_type}")
                pools = self._get(pkey, f"/mgmt/tm/gtm/pool/{record_type}")
                for w in wideips or []:
                    wid = object_id(w)
                    self._subcollection(w, "pools", f"wideip_pools::{record_type}::{wid}")
                    if "poolsCname" in w or "poolsCnameReference" in w:
                        self._subcollection(w, "poolsCname", f"wideip_pools_cname::{record_type}::{wid}")
                for p in pools or []:
                    self._subcollection(p, "members", f"pool_members::{record_type}::{object_id(p)}")
            for s in servers or []:
                self._subcollection(s, "virtualServers", f"server_virtuals::{object_id(s)}")
            if self.scope == "all":
                for key, path in OPTIONAL_PATHS.items():
                    self._get(key, path, optional=True)
                for mon in MONITOR_TYPES:
                    self._get(f"gtm_monitor_{mon}", f"/mgmt/tm/gtm/monitor/{mon}", optional=True)
            if self.collect_stats:
                self._collect_operational()
        except F5ClientError as exc:
            self.snapshot.meta["aborted"] = type(exc).__name__
            self.snapshot.meta["warnings"].append(
                "Collection was interrupted; already collected datasets were retained"
            )
            log.error("Collection interrupted; partial snapshot will be retained: %s", type(exc).__name__)
        finally:
            self.snapshot.meta["finished_at"] = now()
            self.snapshot.meta["success_count"] = sum(
                v == "OK" for v in self.snapshot.meta["endpoint_results"].values()
            )
            self.snapshot.meta["warning_count"] = (
                sum(v != "OK" for k, v in self.snapshot.meta["endpoint_results"].items() if not k.startswith("stats_"))
                + int(bool(self.snapshot.meta.get("aborted")))
            )
        return self.snapshot


def validate(client: F5ReadOnlyClient) -> list[tuple[str, str, int]]:
    """Probe representative DNS endpoints without collecting the full inventory."""
    probes = ["/mgmt/tm/sys/version", "/mgmt/tm/gtm/datacenter", "/mgmt/tm/gtm/server",
              "/mgmt/tm/gtm/wideip/a", "/mgmt/tm/gtm/pool/a"]
    rows: list[tuple[str, str, int]] = []
    for path in probes:
        try:
            client.get(path, params={"$top": 1})
            rows.append((path, "OK", 200))
        except F5APIError as exc:
            rows.append((path, "ERROR", exc.status_code))
    return rows
