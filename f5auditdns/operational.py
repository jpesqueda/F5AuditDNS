"""Extract named, scoped evidence from iControl REST statistics."""
from __future__ import annotations

from collections import defaultdict
import re
from urllib.parse import unquote, urlsplit

METRICS = {
    "preferred": "Preferred", "alternate": "Alternate", "fallback": "Fallback",
    "dropped": "Dropped", "returnToDns": "Return to DNS", "returnFromDns": "Return from DNS",
    "requests": "Requests", "requests.total": "Requests", "resolutions": "Resolutions",
    "clientside.totConns": "Total connections", "clientside.curConns": "Current connections",
    "clientside.bitsIn": "Bits in", "clientside.bitsOut": "Bits out",
}
STATUS = {"status.availabilityState", "status.enabledState", "status.statusReason"}
IDENTITY = {"tmName", "name", "fullPath", "poolName", "serverName", "virtualServerName", "wideipName"}
KNOWN = STATUS | IDENTITY | METRICS.keys()
HEALTH = {"available": "AVAILABLE", "up": "AVAILABLE", "offline": "OFFLINE",
          "down": "OFFLINE", "unavailable": "UNAVAILABLE", "unknown": "UNKNOWN"}
MISSING = "NOT COLLECTED"


def scalar(value):
    if isinstance(value, dict):
        value = value.get("description", value.get("value"))
    return value if type(value) in (str, int, float) else None


def stats_rows(payload):
    """Flatten nestedStats/entries while preserving the nearest resource identity."""
    rows = []

    def walk(node, url=""):
        if not isinstance(node, dict):
            return
        entries = node.get("entries")
        if isinstance(entries, dict):
            url = node.get("selfLink") or url
            walk(entries, url)
        nested = node.get("nestedStats")
        if isinstance(nested, dict):
            walk(nested, url)
        values = {k: scalar(v) for k, v in node.items() if k in KNOWN}
        values = {k: v for k, v in values.items() if v is not None}
        if values.keys() & (STATUS | METRICS.keys()):
            if isinstance(url, str) and url:
                # Keep only the resource path, not management hosts or query strings.
                values["_resource"] = urlsplit(url).path
            rows.append(values)
        for key, value in node.items():
            if key not in KNOWN and key not in ("entries", "nestedStats") and isinstance(value, dict):
                walk(value, key if "/" in key else url)

    walk(payload)
    return rows


def _normal_name(text, rr=""):
    name = str(text or "").strip()
    if rr and name.upper().endswith(":" + rr.upper()):
        name = name[:-(len(rr) + 1)]
    if "~" in name:
        name = name.replace("~", "/")
    return name


def _resource_name(row):
    parts = row.get("_resource", "").rstrip("/").split("/")
    if len(parts) >= 2 and parts[-1] == "stats":
        return unquote(parts[-2])
    return ""


class StatsIndex:
    """Return no metrics for ambiguous identities or for an unobserved object."""

    def __init__(self, snapshot):
        self.snapshot = snapshot
        self.cache = {}

    def _dataset(self, key, rr):
        idx = defaultdict(list)
        rows = self.snapshot.datasets.get(key, [])
        if isinstance(rows, dict):
            rows = stats_rows(rows)
        for row in rows if isinstance(rows, list) else ():
            if not isinstance(row, dict):
                continue
            names = {_normal_name(row.get(field), rr) for field in ("tmName", "fullPath", "name")}
            names.add(_normal_name(_resource_name(row), rr))
            server, vs = row.get("serverName"), row.get("virtualServerName")
            if server and vs:
                names.add(_normal_name(server) + ":" + _normal_name(vs))
            if vs and key.startswith("stats_server_virtuals::"):
                names.add(_normal_name(vs))
            for field, prefix in (("poolName", "stats_pool_"), ("wideipName", "stats_wideip_"),
                                  ("serverName", "stats_server")):
                if (key.startswith(prefix) and "::" not in key and row.get(field)):
                    names.add(_normal_name(row[field], rr))
            for name in names - {""}:
                idx[name].append(row)
        return idx

    def lookup(self, key, name, rr="", aliases=()):
        cache_key = (key, rr)
        if cache_key not in self.cache:
            self.cache[cache_key] = self._dataset(key, rr)
        index = self.cache[cache_key]
        names = {_normal_name(value, rr) for value in (name, *aliases)} - {""}
        matches = {id(row): row for alias in names for row in index.get(alias, ())}
        state = self.snapshot.meta.get("endpoint_results", {}).get(key)
        if len(matches) == 1:
            return next(iter(matches.values())), "REST /stats"
        if len(matches) > 1:
            return {}, "AMBIGUOUS STATS"
        return {}, "NO OBJECT STATS" if state == "OK" else (state or MISSING)

    def columns(self, keys, name, config="", rr="", aliases=()):
        # A collection query can be unavailable on older TMOS; a per-resource
        # query may still be supported. Never mix conflicting rows.
        fields, source = self.lookup(keys[0], name, rr, aliases)
        observed_key = keys[0]
        for key in keys[1:]:
            if fields or source == "AMBIGUOUS STATS":
                break
            if key in self.snapshot.meta.get("endpoint_results", {}) or key in self.snapshot.datasets:
                fields, source = self.lookup(key, name, rr, aliases)
                observed_key = key
        return operational_columns(fields, source, config,
                                   self.snapshot.meta.get("stats_collected_at", {}).get(observed_key, ""))


def operational_columns(fields, source, config="", timestamp=""):
    raw = str(fields.get("status.availabilityState") or "").strip()
    availability = HEALTH.get(raw.lower(), raw.upper()) if raw else ""
    enabled = str(fields.get("status.enabledState") or "").strip()
    disabled = config == "DISABLED" or enabled.lower().startswith(("disabled", "forced-disabled"))
    status = "DISABLED" if disabled else (availability or "NOT OBSERVED")
    columns = {
        "Health": status,
        "Availability": availability,
        "Operational State": enabled.upper(),
        "Status Reason": fields.get("status.statusReason", ""),
        "Health Source": source,
        "Stats UTC": timestamp if fields else "",
    }
    for key, title in METRICS.items():
        metric = fields.get(key)
        if isinstance(metric, str) and re.fullmatch(r"[0-9]+", metric):
            metric = int(metric)
        if type(metric) in (int, float) and metric >= 0:
            columns[title] = metric
    return columns
