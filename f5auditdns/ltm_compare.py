"""Read F5Audit LTM (v0.7.x) offline snapshots for explicit GSLB comparisons.

Comparisons require an explicit GSLB Server -> LTM snapshot mapping. Never
assume that similarly named appliances, VIPs or management addresses are the
same physical device, and never interpret an incomplete dataset as absence.
"""
from __future__ import annotations

import json
import re
from collections import defaultdict
from dataclasses import dataclass, field
from functools import cached_property
from pathlib import Path
from typing import Any

from .destination import parse_destination
from .operational import stats_rows, operational_columns


class LtmSnapshotError(ValueError):
    """The LTM snapshot is incomplete or not in the expected F5Audit format."""


def canonical(name: Any, partition: str = "Common") -> str:
    text = str(name or "").strip()
    return text if text.startswith("/") else f"/{partition}/{text}"


def endpoint(value: Any) -> str:
    """Remove only an optional BIG-IP partition prefix from a destination.

    Unlike DNS, an LTM virtual destination often looks like
    /Common/192.0.2.20:443. Route domains are intentionally preserved.
    """
    text = str(value or "").strip()
    if text.startswith("/") and "/" in text[1:]:
        text = text.rsplit("/", 1)[-1]
    return text.lower()


@dataclass
class LtmVirtual:
    full_path: str
    destination: str
    port: Any = None

    @cached_property
    def parsed(self):
        return parse_destination(self.destination, self.port)


@dataclass
class LtmInventory:
    host: str
    timestamp: str
    directory: str
    virtuals: list[LtmVirtual]
    partitions: set[str]
    role: str = "UNKNOWN"
    stats: dict[str, dict] = field(default_factory=dict)

    @classmethod
    def load(cls, directory: str | Path) -> "LtmInventory":
        folder = Path(directory)
        meta_file = folder / "_meta.json"
        if not meta_file.is_file():
            raise LtmSnapshotError(f"LTM snapshot not found: {meta_file}")
        try:
            meta = json.loads(meta_file.read_text(encoding="utf-8"))
        except (ValueError, OSError) as exc:
            raise LtmSnapshotError(f"Invalid LTM snapshot metadata: {meta_file}") from exc
        if not isinstance(meta, dict) or "collected_at" not in meta:
            raise LtmSnapshotError(f"Not an F5Audit LTM raw snapshot: {folder}")
        if meta.get("aborted"):
            raise LtmSnapshotError("F5Audit LTM collection was interrupted; cannot prove absence")
        if any("/mgmt/tm/ltm/virtual" in str(x.get("endpoint", ""))
               for x in meta.get("denied", []) if isinstance(x, dict)):
            raise LtmSnapshotError("F5Audit LTM virtual inventory access was denied")
        if any("/mgmt/tm/ltm/virtual" in str(p) for p in meta.get("missing_endpoints", [])):
            raise LtmSnapshotError("F5Audit LTM virtual inventory endpoint missing")
        virtuals = []
        partitions = set()
        for file in sorted(folder.glob("ltm_virtual@*.json")):
            try:
                payload = json.loads(file.read_text(encoding="utf-8"))
            except (ValueError, OSError) as exc:
                raise LtmSnapshotError(f"Invalid LTM virtual dataset {file.name}") from exc
            if payload.get("key") != file.stem or not isinstance(payload.get("data"), list):
                raise LtmSnapshotError(f"Invalid LTM virtual dataset format {file.name}")
            partition = file.stem.partition("@")[2]
            partitions.add(partition)
            for row in payload["data"]:
                if not isinstance(row, dict):
                    raise LtmSnapshotError(f"Invalid LTM virtual record in {file.name}")
                full_path = canonical(row.get("fullPath") or row.get("name"), str(row.get("partition") or partition))
                virtuals.append(LtmVirtual(full_path, endpoint(row.get("destination")), row.get("port")))
        if not partitions:
            raise LtmSnapshotError(f"No LTM virtual datasets in {folder}; cannot prove absence")
        # A successful, complete auth/partition collection is required to make
        # negative findings across all partitions, not only /Common.
        auth_file = folder / "auth_partition.json"
        if not auth_file.is_file():
            raise LtmSnapshotError("Missing auth_partition.json; LTM inventory may omit partitions")
        try:
            auth_data = json.loads(auth_file.read_text(encoding="utf-8"))["data"]
            required = {p["name"] for p in auth_data if isinstance(p, dict) and p.get("name")}
        except (ValueError, KeyError, TypeError) as exc:
            raise LtmSnapshotError("Invalid LTM partition inventory") from exc
        if not required or not required.issubset(partitions):
            raise LtmSnapshotError("LTM snapshot does not cover every authorized partition")
        def optional_data(filename):
            try:
                return json.loads((folder / filename).read_text(encoding="utf-8")).get("data")
            except (ValueError, AttributeError, OSError):
                return None

        failover = optional_data("sys_failover.json")
        raw_role = failover.get("apiRawValues", {}) if isinstance(failover, dict) else {}
        role_match = re.search(r"\bFailover\s+(active|standby)\b",
                               str(raw_role.get("apiAnonymous", "")) if isinstance(raw_role, dict) else "", re.I)
        role = role_match[1].upper() if role_match else "UNKNOWN"
        by_name = defaultdict(list)
        for row in stats_rows(optional_data("ltm_virtual_stats.json")):
            name = row.get("tmName")
            if isinstance(name, str) and name.startswith("/"):
                by_name[name].append(row)
        stats = {name: rows[0] for name, rows in by_name.items() if len(rows) == 1}
        return cls(str(meta.get("host") or ""), str(meta["collected_at"]), str(folder),
                   virtuals, partitions, role, stats)

    @cached_property
    def indexes(self):
        by_name, by_endpoint, by_scope, by_address = (defaultdict(list) for _ in range(4))
        for obj in self.virtuals:
            by_name[obj.full_path].append(obj)
            parsed = obj.parsed
            if parsed.key:
                by_endpoint[parsed.key].append(obj)
            if parsed.scope:
                by_scope[parsed.scope].append(obj)
                by_address[parsed.address].append(obj)
        return by_name, by_endpoint, by_scope, by_address

    def match(self, virtual_path: str, destination: str, ltm_name: str = "", port: Any = None):
        """Return evidence with matching LTM objects, never a deletion verdict."""
        by_name, by_endpoint, by_scope, by_address = self.indexes
        target = canonical(ltm_name or virtual_path) if (ltm_name or virtual_path) else ""
        dst = parse_destination(destination, port)
        named = by_name.get(target, [])
        exact = by_endpoint.get(dst.key, []) if dst.key else []
        if len({v.full_path for v in exact}) > 1:
            return "AMBIGUOUS_ENDPOINT", exact
        if exact:
            return ("PRESENT" if any(v.full_path == target for v in exact)
                    else "ADDRESS_PRESENT_DIFFERENT_NAME"), exact
        if not dst.key:
            return "UNVERIFIABLE", named
        if named:
            return "NAME_PRESENT_ADDRESS_DIFFERS", named
        related = by_scope.get(dst.scope, [])
        if related:
            if any(not v.parsed.key for v in related):
                return "LTM_PORT_UNVERIFIABLE", related
            return "IP_PRESENT_DIFFERENT_PORT", related
        if by_address.get(dst.address):
            return "IP_PRESENT_DIFFERENT_ROUTE_DOMAIN", by_address[dst.address]
        if not target:
            return "UNVERIFIABLE", []
        return "NOT_FOUND", []

    def compare(self, virtual_path: str, destination: str, ltm_name: str = "", port: Any = None) -> str:
        return self.match(virtual_path, destination, ltm_name, port)[0]

    def evidence(self, records):
        return [{"host": self.host, "role": self.role, "name": v.full_path,
                 "endpoint": v.destination,
                 **operational_columns(self.stats.get(v.full_path, {}), "LTM RAW")}
                for v in records]


def parse_ltm_mappings(args: list[str] | None) -> dict[str, LtmInventory]:
    """Accept repeated --ltm-raw 'GSLB_SERVER=PATH' arguments.

    The equality sign is only split once, to permit Windows directory names.
    """
    out: dict[str, LtmInventory] = {}
    for spec in args or []:
        server, sep, path = spec.partition("=")
        if not sep or not server.strip() or not path.strip():
            raise LtmSnapshotError("Use --ltm-raw 'GSLB_SERVER=PATH_TO_LTM_RAW' (repeat per LTM)")
        key = canonical(server.strip())
        if key in out:
            raise LtmSnapshotError(f"Duplicate GSLB Server mapping: {key}")
        out[key] = LtmInventory.load(path.strip().strip('"'))
    return out


@dataclass
class LtmScan:
    """Complete, read-only LTM snapshots found under user-provided roots.

    An absent VS in these snapshots is not proof that the relevant LTM was
    included. Negative evidence is explicitly labeled as scanned-only.
    """
    inventories: list[LtmInventory]
    warnings: list[str]
    directories: list[str]

    def search(self, virtual_path: str, destination: str, ltm_name: str = "", port: Any = None) -> dict[str, Any]:
        rows = [(inv, *inv.match(virtual_path, destination, ltm_name, port)) for inv in self.inventories]
        present = ("PRESENT", "ADDRESS_PRESENT_DIFFERENT_NAME", "AMBIGUOUS_ENDPOINT")
        priority = (*present, "NAME_PRESENT_ADDRESS_DIFFERS", "LTM_PORT_UNVERIFIABLE",
                    "IP_PRESENT_DIFFERENT_PORT", "IP_PRESENT_DIFFERENT_ROUTE_DOMAIN", "UNVERIFIABLE")
        default = "NOT_FOUND_IN_SCANNED_LTMS" if rows else "NOT_COMPARED"
        comparison = next((p for p in priority if any(v == p for _, v, _ in rows)), default)
        found = [inv for inv, result, records in rows if records and (
            result in present if comparison in present else result == comparison)]
        return {
            "comparison": comparison,
            "location": ", ".join(inv.host for inv in found),
            "sources": "; ".join(inv.directory for inv in found),
            "timestamp": "; ".join(f"{inv.host}: {inv.timestamp}" for inv in found),
            "evidence": [dict(item, comparison=result) for inv, result, records in rows
                         for item in inv.evidence(records)],
            "checked": len(rows),
        }


def discover_ltm_snapshots(roots: list[str] | None) -> LtmScan:
    """Recursively discover F5Audit LTM snapshots, independently of host count.

    Only folders containing LTM-specific dataset filenames are inspected.
    Repeated snapshots of the SAME host are consolidated to the most recent
    collection. An invalid LTM snapshot is reported, never silently treated as
    evidence of a missing virtual server.
    """
    from datetime import datetime

    inventories: dict[str, LtmInventory] = {}
    warnings: list[str] = []
    observed: set[Path] = set()
    dirs: list[str] = []
    for root_text in roots or []:
        root = Path(root_text).expanduser()
        if not root.is_dir():
            raise LtmSnapshotError(f"LTM raw directory does not exist: {root}")
        dirs.append(str(root))
        meta_paths = [root / "_meta.json"] if (root / "_meta.json").is_file() else []
        meta_paths += sorted(root.rglob("_meta.json"))
        for meta in meta_paths:
            directory = meta.parent.resolve()
            if directory in observed:
                continue
            observed.add(directory)
            if not any(directory.glob("ltm_virtual@*.json")):
                continue  # Non-LTM JSON snapshots can share a parent directory.
            try:
                inv = LtmInventory.load(directory)
            except LtmSnapshotError as exc:
                warnings.append(f"INVALID LTM SNAPSHOT {directory}: {exc}")
                continue
            if not inv.host.strip():
                warnings.append(f"INVALID LTM SNAPSHOT {directory}: host missing in _meta.json")
                continue
            key = inv.host.strip().casefold()
            prev = inventories.get(key)
            if prev is None:
                inventories[key] = inv
            else:
                def dt(value: str):
                    try:
                        return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
                    except (ValueError, OverflowError):
                        return float("-inf")
                chosen = inv if dt(inv.timestamp) > dt(prev.timestamp) else prev
                skipped = prev if chosen is inv else inv
                inventories[key] = chosen
                warnings.append(f"Older duplicate for {inv.host} ignored: {skipped.directory}")
    return LtmScan(sorted(inventories.values(), key=lambda inv: (inv.host.lower(), inv.directory)), warnings, dirs)
