"""Read F5Audit LTM (v0.7.x) offline snapshots for explicit GSLB comparisons.

Comparisons require an explicit GSLB Server -> LTM snapshot mapping. Never
assume that similarly named appliances, VIPs or management addresses are the
same physical device, and never interpret an incomplete dataset as absence.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any


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


@dataclass
class LtmInventory:
    host: str
    timestamp: str
    directory: str
    virtuals: list[LtmVirtual]
    partitions: set[str]

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
                virtuals.append(LtmVirtual(full_path, endpoint(row.get("destination"))))
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
        return cls(str(meta.get("host") or ""), str(meta["collected_at"]), str(folder), virtuals, partitions)

    def compare(self, virtual_path: str, destination: str, ltm_name: str = "") -> str:
        """Return exact matching evidence, not a verdict on whether to delete."""
        target = canonical(ltm_name or virtual_path) if (ltm_name or virtual_path) else ""
        target_destination = endpoint(destination)
        exact_name = [v for v in self.virtuals if v.full_path == target]
        if exact_name:
            if not target_destination or any(v.destination == target_destination for v in exact_name):
                return "PRESENT"
            return "NAME_PRESENT_ADDRESS_DIFFERS"
        if target_destination and any(v.destination == target_destination for v in self.virtuals):
            return "ADDRESS_PRESENT_DIFFERENT_NAME"
        if not target or not target_destination:
            return "UNVERIFIABLE"
        return "NOT_FOUND"


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
