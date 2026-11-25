"""Capture, index, and safely reference complete TMSH object definitions.

READ ONLY: this module never executes any configuration-changing operation.
A captured `list ... all-properties` block is *not* a verified `create` script.
Generated rollback references always require operator validation on the
corresponding TMOS version and current operational state.

The captured files may contain confidential configuration. Treat the complete
backup directory as a secret. Never commit it to source control.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from .collector import RECORD_TYPES
from .cleanup import safe_object, safe_member

BASE_KINDS = tuple((kind, rr) for kind in ("wideip", "pool") for rr in RECORD_TYPES) + (
    ("server", ""), ("datacenter", ""),
)
OPTIONAL_KINDS = (("rule", ""), ("topology", ""), ("region", ""), ("prober-pool", ""))
FILENAME = re.compile(r"^gtm_([a-z][a-z-]*)_(a|aaaa|cname|mx|naptr|srv|all)\.txt$")
HEADER = re.compile(r"(?m)^\s*gtm\s+(wideip|pool|server|datacenter|rule|topology|region|prober-pool)\s+(?:(a|aaaa|cname|mx|naptr|srv)\s+)?([^\s{}]+)\s*\{")
SECRET = re.compile(r"(?im)^\s*(?:password|passphrase|secret|key|api-key|token|private-key|shared-secret|auth-password|client-key|ssl-key)\b")
UNSAFE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]")


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _brace_close(source: str, open_at: int) -> int:
    """Parse balanced tmsh blocks, honoring quoted and escaped braces.

    An unterminated block is never returned as a restorable definition.
    """
    level, quoted, escaped = 0, False, False
    for i in range(open_at, len(source)):
        ch = source[i]
        if escaped:
            escaped = False
        elif ch == "\\":
            escaped = True
        elif ch == '"':
            quoted = not quoted
        elif not quoted and ch == "{":
            level += 1
        elif not quoted and ch == "}":
            level -= 1
            if level == 0:
                return i + 1
    raise ValueError("Unbalanced TMSH configuration; restore reference suppressed")


def _children(text: str, group: str) -> dict[str, str]:
    """Return immediate member/VS definitions from a parent block body."""
    match = re.search(r"(?m)^\s*" + re.escape(group) + r"\s*\{", text)
    if not match:
        return {}
    start = text.find("{", match.start())
    end = _brace_close(text, start)
    inner = text[start + 1:end - 1]
    children = {}
    pos = 0
    while pos < len(inner):
        header = re.search(r"(?m)^\s*([^\s{}]+)\s*\{", inner[pos:])
        if not header:
            break
        begin = pos + header.start()
        name = header.group(1)
        brace = pos + header.end() - 1
        child_end = _brace_close(inner, brace)
        if name in children:
            raise ValueError("Duplicate nested TMSH object")
        children[name] = inner[begin:child_end].strip()
        pos = child_end
    return children


@dataclass(frozen=True)
class Block:
    kind: str
    record: str
    name: str
    definition: str
    source: str
    source_sha256: str
    captured_at: str

    def children(self, group: str) -> dict[str, str]:
        return _children(self.definition, group)


@dataclass(frozen=True)
class Rollback:
    status: str
    command: str
    source: str = ""
    source_sha256: str = ""
    reason: str = ""
    properties: str = ""


class TmshBackup:
    def __init__(self, folder: str | Path):
        self.folder = Path(folder)
        self.blocks: dict[tuple[str, str, str], Block] = {}
        self.warnings: list[str] = []
        if not self.folder.is_dir():
            raise ValueError(f"TMSH backup directory not found: {self.folder}")
        manifest_file = self.folder / "_tmsh_manifest.json"
        manifest = json.loads(manifest_file.read_text(encoding="utf-8")) if manifest_file.exists() else {}
        inventory = manifest.get("files", {})
        self.device = str(manifest.get("device") or "")
        self.captured_at = str(manifest.get("captured_utc") or "")
        candidates = sorted(self.folder.glob("*.txt"))
        if not candidates:
            raise ValueError("No TMSH configuration .txt files found in backup directory")
        for path in candidates:
            if path.is_symlink() or UNSAFE.search(path.name):
                raise ValueError("Unsafe TMSH backup filename")
            if path.stat().st_size > 128 * 1024 * 1024:
                raise ValueError(f"TMSH backup file too large; review offline: {path.name}")
            data = path.read_bytes()
            entry = inventory.get(path.name)
            if manifest and not entry:
                self.warnings.append(f"UNVERIFIED SOURCE: {path.name} is not listed in manifest")
                continue
            if entry and entry.get("sha256") != sha256(data):
                raise ValueError(f"TMSH backup checksum mismatch: {path.name}")
            contents = data.decode("utf-8-sig")
            for m in HEADER.finditer(contents):
                open_at = contents.find("{", m.start())
                end = _brace_close(contents, open_at)
                kind, rr, name = m.group(1), (m.group(2) or "").lower(), m.group(3)
                if not safe_object(name):
                    self.warnings.append(f"Unsupported identifier in {path.name}; skipped")
                    continue
                key = kind, rr, name
                if key in self.blocks:
                    self.warnings.append(f"AMBIGUOUS DUPLICATE: {kind} {rr} {name}")
                    del self.blocks[key]
                    continue
                self.blocks[key] = Block(kind, rr, name, contents[m.start():end].strip(),
                                         path.name, sha256(data), str(entry.get("captured_utc") if entry else self.captured_at))
        if not self.blocks:
            raise ValueError("No valid gtm object definitions found. Use unmodified tmsh list output.")

    def get(self, kind: str, record: str, name: str) -> Optional[Block]:
        return self.blocks.get((kind, record.lower(), name))

    def restore(self, kind: str, record: str, name: str, *, member: str = "", server: str = "") -> Rollback:
        # Complete objects are restored with `create`; nested members and VSs
        # require parent `modify ... add` and must use saved nested attributes.
        if not safe_object(name) or record not in ("", *RECORD_TYPES):
            return Rollback("ROLLBACK INCOMPLETE", "", reason="Unsafe or unsupported object identifier")
        parent_kind = "pool" if member else "server" if server else kind
        parent_name = server or name
        block = self.get(parent_kind, record if member else "" if server else record, parent_name)
        if not block:
            return Rollback("ROLLBACK INCOMPLETE", "", reason="Original TMSH definition missing in provided backup")
        if member or server:
            child_name = member or name
            if (member and not safe_member(child_name)) or (server and not safe_object(child_name)):
                return Rollback("ROLLBACK INCOMPLETE", "", reason="Unsafe nested object identifier")
            group = "members" if member else "virtual-servers"
            try:
                child = block.children(group).get(child_name)
            except ValueError as exc:
                return Rollback("ROLLBACK INCOMPLETE", "", reason=str(exc))
            if not child:
                return Rollback("ROLLBACK INCOMPLETE", "", reason=f"{group} definition missing in parent TMSH backup")
            command = (f"tmsh modify gtm pool {record} {name} members add {{ {child} }}" if member else
                       f"tmsh modify gtm server {server} virtual-servers add {{ {child} }}")
            content = child
        else:
            content = block.definition
            command = "tmsh create " + content
        # Never put potentially sensitive settings into Excel or the change TXT.
        if kind == "rule":
            return Rollback("BACKUP CAPTURED - SENSITIVE",
                            "NOT RUN: # iRule source is intentionally omitted. Restore from restricted original TMSH backup after code review.",
                            block.source, block.source_sha256,
                            "iRule source may contain sensitive configuration or executable Tcl; manual restore required")
        if SECRET.search(content):
            return Rollback("BACKUP CAPTURED - SENSITIVE", "NOT RUN: # Sensitive configuration omitted; use restricted original TMSH backup and approved restoration procedure",
                            block.source, block.source_sha256,
                            "Sensitive settings detected; reconstruct from secured source in a controlled change", "[SENSITIVE BLOCK - NOT EXPORTED]")
        return Rollback("CAPTURED - VERIFY TMSH SYNTAX", "\n".join("NOT RUN: " + line for line in command.splitlines()),
                        block.source, block.source_sha256,
                        "Captured complete TMSH block. Syntax, dependencies and restore order MUST be validated on matching TMOS; NOT automatically certified exact.",
                        content[:6000])


def capture_tmsh_ssh(host: str, username: str, output: str | Path, *, timeout: int = 120,
                     include_optional: bool = True) -> Path:
    """Use system OpenSSH, trusted host key, and a READ ONLY tmsh list command.

    SSH manages authentication itself; password/token never enter Python args.
    This captures confidential configuration in plaintext under the output dir.
    """
    if not re.fullmatch(r"[A-Za-z0-9._:-]+", host) or not re.fullmatch(r"[A-Za-z0-9_.-]+", username):
        raise ValueError("Unsafe SSH host or username")
    folder = Path(output)
    if folder.exists() and (not folder.is_dir() or any(folder.iterdir())):
        raise ValueError("Refusing to overwrite an existing TMSH backup directory")
    folder.mkdir(parents=True, exist_ok=True)
    if os.name != "nt":
        folder.chmod(0o700)
    specs = BASE_KINDS + OPTIONAL_KINDS if include_optional else BASE_KINDS
    recorded = {}
    for kind, rr in specs:
        target = " ".join(x for x in ("gtm", kind, rr) if x)
        filename = "gtm_" + kind.replace("-", "_") + "_" + (rr or "all") + ".txt"
        # A trusted host key is required; OpenSSH handles passwords/agent.
        argv = ["ssh", "-T", "-o", "StrictHostKeyChecking=yes", "-o", f"ConnectTimeout={min(timeout, 30)}",
                f"{username}@{host}", "tmsh -q -c 'cd /; list " + target + " recursive all-properties'"]
        result = subprocess.run(argv, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=timeout)
        if result.returncode != 0:
            # Some TMOS versions do not support every record type/subcollection.
            recorded[filename] = {"status": "FAILED", "exit_code": result.returncode}
            continue
        data = result.stdout
        if not re.search(r"(?m)^\s*gtm\s+" + re.escape(kind), data):
            recorded[filename] = {"status": "EMPTY OR UNRECOGNIZED"}
            continue
        dest = folder / filename
        dest.write_text(data, encoding="utf-8")
        if os.name != "nt":
            dest.chmod(0o600)
        recorded[filename] = {"status": "OK", "sha256": sha256(dest.read_bytes()),
                              "captured_utc": datetime.now(timezone.utc).isoformat()}
    manifest = {"format": "f5auditdns-tmsh-v1", "device": host,
                "captured_utc": datetime.now(timezone.utc).isoformat(), "files": recorded,
                "warning": "CONFIDENTIAL: backup may contain secrets. Do not commit or distribute."}
    path = folder / "_tmsh_manifest.json"
    path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    if os.name != "nt":
        path.chmod(0o600)
    if not any(v.get("status") == "OK" for v in recorded.values()):
        raise ValueError("No valid TMSH definitions collected; check SSH access and tmsh syntax")
    return folder
