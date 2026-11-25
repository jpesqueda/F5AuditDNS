"""Offline change procedure for explicitly approved GSLB pools and members.

Files contain copyable *references*, not executable scripts. The only action
is writing a local TXT file. A target marked APPROVED never bypasses evidence,
rollback availability, or cross-object dependency checks.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from .cleanup import safe_object, safe_member, SUPPORTED_RRS

if TYPE_CHECKING:
    from .analyzer import Audit


@dataclass(frozen=True)
class Selection:
    kind: str
    rr: str
    pool: str
    member: str
    ticket: str
    approved: bool


def parse_approvals(path: str | Path) -> list[Selection]:
    """Parse exact, per-object approvals; no filename-based implicit approval.

    APPROVED|MEMBER|a|/Common/pool|/Common/server:/Common/vs|CHG-0001
    APPROVED|POOL|a|/Common/pool||CHG-0001
    """
    source = Path(path)
    if not source.is_file():
        raise ValueError(f"Approval file not found: {source}")
    records = []
    seen = set()
    for n, raw in enumerate(source.read_text(encoding="utf-8-sig").splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        cells = [x.strip() for x in line.split("|")]
        if len(cells) != 6:
            raise ValueError(f"Approval line {n}: expected 6 |-separated fields")
        state, kind, rr, pool, member, ticket = cells
        kind, rr = kind.upper(), rr.lower()
        if state not in ("APPROVED", "PENDING") or kind not in ("MEMBER", "POOL"):
            raise ValueError(f"Approval line {n}: invalid status/type")
        if rr not in SUPPORTED_RRS or not safe_object(pool):
            raise ValueError(f"Approval line {n}: invalid pool type or fullPath")
        if kind == "MEMBER" and not safe_member(member):
            raise ValueError(f"Approval line {n}: invalid pool member")
        if kind == "POOL" and member not in ("", "-"):
            raise ValueError(f"Approval line {n}: POOL target must not have a member")
        if not re.fullmatch(r"[A-Za-z0-9_.-]{3,80}", ticket):
            raise ValueError(f"Approval line {n}: a valid external ticket is required")
        ident = (kind, rr, pool, member if kind == "MEMBER" else "")
        if ident in seen:
            raise ValueError(f"Duplicate approval target at line {n}")
        seen.add(ident)
        records.append(Selection(kind, rr, pool, member if kind == "MEMBER" else "", ticket, state == "APPROVED"))
    if not records:
        raise ValueError("Approval file contains no targets")
    return records


def _section(heading: str, value: str) -> str:
    return f"\n[{heading}]\n{value or 'NOT RUN: # No captured evidence available'}\n"


def _commands(row, kind):
    if kind == "MEMBER":
        return row.get("Delete pool member", ""), row.get("Recreate pool member (Rollback)", "")
    return row.get("Delete pool", ""), row.get("Recreate pool (Rollback)", "")


def write_change_plan(audit: "Audit", target: str | Path, selections: list[Selection] | None = None,
                      *, hostname: str = "", collected_at: str = "") -> str:
    """Write a non-executable TXT, ordered member removals before pool review.

    Approved entries without verified TMSH recovery or with known dependencies
    are BLOCKED, and the action is NOT emitted as an executable instruction.
    """
    members = {(m['Type'].lower(), m['Pool'], m['Member']): m for m in audit.members}
    pools = {(p['Type'].lower(), p['Pool']): p for p in audit.pools}
    if selections is None:
        selections = [Selection("MEMBER", k[0], k[1], k[2], "NOT-APPROVED", False)
                      for k, m in members.items() if m.get("IP Marked (Source)")]
        selections += [Selection("POOL", k[0], k[1], "", "NOT-APPROVED", False)
                       for k, p in pools.items() if p.get("Pool Action") == "REVIEW EMPTY POOL"]
    if not selections:
        selections = []
    approved_members = { (x.rr, x.pool, x.member) for x in selections if x.kind == "MEMBER" and x.approved }
    lines = ["F5AuditDNS | CONTROLLED GSLB CLEANUP PROCEDURE (REFERENCE ONLY)",
             "=" * 74,
             f"DNS snapshot device: {hostname or 'UNKNOWN'}",
             f"DNS snapshot UTC: {collected_at or 'UNKNOWN'}",
             "READ ONLY TOOL: this TXT does NOT execute any tmsh command.",
             "Requires an independently approved change, current runtime verification and an on-device recovery plan.",
             "APPROVED in the manifest is an operator assertion, NOT a safety verdict.",
             "Captured TMSH configuration may be sensitive: keep source backups private.",
             "Never paste NOT RUN commands into automation without manual validation."]
    for number, sel in enumerate(sorted(selections, key=lambda x: (0 if x.kind == "MEMBER" else 1, x.rr, x.pool, x.member)), 1):
        row = members.get((sel.rr, sel.pool, sel.member)) if sel.kind == "MEMBER" else pools.get((sel.rr, sel.pool))
        if row is None:
            raise ValueError(f"Approved object not present in the DNS snapshot: {sel.kind} {sel.rr} {sel.pool} {sel.member}")
        deletion, rollback = _commands(row, sel.kind)
        blockers = []
        if not sel.approved:
            blockers.append("APPROVAL PENDING - external approval required")
        if row.get("Rollback Status") != "CAPTURED - VERIFY TMSH SYNTAX":
            blockers.append(f"ROLLBACK NOT VERIFIED: {row.get('Rollback Status') or 'MISSING'}")
        if sel.kind == "POOL":
            other_members = [m['Member'] for m in audit.members
                             if m['Type'].lower() == sel.rr and m['Pool'] == sel.pool and
                             (sel.rr, sel.pool, m['Member']) not in approved_members]
            if other_members:
                blockers.append(f"POOL HAS {len(other_members)} MEMBER(S) NOT APPROVED FOR REMOVAL")
            if row.get("Wide IP Reference"):
                blockers.append("POOL HAS WIDE IP / LAST RESORT REFERENCE(S); remove only after separately approved unlink")
            if row.get("Reference Confidence") != "NO STATIC REFS IN COMPLETE SNAPSHOT":
                blockers.append("DYNAMIC / INCOMPLETE DEPENDENCY COVERAGE - REVIEW REQUIRED")
        if row.get("Rollback Source") and row.get("Rollback SHA256"):
            backup_evidence = f"{row['Rollback Source']}  SHA256={row['Rollback SHA256']}"
        else:
            backup_evidence = "MISSING - capture original tmsh list all-properties and verify checksum"
        status = "BLOCKED - MANUAL REMEDIATION" if blockers else "REVIEW-READY - NOT EXECUTED"
        lines += ["\n" + "=" * 74, f"{number:03d} | {sel.kind} | {sel.rr.upper()} | {sel.pool}" +
                  (f" | {sel.member}" if sel.member else ""),
                  f"Approval: {'APPROVED (OPERATOR-SUPPLIED)' if sel.approved else 'PENDING'} | Ticket: {sel.ticket}",
                  f"Execution gate: {status}", "Backup evidence: " + backup_evidence]
        if blockers:
            lines += ["BLOCKERS:"] + [" - " + reason for reason in blockers]
        lines.append(_section("01. PRECHECK - CAPTURE ORIGINAL CONFIG / STATUS",
                              "\n".join(x for x in (row.get('Check Pool (list)'), row.get('Check Pool (show)')) if x)))
        lines.append(_section("02. PRECHECK - DEPENDENCIES / WIDE IPS / DYNAMIC RULES",
                              "\n".join(x for x in (row.get('Check Wide IP References (list)'),row.get('Check Wide IP References'),
                                                      row.get('Check Other References (grep)'),row.get('Check Dynamic References (grep)')) if x)))
        lines.append(_section("03. CHANGE - ONLY AFTER ALL MANUAL GATES CLEAR",
                              deletion if not blockers else "NOT RUN: # BLOCKED: resolve all blockers; proposed command intentionally withheld"))
        lines.append(_section("04. POSTCHECK - HEALTH / DNS / GSLB POOL MEMBERS",
                              row.get('Check Pool (show)', '') + "\n" +
                              "NOT RUN: # Validate authoritative DNS, HA peers, health, TTL and failover using approved test procedure"))
        lines.append(_section("05. ROLLBACK - IF CHANGE MUST BE REVERSED", rollback))
        lines.append(_section("06. ROLLBACK VERIFICATION",
                              row.get('Check Pool (list)', '') + "\n" +
                              "NOT RUN: # Compare restored object settings with SHA256-verified original backup"))
    lines += ["\nFINAL STATUS: PLANNING DOCUMENT ONLY. No configuration was modified."]
    out = Path(target)
    if out.exists():
        raise ValueError(f"Refusing to overwrite existing procedure TXT: {out}")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return str(out)
