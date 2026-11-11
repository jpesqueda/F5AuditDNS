"""Excel and CSV reporting for F5AuditDNS.

The report contains evidence and review items, not executable cleanup commands.
"""
from __future__ import annotations

import csv
import re
from pathlib import Path
from typing import Any

from .analyzer import Audit

SHEETS = [
    ("Summary", "summary"),
    ("Wide IP Findings", "wideips"),
    ("GSLB Pool Findings", "pools"),
    ("Pool Members", "members"),
    ("GSLB Servers", "servers"),
    ("GSLB Virtual Servers", "virtuals"),
    ("Data Centers", "datacenters"),
    ("DNS Chains", "chains"),
    ("Manual Review", "manual_review"),
    ("Auxiliary Inventory", "auxiliary"),
    ("Collection Health", "collection_health"),
]


def _safe_cell(value: Any) -> Any:
    """Prevent spreadsheet-formula injection from BIG-IP object names/descriptions."""
    if value is None:
        return ""
    if isinstance(value, bool):
        return "YES" if value else "NO"
    if isinstance(value, (float, int)):
        return value
    text = str(value)
    if text.lstrip().startswith(("=", "+", "-", "@", "\t", "\r")):
        return "'" + text
    return text[:32000]


def as_csv(audit: Audit, directory: str | Path) -> list[str]:
    folder = Path(directory)
    folder.mkdir(parents=True, exist_ok=True)
    paths = []
    for title, name in SHEETS:
        rows: list[dict[str, Any]] = getattr(audit, name)
        if not rows:
            continue
        dest = folder / (re.sub(r"[^a-zA-Z0-9_-]", "_", title) + ".csv")
        columns = list(dict.fromkeys(k for r in rows for k in r))
        with dest.open("w", newline="", encoding="utf-8-sig") as handle:
            writer = csv.DictWriter(handle, fieldnames=columns)
            writer.writeheader()
            for row in rows:
                writer.writerow({k: _safe_cell(row.get(k, "")) for k in columns})
        paths.append(str(dest))
    return paths


def as_excel(audit: Audit, filename: str | Path) -> str:
    """Export a readable multi-tab workbook, styled similarly to F5Audit LTM."""
    from openpyxl import Workbook
    from openpyxl.styles import Alignment, Font, PatternFill
    from openpyxl.utils import get_column_letter

    wb = Workbook()
    wb.remove(wb.active)
    for title, attribute in SHEETS:
        ws = wb.create_sheet(title)
        rows: list[dict[str, Any]] = getattr(audit, attribute)
        if not rows:
            ws.append(["No records in this section"])
            ws.column_dimensions["A"].width = 36
            continue
        keys = list(dict.fromkeys(k for r in rows for k in r))
        ws.append(keys)
        ws.freeze_panes = "A2"
        for c in ws[1]:
            c.fill = PatternFill("solid", fgColor="19344D")
            c.font = Font(color="FFFFFF", bold=True)
            c.alignment = Alignment(vertical="center", wrap_text=True)
        ws.row_dimensions[1].height = 28
        for index, row in enumerate(rows, 2):
            ws.append([_safe_cell(row.get(k, "")) for k in keys])
            if index % 2 == 0:
                for cell in ws[index]:
                    cell.fill = PatternFill("solid", fgColor="F1F5F9")
            for cell in ws[index]:
                cell.alignment = Alignment(vertical="top", wrap_text=True)
        for col, k in enumerate(keys, 1):
            max_data = max([len(str(k))] + [len(str(r.get(k, ""))) for r in rows[:250]])
            width = min(52, max(14, max_data + 2))
            if k in ("Reason", "Note", "Description"):
                width = 52
            ws.column_dimensions[get_column_letter(col)].width = width
        ws.auto_filter.ref = ws.dimensions
        ws.sheet_view.showGridLines = False
    dest = Path(filename)
    dest.parent.mkdir(parents=True, exist_ok=True)
    wb.save(dest)
    return str(dest)
