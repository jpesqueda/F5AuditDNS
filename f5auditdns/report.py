"""Excel and CSV reporting for F5AuditDNS.

The report contains evidence and proposed commands for human change review only.
"""
from __future__ import annotations

import csv
import re
from pathlib import Path
from typing import Any

from .analyzer import Audit
from .search import SearchTerm, matching_columns

SHEETS = [
    ("Summary", "summary"),
    ("Wide IP Findings", "wideips"),
    ("GSLB Pool Findings", "pools"),
    ("Pool Members", "members"),
    ("GSLB Servers", "servers"),
    ("GSLB Virtual Servers", "virtuals"),
    ("Data Centers", "datacenters"),
    ("DNS Chains", "chains"),
    ("Cleanup Candidates", "candidates"),
    ("LTM Inventories", "ltm_inventory"),
    ("Manual Review", "manual_review"),
    ("Auxiliary Inventory", "auxiliary"),
    ("Collection Health", "collection_health"),
    ("Reference Map", "reference_map"),
    ("Object Inventory", "object_inventory"),
    ("Pool Impact", "pool_impact"),
    ("Cleanup Procedure", "cleanup_procedure"),
    ("FreedIP", "freed_ips"),
]


STATUS_COLORS = {
    "AVAILABLE": ("DCFCE7", "166534"), "OFFLINE": ("FEE2E2", "991B1B"),
    "UNAVAILABLE": ("FEF3C7", "92400E"), "DISABLED": ("E2E8F0", "334155"),
    "UNKNOWN": ("DBEAFE", "1E40AF"), "NOT OBSERVED": ("F1F5F9", "475569"),
    "IN USE": ("DCFCE7", "166534"),
    "ORPHAN": ("FEF3C7", "92400E"),
    "INACTIVE": ("FEF3C7", "92400E"),
    "MANUAL REVIEW": ("FEF3C7", "92400E"),
    "UNRELIABLE": ("FEE2E2", "991B1B"),
    "OFFLINE (decommission candidate)": ("FDE68A", "854D0E"),
    "PENDING": ("FEF3C7", "92400E"),
    "ROLLBACK INCOMPLETE": ("FEE2E2", "991B1B"),
    "KEEP POOL": ("DCFCE7", "166534"),
    "REVIEW EMPTY POOL": ("FEF3C7", "92400E"),
    "INVENTORY INCOMPLETE - NO SIMULATION": ("FEE2E2", "991B1B"),
}

IDENTITY_COLUMNS = {
    "pools": ("Type", "Pool"), "members": ("Type", "Pool", "Member", "GSLB Server", "Virtual Server"),
    "virtuals": ("Server", "Virtual Server"), "candidates": ("Type", "Object", "GSLB Pool", "GSLB Server"),
}
PRIORITY_COLUMNS = ("Destination", "Destination IP", "Port", "Route Domain", "Service",
                    "Health", "Config", "LTM Comparison", "LTM Location", "LTM Matched Virtual Server",
                    "LTM Health", "Verdict", "Referenced by", "Member count", "Status Reason", "Health Source")


def _columns(rows, attribute):
    ordered = dict.fromkeys(k for row in rows for k in row)
    if attribute in IDENTITY_COLUMNS:
        priority = (*IDENTITY_COLUMNS[attribute], *PRIORITY_COLUMNS)
        return [k for k in priority if k in ordered] + [k for k in ordered if k not in priority]
    return list(ordered)


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


def search_matches(audit: Audit, terms: list[SearchTerm]):
    """Return per-row evidence cells and an auditable search results inventory.

    Match locations are separate from audit verdicts and cleanup evidence.
    No command, rollback, approval or monitor status is changed by searching.
    """
    marks: dict[tuple[str, int], set[str]] = {}
    records: list[dict[str, Any]] = []
    seen = {term: 0 for term in terms}
    for title, attribute in SHEETS:
        rows = getattr(audit, attribute)
        if not rows:
            continue
        for index, row in enumerate(rows, 2):
            for term in terms:
                cells = matching_columns(row, term)
                if not cells:
                    continue
                marks.setdefault((title, index), set()).update(cells)
                seen[term] += 1
                identity = next((str(row.get(key)) for key in
                                 ('Virtual Server', 'GSLB Virtual Server', 'Member',
                                  'Object Name', 'Pool', 'Wide IP', 'Object', 'Destination IP')
                                 if row.get(key)), '')
                records.append({
                    'Search Term': term.value, 'Search Type': term.kind,
                    'Source': term.source, 'Status': 'FOUND',
                    'Sheet': title, 'Excel Row': index,
                    'Matched Columns': ', '.join(sorted(cells)),
                    'Matched Object': identity,
                    'Read Only': 'YES - HIGHLIGHT ONLY',
                })
    for term in terms:
        if not seen[term]:
            records.append({'Search Term': term.value, 'Search Type': term.kind,
                            'Source': term.source, 'Status': 'NOT FOUND',
                            'Sheet': '', 'Excel Row': '', 'Matched Columns': '',
                            'Matched Object': '', 'Read Only': 'YES - HIGHLIGHT ONLY'})
    return marks, records


def as_csv(audit: Audit, directory: str | Path,
           search_terms: list[SearchTerm] | None = None) -> list[str]:
    folder = Path(directory)
    folder.mkdir(parents=True, exist_ok=True)
    paths = []
    for title, name in SHEETS:
        rows: list[dict[str, Any]] = getattr(audit, name)
        if title == "FreedIP" and not rows:
            continue
        if not rows:
            continue
        dest = folder / (re.sub(r"[^a-zA-Z0-9_-]", "_", title) + ".csv")
        columns = _columns(rows, name)
        with dest.open("w", newline="", encoding="utf-8-sig") as handle:
            writer = csv.DictWriter(handle, fieldnames=columns)
            writer.writeheader()
            for row in rows:
                writer.writerow({k: _safe_cell(row.get(k, "")) for k in columns})
        paths.append(str(dest))
    if search_terms:
        _, search_rows = search_matches(audit, search_terms)
        output = folder / 'Search_Results.csv'
        columns = list(search_rows[0])
        with output.open('w', newline='', encoding='utf-8-sig') as handle:
            writer = csv.DictWriter(handle, fieldnames=columns)
            writer.writeheader()
            for row in search_rows:
                writer.writerow({key: _safe_cell(row.get(key, '')) for key in columns})
        paths.append(str(output))
    return paths


def as_excel(audit: Audit, filename: str | Path,
             search_terms: list[SearchTerm] | None = None) -> str:
    """Export a readable multi-tab workbook, styled similarly to F5Audit LTM."""
    from openpyxl import Workbook
    from openpyxl.styles import Alignment, Font, PatternFill
    from openpyxl.utils import get_column_letter

    marks, search_rows = search_matches(audit, search_terms) if search_terms else ({}, [])
    yellow = PatternFill('solid', fgColor='FFF59D')
    wb = Workbook()
    wb.remove(wb.active)
    for title, attribute in SHEETS:
        if title == "FreedIP" and not getattr(audit, attribute):
            continue
        ws = wb.create_sheet(title)
        rows: list[dict[str, Any]] = getattr(audit, attribute)
        if not rows:
            ws.append(["No records in this section"])
            ws.column_dimensions["A"].width = 36
            continue
        keys = _columns(rows, attribute)
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
                column_title = keys[cell.column - 1]
                if column_title in ("Health", "LTM Health", "Availability", "Verdict",
                                    "Approval Status", "Rollback Status", "Pool Action",
                                    "VS Cleanup Action"):
                    colors = STATUS_COLORS.get(cell.value)
                    if colors:
                        cell.fill = PatternFill("solid", fgColor=colors[0])
                        cell.font = Font(color=colors[1], bold=True)
                if column_title == "IP Marked (Source)" and cell.value:
                    cell.fill = PatternFill("solid", fgColor="FEF3C7")
                    cell.font = Font(color="92400E", bold=True)
                if column_title in marks.get((title, index), ()):
                    # Search yellow overrides row stripes and status colors,
                    # but no original cell values or verdicts are modified.
                    cell.fill = yellow
                    cell.font = Font(color='1F2937', bold=True)
                cell.alignment = Alignment(vertical="top", wrap_text=True)
        for col, k in enumerate(keys, 1):
            max_data = max([len(str(k))] + [len(str(r.get(k, ""))) for r in rows[:250]])
            width = min(52, max(14, max_data + 2))
            if k in ("Reason", "Status Reason", "LTM Evidence", "Note", "Notes", "Description", "Delete", "Rollback"):
                width = 52
            ws.column_dimensions[get_column_letter(col)].width = width
        ws.auto_filter.ref = ws.dimensions
        if "Approval Status" in keys and len(rows) > 0:
            # Excel users can record a change-board decision; the generated
            # tool itself never records approval or executes any command.
            from openpyxl.worksheet.datavalidation import DataValidation
            validation = DataValidation(type="list", formula1='"PENDING,APPROVED,REJECTED"',
                                        allow_blank=False)
            validation.errorTitle = "Approval status"
            validation.error = "Choose PENDING, APPROVED, or REJECTED."
            validation.showErrorMessage = True
            ws.add_data_validation(validation)
            letter = get_column_letter(keys.index("Approval Status") + 1)
            validation.add(f"{letter}2:{letter}{len(rows)+1}")
        ws.sheet_view.showGridLines = False
    if search_rows:
        ws = wb.create_sheet('Search Results')
        headers = list(search_rows[0])
        ws.append(headers)
        ws.freeze_panes = 'A2'
        for cell in ws[1]:
            cell.fill = PatternFill('solid', fgColor='19344D')
            cell.font = Font(color='FFFFFF', bold=True)
            cell.alignment = Alignment(wrap_text=True, vertical='center')
        ws.row_dimensions[1].height = 28
        for index, row in enumerate(search_rows, 2):
            ws.append([_safe_cell(row.get(key)) for key in headers])
            for cell in ws[index]:
                cell.alignment = Alignment(vertical='top', wrap_text=True)
                if row['Status'] == 'FOUND' and cell.column in (1, 4, 7):
                    cell.fill = yellow
                    cell.font = Font(color='1F2937', bold=True)
                elif row['Status'] == 'NOT FOUND' and cell.column == 4:
                    cell.fill = PatternFill('solid', fgColor='FEE2E2')
                    cell.font = Font(color='991B1B', bold=True)
        for index, key in enumerate(headers, 1):
            ws.column_dimensions[get_column_letter(index)].width = {
                'Search Term': 32, 'Search Type': 18, 'Source': 35,
                'Status': 15, 'Sheet': 25, 'Excel Row': 15,
                'Matched Columns': 42, 'Matched Object': 42, 'Read Only': 29,
            }.get(key, 22)
        ws.auto_filter.ref = ws.dimensions
        ws.sheet_view.showGridLines = False
    dest = Path(filename)
    dest.parent.mkdir(parents=True, exist_ok=True)
    wb.save(dest)
    return str(dest)
