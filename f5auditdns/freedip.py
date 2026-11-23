"""Read-only import of decommissioned-IP evidence from TXT, CSV and XLSX.

An entry identifies evidence for human review; it is never an authorization to
remove GSLB objects. A bare IP never establishes endpoint-level identity.
"""
from __future__ import annotations

import csv
import ipaddress
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


@dataclass(frozen=True)
class FreedIPRecord:
    ip: str
    port: int | None
    route_domain: int | None
    source: str

    @property
    def endpoint(self) -> str:
        return self.ip + (f"%{self.route_domain}" if self.route_domain is not None else "") + (
            f":{self.port}" if self.port is not None else "")


def _parse_token(token: object) -> tuple[str, int | None, int | None] | None:
    text = str(token if token is not None else "").strip().strip('"\'')
    if not text or len(text) > 100:
        return None
    # F5 destination syntax: IPv4%RD:port, [IPv6%RD]:port, or bare IP.
    if text.startswith('['):
        m = re.fullmatch(r"\[([^]]+)\](?::(\d{1,5}))?", text)
        if not m:
            return None
        host, port_txt = m.groups()
    else:
        try:
            return str(ipaddress.ip_address(text)), None, None
        except ValueError:
            pass
        m = re.fullmatch(r"(\d{1,3}(?:\.\d{1,3}){3}(?:%\d+)?)(?::(\d{1,5}))?", text)
        if not m:
            return None
        host, port_txt = m.groups()
    route_domain = None
    if '%' in host:
        host, rd = host.rsplit('%', 1)
        if not rd.isdigit():
            return None
        route_domain = int(rd)
    try:
        ip = str(ipaddress.ip_address(host))
        port = int(port_txt) if port_txt is not None else None
        if port is not None and not 0 <= port <= 65535:
            return None
        return ip, port, route_domain
    except ValueError:
        return None


def _values(path: Path) -> Iterable[tuple[str, str]]:
    suffix = path.suffix.lower()
    if suffix == '.txt':
        with path.open(encoding='utf-8-sig') as source:
            for number, line in enumerate(source, 1):
                if line.strip().startswith('#'):
                    continue
                # Allow whitespace/comma/semicolon separated lists.
                for column, item in enumerate(re.split(r'[\s,;]+', line.strip()), 1):
                    yield f'line {number} col {column}', item
    elif suffix == '.csv':
        with path.open(newline='', encoding='utf-8-sig') as source:
            sample = source.read(4096)
            source.seek(0)
            try:
                dialect = csv.Sniffer().sniff(sample, delimiters=',;\t')
            except csv.Error:
                dialect = csv.excel
            for number, row in enumerate(csv.reader(source, dialect), 1):
                for column, item in enumerate(row, 1):
                    yield f'row {number} col {column}', item
    elif suffix == '.xlsx':
        from openpyxl import load_workbook
        workbook = load_workbook(path, read_only=True, data_only=True)
        try:
            for sheet in workbook:
                for number, row in enumerate(sheet.iter_rows(values_only=True), 1):
                    for column, item in enumerate(row, 1):
                        if item is not None:
                            yield f'{sheet.title} row {number} col {column}', str(item)
        finally:
            workbook.close()
    else:
        raise ValueError('FreedIP file must be .txt, .csv or .xlsx')


def load_freed_ips(path: str | Path | None) -> list[FreedIPRecord]:
    """Import explicit IP values only, ignoring arbitrary headers or free text."""
    if path is None:
        return []
    filename = Path(path)
    if not filename.is_file():
        raise ValueError(f'FreedIP file not found: {filename}')
    result = {}
    for location, text in _values(filename):
        parsed = _parse_token(text)
        if parsed:
            ip, port, rd = parsed
            result.setdefault((ip, port, rd), FreedIPRecord(
                ip=ip, port=port, route_domain=rd,
                source=f'{filename.name} ({location})'))
    return list(result.values())


def match_freed_ip(ip: object, port: object, route_domain: object,
                   records: list[FreedIPRecord]) -> tuple[str, str]:
    """Never convert a bare-IP mark into a verified decommission verdict."""
    try:
        endpoint_ip = str(ipaddress.ip_address(str(ip)))
    except ValueError:
        return '', 'NO MATCH'
    matches = [x for x in records if x.ip == endpoint_ip]
    if not matches:
        return '', 'NO MATCH'
    try:
        endpoint_port = int(port)
    except (ValueError, TypeError):
        endpoint_port = None
    try:
        endpoint_rd = int(route_domain) if route_domain not in (None, '') else None
    except (ValueError, TypeError):
        endpoint_rd = None
    matches = [x for x in matches if x.port is None or x.port == endpoint_port]
    matches = [x for x in matches if x.route_domain is None or x.route_domain == endpoint_rd]
    if not matches:
        return '', 'IP MATCH, ENDPOINT CONFLICT'
    strongest = max(matches, key=lambda x: (x.port is not None, x.route_domain is not None))
    if strongest.port is None:
        quality = 'IP ONLY - REVIEW'
    elif strongest.route_domain is None:
        quality = 'IP+PORT - RD NOT VERIFIED'
    else:
        quality = 'IP+PORT+ROUTE DOMAIN - REVIEW'
    return '; '.join(dict.fromkeys(x.source for x in matches)), quality
