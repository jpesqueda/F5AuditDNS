"""Read-only, offline object and endpoint search for Excel/CSV audit reports.

Search highlights are visual evidence only: they never alter a verdict,
FreedIP matching, simulated impact, or change approval. Search deliberately
avoids command/notes text, and compares IPs using address-aware boundaries.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from .freedip import _parse_token, _values


@dataclass(frozen=True)
class SearchTerm:
    value: str
    kind: str  # IP, ENDPOINT, OBJECT, VIRTUAL SERVER
    source: str
    ip: str = ''
    port: int | None = None
    route_domain: int | None = None


IDENTITY_FIELDS = frozenset({
    'Wide IP', 'Pool', 'GSLB Pool', 'Member', 'Pool Member', 'Current Pool Members',
    'Virtual Server', 'GSLB Virtual Server', 'Server', 'GSLB Server', 'Data Center',
    'Object', 'Object Name', 'Name', 'References', 'Referenced by',
    'Wide IP Reference', 'Wide IP References (via pools)',
    'Current Pool References', 'Current Pool Reference', 'Source Dataset',
    'Current Virtual Servers', 'Current Pool References', 'GSLB Virtual Servers',
    'LTM Matched Virtual Server',
})
ENDPOINT_FIELDS = frozenset({
    'Destination', 'Destination IP', 'IP', 'LTM Matched Destination',
})


def _normalized_object(text: object) -> str:
    return str(text if text is not None else '').strip().casefold()


def _named_token_match(cell: object, query: str) -> bool:
    """Match a complete object/path token, never a substring of another name."""
    cell_text = _normalized_object(cell)
    value = _normalized_object(query)
    if not cell_text or not value:
        return False
    if cell_text == value or cell_text.rsplit('/', 1)[-1] == value:
        return True
    # Some columns contain multiple paths separated by newlines or commas;
    # GSLB pool-member references use server:virtual-server tokens.
    for entry in re.split(r'[\s,;{}()\[\]]+', cell_text):
        entry = entry.strip('"\'')
        if not entry:
            continue
        if entry == value or entry.rsplit('/', 1)[-1] == value:
            return True
        if ':' in entry:
            virtual = entry.rsplit(':', 1)[-1]
            if virtual == value or virtual.rsplit('/', 1)[-1] == value:
                return True
    return False


def _has_ip(cell: object, query_ip: str) -> bool:
    text = str(cell if cell is not None else '')
    if not text or len(text) > 4000:
        return False
    # IP may be followed by :port or %route-domain. Reject IP prefixes such
    # as 192.0.2.4 in 192.0.2.42 and IPv6 hextet prefixes.
    if ':' in query_ip:
        pattern = r'(?<![0-9a-fA-F:.])' + re.escape(query_ip) + r'(?![0-9a-fA-F:.])'
        # IPv6 + :port needs a bracket to be unambiguous; a simple IP column
        # is handled by direct equality, while :port syntax requires brackets.
        if text.strip().strip('[]') == query_ip:
            return True
        if f'[{query_ip}]' in text:
            return True
        return bool(re.search(pattern, text, flags=re.IGNORECASE))
    return bool(re.search(r'(?<![A-Za-z0-9.])' + re.escape(query_ip) + r'(?![A-Za-z0-9.])', text))


def _numeric(value: object) -> int | None:
    try:
        return int(value) if str(value) not in ('', 'None') else None
    except (TypeError, ValueError):
        return None


def make_term(value: object, kind: str = 'OBJECT', source: str = 'CLI') -> SearchTerm | None:
    text = str(value if value is not None else '').strip().strip('"\'')
    if not text or len(text) > 255 or text.casefold() in {
        'ip', 'address', 'destination ip', 'destination', 'port', 'name',
        'virtual server', 'virtual servers', 'pool', 'server', 'hostname',
        'notes', 'comment', 'comments', 'route domain', 'source', 'status',
    }:
        return None
    if any(ord(ch) < 32 for ch in text):
        return None
    # Treat workbook cells as lookup *identifiers*, not narrative notes.
    # Explicit CLI queries may still search unusual names containing spaces.
    if source != 'CLI' and any(ch.isspace() for ch in text):
        return None
    parsed = _parse_token(text)
    if parsed:
        ip, port, route_domain = parsed
        return SearchTerm(text, 'ENDPOINT' if port is not None or route_domain is not None else 'IP',
                          source, ip, port, route_domain)
    return SearchTerm(text, kind, source)


def load_search_terms(virtual_servers: Iterable[str] = (), objects: Iterable[str] = (),
                      files: Iterable[str | Path] = ()) -> list[SearchTerm]:
    """Read .txt/.csv/.xlsx searches, including multi-column spreadsheets."""
    found: dict[tuple[str, str, int | None, int | None], SearchTerm] = {}
    for kind, values in (('VIRTUAL SERVER', virtual_servers), ('OBJECT', objects)):
        for value in values:
            term = make_term(value, kind, 'CLI')
            if term:
                found.setdefault((term.kind, term.ip or term.value.casefold(), term.port,
                                  term.route_domain), term)
    for path_value in files:
        path = Path(path_value)
        if not path.is_file():
            raise ValueError(f'Search file not found: {path}')
        for location, cell in _values(path):
            term = make_term(cell, 'OBJECT', f'{path.name} ({location})')
            if term:
                found.setdefault((term.kind, term.ip or term.value.casefold(), term.port,
                                  term.route_domain), term)
            if len(found) > 10000:
                raise ValueError('Search file has over 10,000 unique terms; split it into smaller files')
    return list(found.values())


def matching_columns(row: dict[str, Any], term: SearchTerm) -> set[str]:
    """Return only evidence cells that match a query; do not alter row data."""
    result: set[str] = set()
    if term.ip:
        ip_columns = [key for key in ENDPOINT_FIELDS if key in row and _has_ip(row[key], term.ip)]
        if not ip_columns:
            return set()
        if term.port is not None and _numeric(row.get('Port')) != term.port:
            # Rows without separate port may still have a parseable destination.
            from .destination import parse_destination
            if not any(parse_destination(str(row.get(key) or '')).port == term.port
                       for key in ('Destination', 'LTM Matched Destination') if key in row):
                return set()
        if term.route_domain is not None and _numeric(row.get('Route Domain')) != term.route_domain:
            return set()
        result.update(ip_columns)
        if term.port is not None and 'Port' in row:
            result.add('Port')
        if term.route_domain is not None and 'Route Domain' in row:
            result.add('Route Domain')
        return result

    if term.kind == 'VIRTUAL SERVER':
        # If user supplies SERVER:VS, require both when a Server field exists.
        search = term.value
        qualifier, sep, vs = search.rpartition(':')
        if sep and qualifier.startswith('/') and vs:
            server = row.get('GSLB Server') or row.get('Server')
            dataset = str(row.get('Source Dataset') or '')
            if not server and dataset.startswith('server_virtuals::'):
                server = dataset.split('::', 1)[1]
            # A full SERVER:VS query must not match an unscoped row.
            if not server or not _named_token_match(server, qualifier):
                return set()
            search = vs
        for key in ('Virtual Server', 'GSLB Virtual Server', 'Member', 'Pool Member',
                    'Object Name', 'LTM Matched Virtual Server', 'Current Virtual Servers'):
            if key not in row:
                continue
            if key == 'Object Name' and not ('server_virtuals::' in str(row.get('Source Dataset') or '')
                                            or 'virtual' in str(row.get('Object Type') or '').lower()):
                continue
            if _named_token_match(row[key], search):
                result.add(key)
        return result

    for key in IDENTITY_FIELDS:
        if key in row and _named_token_match(row[key], term.value):
            result.add(key)
    return result
