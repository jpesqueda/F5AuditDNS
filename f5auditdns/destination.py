"""Parse BIG-IP virtual destinations without conflating ports or route domains."""
from __future__ import annotations

from dataclasses import dataclass
from ipaddress import ip_address
import re
from typing import Any

# Transport-independent service labels only. Unknown names remain visible but
# require an explicit numeric port before making a negative inventory finding.
SERVICES = {"http": 80, "https": 443, "domain": 53, "ssh": 22, "smtp": 25,
            "ldap": 389, "ldaps": 636, "ntp": 123}


@dataclass(frozen=True)
class Destination:
    address: str = ""
    route_domain: int | None = None
    port: int | None = None
    service: str = ""
    state: str = "NOT REPORTED"

    @property
    def scope(self):
        return (self.address, self.route_domain or 0) if self.address else None

    @property
    def key(self):
        return (*self.scope, self.port) if self.scope and self.state == "IP AND PORT" else None

    def columns(self):
        return {"Destination IP": self.address, "Port": self.port,
                "Route Domain": self.route_domain, "Service": self.service,
                "Destination Parse": self.state}


def _address(raw):
    ip, mark, rd = raw.partition("%")
    if mark and not re.fullmatch(r"[0-9]+", rd):
        return None
    try:
        return str(ip_address(ip)), int(rd) if mark else None
    except ValueError:
        return None


def _service(value):
    if value is None or value == "":
        return None, "", "PORT NOT REPORTED"
    text = str(value).strip().lower()
    if text in ("0", "any", "*"):
        return 0, text if text != "0" else "", "WILDCARD"
    if re.fullmatch(r"[0-9]{1,5}", text) and 0 < int(text) <= 65535:
        return int(text), "", "IP AND PORT"
    if text in SERVICES:
        return SERVICES[text], text, "IP AND PORT"
    return None, text, "UNRESOLVED SERVICE"


def parse_destination(value: Any, port: Any = None) -> Destination:
    raw = str(value or "").strip()
    if raw.startswith("/"):
        raw = raw.rsplit("/", 1)[-1]
    if not raw:
        return Destination()
    embedded = None
    if raw.startswith("["):
        m = re.fullmatch(r"\[([^]]+)\](?::([^:]+))?", raw)
        if not m:
            return Destination(state="UNRECOGNIZED DESTINATION")
        addr, embedded = _address(m[1]), m[2]
    else:
        addr = _address(raw)
        if not addr and ":" in raw:
            host, _, tail = raw.rpartition(":")
            candidate = _address(host)
            if candidate and ":" not in candidate[0]:
                addr, embedded = candidate, tail
        if not addr and ":" in raw and "." in raw:
            host, _, tail = raw.rpartition(".")
            candidate = _address(host)
            if candidate and ":" in candidate[0]:
                addr, embedded = candidate, tail
    if not addr:
        return Destination(state="UNRECOGNIZED DESTINATION")
    number, service, state = _service(embedded if embedded not in (None, "") else port)
    if embedded not in (None, "") and port not in (None, ""):
        explicit, _, explicit_state = _service(port)
        if number is not None and explicit is not None and explicit != number:
            state, number = "CONFLICTING PORT", None
        elif number is None and explicit_state == "IP AND PORT":
            state, number = "IP AND PORT", explicit
    ip, rd = addr
    if ip in {"0.0.0.0", "::"}:
        state = "WILDCARD"
    return Destination(ip, rd, number, service, state)
