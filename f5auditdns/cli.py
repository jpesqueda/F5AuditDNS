"""Command line interface: validate, collect and analyze BIG-IP DNS configuration."""
from __future__ import annotations

import argparse
import getpass
import logging
import os
import re
import sys
from datetime import datetime
from pathlib import Path

from . import __version__
from .analyzer import analyze
from .client import F5ClientError, F5ReadOnlyClient
from .collector import Collector, Snapshot, SnapshotError, validate
from .report import as_csv, as_excel


# Keep the default folder naming independent from the F5Audit LTM project.
DEFAULT_FOLDER_PREFIX = "f5auditDNS_raw"


def safe_hostname(value: str) -> str:
    """Sanitize a BIG-IP hostname or management address for Windows/macOS/Linux.

    A device may report a FQDN. Keep its dots, but replace separators, spaces,
    colons (including IPv6), and other unsupported filename characters.
    """
    value = re.sub(r"[^A-Za-z0-9._-]", "_", str(value).strip())
    return value.strip("._-")[:80] or "unknown_host"


def auto_snapshot_directory(hostname: str, started_at: datetime | None = None) -> Path:
    """Create a name in the *current directory*, without replacing a prior run.

    The timestamp refers to the beginning of collection, in local system time.
    If multiple runs start in the same minute, append _02, _03, etc.
    """
    started_at = started_at or datetime.now().astimezone()
    stem = f"{DEFAULT_FOLDER_PREFIX}_{safe_hostname(hostname)}_{started_at:%Y%m%d_%H%M}"
    path = Path(stem)
    number = 2
    while path.exists():
        path = Path(f"{stem}_{number:02d}")
        number += 1
    return path


def resolve_device_hostname(client: F5ReadOnlyClient, fallback: str) -> tuple[str, bool]:
    """Read actual BIG-IP hostname. Fallback safely if API access is denied.

    Do not save the complete /sys/global-settings JSON, which may contain
    unrelated/sensitive system properties. Only the hostname is retained.
    """
    try:
        response = client.get("/mgmt/tm/sys/global-settings", params={"$select": "hostname"})
        hostname = response.get("hostname") if isinstance(response, dict) else None
        if isinstance(hostname, str) and hostname.strip():
            return hostname.strip(), True
    except F5ClientError as exc:
        logging.warning("Could not discover device hostname: %s", exc)
    return fallback, False


def shell_path(path: Path) -> str:
    """Format a path suitable for pasting from the same working directory."""
    try:
        relative = os.path.relpath(path.resolve(), Path.cwd().resolve())
    except ValueError:  # Windows: different drive letters
        return str(path.resolve())
    if relative != "." and not relative.startswith("." + os.sep):
        if relative.startswith(".." + os.sep):
            return relative
        return "." + os.sep + relative
    return relative


def parser() -> argparse.ArgumentParser:
    examples = r"""Examples (IP address):
  f5auditdns validate -ho 192.0.2.20 -u auditor
  f5auditdns validate -ho 192.0.2.20 -u auditor --insecure
  f5auditdns collect -ho 192.0.2.20 -u auditor --insecure
  f5auditdns collect -ho 192.0.2.20 -u auditor --insecure -o .\raw_dns
  f5auditdns collect -ho 192.0.2.20 -u auditor --scope core -o .\raw_dns_core

Examples (DNS hostname / FQDN):
  f5auditdns validate -ho f5auditdns.com -u auditor
  f5auditdns validate -ho f5auditdns.com -u auditor --insecure
  f5auditdns collect -ho f5auditdns.com -u auditor
  f5auditdns collect -ho f5auditdns.com -u auditor --insecure -o .\raw_dns

Analyze the snapshot (offline):
  f5auditdns analyze --from-raw .\raw_dns -o DNS_Audit.xlsx
  f5auditdns analyze --from-raw .\examples\raw_simulado -o DNS_Audit.xlsx
  f5auditdns analyze --from-raw .\raw_dns --format csv -o .\reports_csv

Default output: if -o is omitted for collect, a new directory named
  f5auditDNS_raw_<device-hostname>_<YYYYMMDD_HHMM>
is created in the current working directory. After collection, the exact
analyze command is displayed, relative to that same directory.

Safety: BIG-IP configuration is read via GET. A POST is used only to obtain
an authentication token. No changes or deletion scripts are generated.
"""
    validate_examples = r"""Examples:
  f5auditdns validate -ho 192.0.2.20 -u auditor
  f5auditdns validate -ho 192.0.2.20 -u auditor --insecure
  f5auditdns validate -ho f5auditdns.com -u auditor
  f5auditdns validate -ho f5auditdns.com -u auditor --insecure
"""
    collect_examples = r"""Examples:
  f5auditdns collect -ho 192.0.2.20 -u auditor
  f5auditdns collect -ho 192.0.2.20 -u auditor --insecure
  f5auditdns collect -ho 192.0.2.20 -u auditor --insecure -o .\raw_dns
  f5auditdns collect -ho f5auditdns.com -u auditor
  f5auditdns collect -ho f5auditdns.com -u auditor --insecure -o .\raw_dns

Without -o, the output folder uses the BIG-IP device hostname and timestamp,
and the final output prints an analyze command you can copy and paste.
"""
    analyze_examples = r"""Examples (no BIG-IP connection needed):
  f5auditdns analyze --from-raw .\raw_dns -o DNS_Audit.xlsx
  f5auditdns analyze --from-raw .\examples\raw_simulado -o DNS_Audit.xlsx
  f5auditdns analyze --from-raw .\raw_dns --format csv -o .\reports_csv
"""
    p = argparse.ArgumentParser(
        prog="f5auditdns",
        description="Read-only F5 BIG-IP DNS / GSLB audit (independent of F5Audit LTM).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=examples,
    )
    p.add_argument("--version", action="version", version=f"F5AuditDNS {__version__}")
    subs = p.add_subparsers(dest="command", required=True)
    for name in ("validate", "collect", "analyze"):
        sub = subs.add_parser(name, help={
            "validate": "Check DNS API read permissions",
            "collect": "Collect a read-only snapshot into JSON files",
            "analyze": "Analyze a saved snapshot and export Excel/CSV",
        }[name], formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog={"validate": validate_examples, "collect": collect_examples,
                    "analyze": analyze_examples}[name])
        if name in ("validate", "collect"):
            sub.add_argument("-ho", "--host", required=True,
                             help="BIG-IP management IP address or DNS hostname (FQDN)")
            sub.add_argument("-u", "--user", required=True, help="BIG-IP username")
            sub.add_argument("-p", "--password", help="Not recommended; prompt or F5AUDITDNS_PASSWORD is safer")
            sub.add_argument("--insecure", action="store_true", help="Disable TLS certificate verification (lab only)")
            sub.add_argument("--timeout", type=int, default=30, help="REST timeout (default: 30s)")
            sub.add_argument("--page-size", type=int, default=100, help="Objects per REST page (default: 100)")
            sub.add_argument("--provider", default="tmos", help="Authentication provider (default: tmos)")
        if name == "collect":
            sub.add_argument("-o", "--save-raw", default=None,
                             help="Snapshot directory (default: ./f5auditDNS_raw_HOSTNAME_YYYYMMDD_HHMM)")
            sub.add_argument("--scope", choices=("core", "all"), default="all",
                             help="core: GSLB objects only; all: also monitors, iRules, topology, listeners")
        if name == "analyze":
            sub.add_argument("--from-raw", required=True, help="Previously collected snapshot directory")
            sub.add_argument("-o", "--out", default="F5_DNS_Audit.xlsx", help="Output .xlsx or CSV directory")
            sub.add_argument("--format", choices=("excel", "csv"), default="excel")
        sub.add_argument("-v", "--verbose", action="store_true", help="Show REST collection progress")
    return p


def make_client(args: argparse.Namespace) -> F5ReadOnlyClient:
    password = args.password
    if password is None:
        password = os.environ.get("F5AUDITDNS_PASSWORD")
    if password is None:
        password = getpass.getpass("BIG-IP password: ")
    if args.insecure:
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    return F5ReadOnlyClient(
        host=args.host, username=args.user, password=password,
        verify_tls=not args.insecure, timeout=args.timeout,
        login_provider=args.provider, page_size=args.page_size,
    )


def main(argv: list[str] | None = None) -> int:
    p = parser()
    args = p.parse_args(argv)
    logging.basicConfig(level=logging.INFO if args.verbose else logging.WARNING,
                        format="%(levelname)s: %(message)s")
    try:
        if args.command == "validate":
            client = make_client(args)
            results = validate(client)
            print("\nF5AuditDNS | API Access Validation")
            for path, state, status in results:
                print(f"  {state:<5} HTTP {status:<3} {path}")
            good = all(r[1] == "OK" for r in results)
            print("Result:", "PASS" if good else "INCOMPLETE")
            return 0 if good else 2
        if args.command == "collect":
            started_at = datetime.now().astimezone()
            # Keep the explicit-folder no-overwrite check before making any
            # network connection. The default folder is chosen after fetching
            # the device hostname (with a safe fallback to the -ho value).
            if args.save_raw is not None:
                path = Path(args.save_raw)
                if path.exists() and (not path.is_dir() or any(path.iterdir())):
                    print(f"ERROR: {path} is not an empty folder. Choose a new snapshot folder.", file=sys.stderr)
                    return 2
            print(f"Collecting BIG-IP DNS/GSLB: {args.host} | scope={args.scope}")
            client = make_client(args)
            hostname = None
            if args.save_raw is None:
                hostname, discovered = resolve_device_hostname(client, args.host)
                if not discovered:
                    print("WARNING: BIG-IP hostname unavailable; using -ho value for folder name.")
                path = auto_snapshot_directory(hostname, started_at)
            snapshot = Collector(client, args.host, args.scope).collect()
            if hostname is not None:
                snapshot.meta["device_hostname"] = hostname
            snapshot.write(path)
            ok = snapshot.meta.get("success_count", 0)
            bad = snapshot.meta.get("warning_count", 0)
            print(f"Raw snapshot saved: {shell_path(path)} | OK datasets: {ok} | warnings: {bad}")
            print("The audit is read-only; no configuration was modified.")
            print("\nNext step: analyze this snapshot (run in the SAME directory):")
            print(f'  f5auditdns analyze --from-raw "{shell_path(path)}" -o ".{os.sep}DNS_Audit.xlsx"')
            return 0 if bad == 0 else 2
        snapshot = Snapshot.read(args.from_raw)
        audit = analyze(snapshot)
        if args.format == "csv":
            paths = as_csv(audit, args.out)
            print(f"Generated {len(paths)} CSV files in {args.out}")
        else:
            filename = as_excel(audit, args.out)
            print(f"Excel report: {filename}")
        print(f"Wide IPs: {len(audit.wideips)} | Pools: {len(audit.pools)} "
              f"| Members: {len(audit.members)} | Review items: {len(audit.manual_review)}")
        return 0
    except (F5ClientError, SnapshotError, OSError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
