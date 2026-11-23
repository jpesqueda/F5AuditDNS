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
from .ltm_compare import parse_ltm_mappings, discover_ltm_snapshots, LtmSnapshotError
from .client import F5ClientError, F5ReadOnlyClient
from .collector import Collector, Snapshot, SnapshotError, validate
from .report import as_csv, as_excel
from .freedip import load_freed_ips
from .search import load_search_terms


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
  f5auditdns analyze --from-raw .\raw_dns -o DNS_Audit.xlsx --ltm-raw "/Common/GDL-F5=.\raw_ltm_gdl"
  f5auditdns analyze --from-raw .\raw_dns --ltm-raw-dir .\LTMAudits -o DNS_Cleanup.xlsx
  f5auditdns analyze --from-raw .\raw_dns --ltm-raw-dir .\LTMAudits --ltm-coverage-complete -o DNS_Cleanup.xlsx
  f5auditdns analyze --from-raw .\raw_dns --ltm-raw-dir .\LTMAudits --file .\freed_ips.txt -o Cleanup.xlsx
  f5auditdns analyze --from-raw .\raw_dns --virtual-server vs_app -o Highlighted.xlsx
  f5auditdns analyze --from-raw .\raw_dns --ltm-raw-dir .\LTMAudits --file .\freed_ips.txt -o Highlighted_And_Simulated.xlsx
  f5auditdns analyze --from-raw .\examples\raw_simulado -o DNS_Audit.xlsx
  f5auditdns analyze --from-raw .\raw_dns --format csv -o .\reports_csv

Default output: if -o is omitted for collect, a new directory named
  f5auditDNS_raw_<device-hostname>_<YYYYMMDD_HHMM>
is created in the current working directory. After collection, the exact
analyze command is displayed, relative to that same directory.

Safety: BIG-IP configuration is read via GET. A POST is used only to obtain
an authentication token. No changes are made. Delete/Rollback columns are informational change proposals.
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
  f5auditdns analyze --from-raw .\raw_dns --ltm-raw "/Common/GDL-F5=.\raw_ltm_gdl" -o DNS_Audit.xlsx
  f5auditdns analyze --from-raw .\raw_dns --ltm-raw "GDL-F5=.\ltm_gdl_raw" --ltm-raw "QRO-F5=.\ltm_qro_raw"
  f5auditdns analyze --from-raw .\raw_dns --ltm-raw-dir .\AllLTM_RAW -o .\DNS_Cleanup.xlsx
  f5auditdns analyze --from-raw .\raw_dns --ltm-raw-dir .\AllLTM_RAW --ltm-coverage-complete
  f5auditdns analyze --from-raw .\raw_dns -o DNS_Audit.xlsx
  f5auditdns analyze --from-raw .\raw_dns -o DNS_Audit.xlsx --ltm-raw "/Common/GDL-F5=.\raw_ltm_gdl"
  f5auditdns analyze --from-raw .\raw_dns --ltm-raw-dir .\LTMAudits -o DNS_Cleanup.xlsx
  f5auditdns analyze --from-raw .\raw_dns --ltm-raw-dir .\LTMAudits --ltm-coverage-complete -o DNS_Cleanup.xlsx
  f5auditdns analyze --from-raw .\raw_dns --ltm-raw-dir .\LTMAudits --file .\freed_ips.txt -o Cleanup.xlsx
  f5auditdns analyze --from-raw .\raw_dns --virtual-server vs_app -o Highlighted.xlsx
  f5auditdns analyze --from-raw .\raw_dns --ltm-raw-dir .\LTMAudits --file .\freed_ips.txt -o Highlighted_And_Simulated.xlsx
  f5auditdns analyze --from-raw .\examples\raw_simulado -o DNS_Audit.xlsx
  f5auditdns analyze --from-raw .\raw_dns --format csv -o .\reports_csv
"""
    examples += """

Ejemplos (español):
  f5auditdns collect -ho dns01.example.test -u auditor -o .\\DNS_RAW
  f5auditdns analyze --from-raw .\\DNS_RAW --virtual-server vs_app -o VS_Resaltado.xlsx
  f5auditdns analyze --from-raw .\\DNS_RAW --ltm-raw-dir .\\LTM_RAW --file .\\lista.xlsx -o Reporte.xlsx

Importante: --file busca/resalta y, si contiene IPs, TAMBIEN simula
su retirada en Pool Impact (Approval Status=PENDING). Nombres de VS solo buscan.
Use --search-only si solo quiere amarillo sin simular cambios.
--freed-ip-file agrega evidencia opcional. Nunca se ejecutan comandos tmsh.
"""
    validate_examples += """

Ejemplos (español): comprobar acceso de lectura a API REST.
  f5auditdns validate -ho 192.0.2.20 -u auditor
"""
    collect_examples += """

Ejemplos (español): capturar RAW sin modificar BIG-IP.
  f5auditdns collect -ho dns01.example.test -u auditor -o .\\DNS_RAW
"""
    analyze_examples += """

Ejemplos (español): analizar RAW existentes sin conexión al BIG-IP.
  f5auditdns analyze --from-raw .\\DNS_RAW --virtual-server vs_app -o VS_Resaltado.xlsx
  f5auditdns analyze --from-raw .\\DNS_RAW --ltm-raw-dir .\\LTM_RAW --file .\\lista.xlsx -o Reporte.xlsx
  f5auditdns analyze --from-raw .\\DNS_RAW --freed-ip-file .\\freed_ips.xlsx -o Cleanup.xlsx

--file: buscar/resaltar; las IPs válidas también alimentan FreedIP y Pool Impact.
--search-only: --file solo resalta, sin simulación FreedIP.
--freed-ip-file: evidencia adicional para simulación, nunca autorización.
Ninguna opción cambia Verdict ni Approval Status (PENDING).
"""
    p = argparse.ArgumentParser(
        prog="f5auditdns",
        description="Read-only F5 BIG-IP DNS / GSLB audit / Auditoría DNS/GSLB de solo lectura (independiente de F5Audit LTM).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=examples,
    )
    p.add_argument("--version", action="version", version=f"F5AuditDNS {__version__}")
    subs = p.add_subparsers(dest="command", required=True)
    for name in ("validate", "collect", "analyze"):
        sub = subs.add_parser(name, help={
            "validate": "Check DNS API read permissions / Comprobar permisos API DNS",
            "collect": "Collect a read-only JSON snapshot / Recopilar RAW JSON sin modificar BIG-IP",
            "analyze": "Analyze saved snapshot, export Excel/CSV / Analizar RAW y exportar Excel/CSV",
        }[name], formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog={"validate": validate_examples, "collect": collect_examples,
                    "analyze": analyze_examples}[name])
        if name in ("validate", "collect"):
            sub.add_argument("-ho", "--host", required=True,
                             help="BIG-IP management IP or FQDN / IP de administración o nombre DNS")
            sub.add_argument("-u", "--user", required=True, help="BIG-IP username / Usuario BIG-IP")
            sub.add_argument("-p", "--password", help="Not recommended: use prompt/env var / Preferir prompt o variable F5AUDITDNS_PASSWORD")
            sub.add_argument("--insecure", action="store_true", help="Disable TLS verification (authorized cases) / Desactivar TLS (casos autorizados)")
            sub.add_argument("--timeout", type=int, default=30, help="REST timeout (default 30s) / Timeout REST (30s)")
            sub.add_argument("--page-size", type=int, default=100, help="Objects per REST page (100) / Objetos por página REST (100)")
            sub.add_argument("--provider", default="tmos", help="Authentication provider (tmos) / Proveedor de autenticación (tmos)")
        if name == "collect":
            sub.add_argument("-o", "--save-raw", default=None,
                             help="Snapshot directory / Directorio RAW (default: ./f5auditDNS_raw_HOSTNAME_YYYYMMDD_HHMM)")
            sub.add_argument("--no-stats", action="store_true", help="Skip operational /stats / Omitir estadísticas operativas")
            sub.add_argument("--scope", choices=("core", "all"), default="all",
                             help="core: GSLB only; all: auxiliaries / core: GSLB; all: monitores, reglas y topología")
        if name == "analyze":
            sub.add_argument("--from-raw", required=True, help="Saved DNS RAW directory / Directorio RAW DNS existente")
            sub.add_argument("--ltm-raw", action="append", default=[], metavar="GSLB_SERVER=PATH",
                             help="Explicit GSLB Server=LTM RAW mapping / Mapeo explícito GSLB Server=RAW LTM (repetible)")
            sub.add_argument("--ltm-raw-dir", action="append", default=[], metavar="DIR",
                             help="Find LTM RAWs recursively (repeatable) / Buscar RAW LTM recursivamente (repetible)")
            sub.add_argument("--ltm-coverage-complete", action="store_true",
                             help="Operator asserts complete relevant LTM coverage; no automatic approval / "
                                  "Operador confirma cobertura LTM; no autoriza eliminación")
            sub.add_argument("--virtual-server", "--vs", action="append", default=[], metavar="NAME",
                             help="Highlight VS name or SERVER:VS (repeatable) / Resaltar VS o SERVER:VS (repetible)")
            sub.add_argument("--object", "--search", action="append", default=[], metavar="NAME",
                             help="Highlight object name or endpoint / Resaltar nombre de objeto, pool, Wide IP o IP")
            sub.add_argument("--file", action="append", default=[], metavar="FILE",
                             help="TXT/CSV/XLSX: highlight names and IPs; IP values ALSO simulate "
                                  "unapproved FreedIP cleanup / Resaltar y simular IPs como evidencia NO aprobada")
            sub.add_argument("--search-only", action="store_true",
                             help="With --file, highlight only (skip automatic FreedIP simulation) / "
                                  "Solo resaltar, sin simulación automática")
            sub.add_argument("--freed-ip-file", metavar="FILE",
                             help="Additional explicit FreedIP evidence; merges with --file IPs / "
                                  "Evidencia adicional de IPs decomisionadas, sin aprobación automática")
            sub.add_argument("--max-snapshot-gap-hours", type=float, default=48, metavar="HOURS",
                             help="Max DNS/LTM age gap (48h) / Diferencia máxima RAW DNS/LTM (48h)")
            sub.add_argument("-o", "--out", default="F5_DNS_Audit.xlsx", help="Output XLSX or CSV directory / Excel o directorio CSV de salida")
            sub.add_argument("--format", choices=("excel", "csv"), default="excel")
        sub.add_argument("-v", "--verbose", action="store_true", help="Show collection progress / Mostrar progreso de la recolección")
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
            snapshot = Collector(client, args.host, args.scope, collect_stats=not args.no_stats).collect()
            if hostname is not None:
                snapshot.meta["device_hostname"] = hostname
            snapshot.write(path)
            ok = snapshot.meta.get("success_count", 0)
            bad = snapshot.meta.get("warning_count", 0)
            print(f"Raw snapshot saved: {shell_path(path)} | OK datasets: {ok} | warnings: {bad}")
            if args.no_stats:
                print("Operational stats: skipped (--no-stats).")
            else:
                requests = [v for k, v in snapshot.meta["endpoint_results"].items() if k.startswith("stats_")]
                print(f"Operational stats: {requests.count('OK')}/{len(requests)} endpoints returned a stats response. "
                      "See Collection Health and Health Source in the report.")
            print("The audit is read-only; no configuration was modified.")
            print("\nNext step: analyze this snapshot (run in the SAME directory):")
            print(f'  f5auditdns analyze --from-raw "{shell_path(path)}" -o ".{os.sep}DNS_Audit.xlsx"')
            return 0 if bad == 0 else 2
        snapshot = Snapshot.read(args.from_raw)
        if args.max_snapshot_gap_hours <= 0:
            raise ValueError("--max-snapshot-gap-hours must be positive")
        ltm_snapshots = parse_ltm_mappings(args.ltm_raw)
        if args.ltm_coverage_complete and not args.ltm_raw_dir:
            raise ValueError("--ltm-coverage-complete requires --ltm-raw-dir")
        ltm_scan = discover_ltm_snapshots(args.ltm_raw_dir) if args.ltm_raw_dir else None
        if ltm_scan and not ltm_scan.inventories:
            raise LtmSnapshotError("No valid F5Audit LTM raw snapshots found under --ltm-raw-dir")
        if ltm_scan:
            print(f"LTM auto-discovery: {len(ltm_scan.inventories)} valid snapshot(s) "
                  f"| warnings: {len(ltm_scan.warnings)} | coverage confirmed: "
                  f"{'YES' if args.ltm_coverage_complete else 'NO'}")
            for inv in ltm_scan.inventories:
                print(f"  LTM {inv.host} | {len(inv.virtuals)} VS | {inv.directory}")
            for warning in ltm_scan.warnings:
                print(f"  WARNING: {warning}")
        search_terms = load_search_terms(args.virtual_server, args.object, args.file)
        if args.file and not search_terms:
            raise ValueError("No valid search values found in --file; use IP addresses or object names")
        if search_terms:
            print(f"Offline search: {len(search_terms)} unique term(s); yellow highlights do not change Verdict or approval")
        # A --file list may mix names and IP addresses. Names are search terms
        # only; valid IP or IP:port[%RD] entries also feed the existing FreedIP
        # impact simulator. All results are REVIEW/PENDING, never approvals.
        # --search-only restores the previous highlight-only --file behavior.
        evidence_files = ([args.freed_ip_file] if args.freed_ip_file else [])
        if not args.search_only:
            evidence_files += args.file
        found_ip_evidence = {}
        for filename in evidence_files:
            for record in load_freed_ips(filename):
                found_ip_evidence.setdefault((record.ip, record.port, record.route_domain), record)
        freed_ips = list(found_ip_evidence.values())
        if freed_ips:
            print(f"FreedIP simulation: {len(freed_ips)} distinct IP/endpoint(s) from file(s); "
                  "evidence only, Approval Status=PENDING")
        elif args.file:
            print("No IP endpoints in --file for FreedIP simulation; search/highlighting only")
        audit = analyze(snapshot, ltm_snapshots, args.max_snapshot_gap_hours,
                        ltm_scan=ltm_scan, ltm_coverage_complete=args.ltm_coverage_complete,
                        freed_ips=freed_ips)
        if args.format == "csv":
            paths = as_csv(audit, args.out, search_terms=search_terms)
            print(f"Generated {len(paths)} CSV files in {args.out}")
        else:
            filename = as_excel(audit, args.out, search_terms=search_terms)
            print(f"Excel report: {filename}")
        print(f"Wide IPs: {len(audit.wideips)} | Pools: {len(audit.pools)} "
              f"| Members: {len(audit.members)} | Review items: {len(audit.manual_review)} "
              f"| Cleanup candidates: {len(audit.candidates)}")
        print("Delete/Rollback are NOT RUN reference commands only; no changes made to BIG-IP.")
        return 0
    except (F5ClientError, SnapshotError, LtmSnapshotError, OSError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
