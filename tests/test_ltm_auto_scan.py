"""F5AuditDNS v0.3.0: community-friendly LTM raw discovery and reference actions."""
import json
from pathlib import Path

from f5auditdns.analyzer import analyze
from f5auditdns.ltm_compare import discover_ltm_snapshots
from f5auditdns.cli import main
from test_auditdns import sample


def create_ltm(root: Path, name: str, virtuals: list, timestamp="2026-11-11T01:00:00Z") -> Path:
    folder = root / name / "raw"
    folder.mkdir(parents=True)
    (folder / "_meta.json").write_text(json.dumps({
        "host": name, "collected_at": timestamp, "aborted": None,
        "denied": [], "missing_endpoints": []
    }), encoding="utf-8")
    (folder / "auth_partition.json").write_text(json.dumps({
        "key": "auth_partition", "data": [{"name": "Common"}]
    }), encoding="utf-8")
    (folder / "ltm_virtual@Common.json").write_text(json.dumps({
        "key": "ltm_virtual@Common", "data": virtuals
    }), encoding="utf-8")
    return folder


def vip(path="/Common/vs1"):
    return {"fullPath": path, "destination": "/Common/192.0.2.1:443"}


def test_scan_one_ltm_auto_location_and_reference_commands(tmp_path):
    create_ltm(tmp_path, "ltm01", [vip()])
    scan = discover_ltm_snapshots([str(tmp_path)])
    report = analyze(sample(), ltm_scan=scan)
    member = report.members[0]
    assert scan.inventories[0].host == "ltm01"
    assert member["LTM Location"] == "ltm01"
    assert member["LTM Comparison"] == "PRESENT"
    assert member["LTM Search Mode"] == "AUTO SEARCH"
    assert member["Verdict"] == "IN USE"
    assert member["Delete"].startswith("NOT RUN: tmsh modify gtm pool")
    assert "NOT RUN: tmsh modify gtm pool" in member["Rollback"]
    assert report.virtuals[0]["LTM Location"] == "ltm01"
    assert report.servers[0]["LTM Location"] == "ltm01"
    assert report.servers[0]["Delete"].startswith("NOT RUN: tmsh delete gtm server")
    assert report.chains[0]["LTM Location"] == "ltm01"
    assert len(report.ltm_inventory) == 1
    assert not report.candidates


def test_scan_ten_devices_locates_vip_on_both_ha_devices(tmp_path):
    for i in range(1, 11):
        create_ltm(tmp_path, f"ltm{i:02}", [vip()] if i in (3, 4) else [])
    scan = discover_ltm_snapshots([str(tmp_path)])
    assert len(scan.inventories) == 10
    report = analyze(sample(), ltm_scan=scan)
    assert report.members[0]["LTM Scanned"] == 10
    assert report.members[0]["LTM Location"] == "ltm03, ltm04"
    assert report.members[0]["LTM Comparison"] == "PRESENT"
    assert not report.candidates


def test_unknown_coverage_never_promotes_negative_to_candidate(tmp_path):
    create_ltm(tmp_path, "ltm01", [])
    scan = discover_ltm_snapshots([str(tmp_path)])
    report = analyze(sample(), ltm_scan=scan)
    member = report.members[0]
    assert member["LTM Comparison"] == "NOT_FOUND_IN_SCANNED_LTMS"
    assert member["LTM Location"] == ""
    assert member["Verdict"] == "MANUAL REVIEW"
    assert member["Delete"].startswith("NOT RUN: tmsh ")
    assert not report.candidates


def test_explicit_complete_coverage_allows_candidate_if_fresh(tmp_path):
    create_ltm(tmp_path, "ltm01", [])
    scan = discover_ltm_snapshots([str(tmp_path)])
    snap = sample()
    snap.datasets["gtm_server"][0]["virtualServerDiscovery"] = "disabled"
    report = analyze(snap, ltm_scan=scan, ltm_coverage_complete=True)
    assert report.members[0]["Verdict"] == "OFFLINE (decommission candidate)"
    assert report.virtuals[0]["Verdict"] == "OFFLINE (decommission candidate)"
    assert {x["Type"] for x in report.candidates} == {"POOL MEMBER", "GSLB VIRTUAL SERVER"}
    assert all(x["Delete"].startswith("NOT RUN: tmsh") for x in report.candidates)


def test_incomplete_ltm_inventory_blocks_all_negative_candidates(tmp_path):
    good = create_ltm(tmp_path, "ltm01", [])
    bad = create_ltm(tmp_path, "ltm02", [])
    (bad / "auth_partition.json").unlink()
    scan = discover_ltm_snapshots([str(tmp_path)])
    assert len(scan.inventories) == 1
    assert any("INVALID LTM SNAPSHOT" in w for w in scan.warnings)
    report = analyze(sample(), ltm_scan=scan, ltm_coverage_complete=True)
    assert report.members[0]["Verdict"] == "MANUAL REVIEW"
    assert not report.candidates


def test_stale_snapshot_blocks_absence_even_if_coverage_confirmed(tmp_path):
    create_ltm(tmp_path, "ltm01", [], timestamp="2026-01-01T01:00:00Z")
    scan = discover_ltm_snapshots([str(tmp_path)])
    report = analyze(sample(), ltm_scan=scan, ltm_coverage_complete=True)
    assert report.members[0]["Verdict"] == "MANUAL REVIEW"
    assert not report.candidates


def test_repeat_snapshots_keeps_latest_per_host(tmp_path):
    create_ltm(tmp_path, "ltm01", [], timestamp="2026-11-11T01:00:00Z")
    new_dir = tmp_path / "new" / "raw"
    new_dir.mkdir(parents=True)
    for filename in ["_meta.json", "auth_partition.json", "ltm_virtual@Common.json"]:
        (new_dir / filename).write_bytes((tmp_path / "ltm01" / "raw" / filename).read_bytes())
    meta = json.loads((new_dir / "_meta.json").read_text())
    meta["collected_at"] = "2026-11-11T02:00:00Z"
    (new_dir / "_meta.json").write_text(json.dumps(meta))
    (new_dir / "ltm_virtual@Common.json").write_text(json.dumps({
        "key": "ltm_virtual@Common", "data": [vip()]
    }))
    scan = discover_ltm_snapshots([str(tmp_path)])
    assert len(scan.inventories) == 1
    assert scan.inventories[0].virtuals[0].full_path == "/Common/vs1"
    assert "Older duplicate" in scan.warnings[0]


def test_cli_analyze_discovers_nested_raw_and_generates_excel(tmp_path, capsys):
    dns = tmp_path / "dnsraw"
    sample().write(dns)
    ltm = tmp_path / "all_ltm"
    create_ltm(ltm, "ltm01", [vip()])
    out = tmp_path / "report.xlsx"
    code = main(["analyze", "--from-raw", str(dns), "--ltm-raw-dir", str(ltm), "-o", str(out)])
    assert code == 0
    output = capsys.readouterr().out
    assert "LTM auto-discovery: 1 valid snapshot(s)" in output
    assert "ltm01" in output
    assert out.exists()
    from openpyxl import load_workbook
    book = load_workbook(out, read_only=True)
    assert "LTM Inventories" in book.sheetnames
    ws = book["Pool Members"]
    headers = [c.value for c in next(ws.rows)]
    assert "LTM Location" in headers
    assert "Delete" in headers


def test_candidate_not_generated_for_unsafe_identifier_or_missing_inventory(tmp_path):
    snap = sample()
    snap.datasets["pool_members::a::/Common/pool1"][0]["name"] = "malicious;name"
    result = analyze(snap)
    assert result.members[0]["Delete"].startswith("NOT RUN: No safe deletion command")
    assert result.members[0]["Verdict"] == "UNRELIABLE"
    assert not result.candidates


def test_ha_locations_include_member_with_renamed_vs_but_same_destination(tmp_path):
    create_ltm(tmp_path, "ltm-active", [vip()])
    create_ltm(tmp_path, "ltm-standby", [vip("/Common/different_vs_name")])
    scan = discover_ltm_snapshots([str(tmp_path)])
    report = analyze(sample(), ltm_scan=scan)
    assert report.members[0]["LTM Comparison"] == "PRESENT"
    assert report.members[0]["LTM Location"] == "ltm-active, ltm-standby"
    assert report.members[0]["Verdict"] == "IN USE"
