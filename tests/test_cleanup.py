"""Cleanup verification: destructive commands are NEVER executed by F5AuditDNS."""
import json

import pytest

from f5auditdns.analyzer import analyze
from f5auditdns.cleanup import prepared_member_commands, prepared_pool_commands
from f5auditdns.ltm_compare import LtmInventory, LtmSnapshotError, parse_ltm_mappings

from test_auditdns import sample


def ltm_snapshot(tmp_path, *, virtuals, host="ltm-gdl", denied=False):
    path = tmp_path / "ltm_gdl_raw"
    path.mkdir()
    (path / "_meta.json").write_text(json.dumps({
        "collected_at": "2026-11-11T20:00:00Z", "host": host,
        "denied": [{"endpoint": "/mgmt/tm/ltm/virtual"}] if denied else [],
        "missing_endpoints": [], "aborted": None,
    }))
    (path / "auth_partition.json").write_text(json.dumps({"key": "auth_partition", "data": [{"name": "Common"}]}))
    (path / "ltm_virtual@Common.json").write_text(json.dumps({"key": "ltm_virtual@Common", "data": virtuals}))
    return path


def test_no_ltm_snapshot_does_not_mark_member_for_deletion():
    report = analyze(sample())
    member = report.members[0]
    assert member["Verdict"] == "IN USE"
    assert member["Delete"].startswith("NOT RUN: tmsh modify gtm pool")
    assert member["LTM Comparison"] == "NOT_COMPARED"
    assert not report.candidates


def test_missing_ltm_virtual_becomes_candidate_only_with_explicit_mapping(tmp_path):
    path = ltm_snapshot(tmp_path, virtuals=[])
    inv = parse_ltm_mappings([f"/Common/BIGIP1={path}"])
    snap = sample()
    snap.datasets["gtm_server"][0]["virtualServerDiscovery"] = "disabled"
    report = analyze(snap, inv)
    member = report.members[0]
    vs = report.virtuals[0]
    assert member["LTM Comparison"] == "NOT_FOUND"
    assert member["Verdict"] == "OFFLINE (decommission candidate)"
    assert member["Delete"] == "NOT RUN: tmsh modify gtm pool a /Common/pool1 members delete { /Common/BIGIP1:/Common/vs1 }"
    assert "tmsh modify gtm pool a /Common/pool1 members add" in member["Rollback"]
    assert vs["Verdict"] == "OFFLINE (decommission candidate)"
    assert vs["Delete"].startswith("NOT RUN: tmsh modify gtm server /Common/BIGIP1 virtual-servers delete")
    assert [r["Type"] for r in report.candidates] == ["POOL MEMBER", "GSLB VIRTUAL SERVER"]
    assert "FIRST" in vs["Notes"]


def test_existing_ltm_virtual_keeps_member_in_use(tmp_path):
    path = ltm_snapshot(tmp_path, virtuals=[{"fullPath": "/Common/vs1", "destination": "/Common/192.0.2.1:443"}])
    inv = parse_ltm_mappings([f"BIGIP1={path}"])
    report = analyze(sample(), inv)
    assert report.members[0]["LTM Comparison"] == "PRESENT"
    assert report.members[0]["Verdict"] == "IN USE"
    assert report.members[0]["Delete"].startswith("NOT RUN: tmsh modify gtm pool")


def test_ltm_vs_name_present_but_address_changed_not_deleted(tmp_path):
    path = ltm_snapshot(tmp_path, virtuals=[{"fullPath": "/Common/vs1", "destination": "/Common/198.51.100.1:443"}])
    report = analyze(sample(), parse_ltm_mappings([f"BIGIP1={path}"]))
    assert report.members[0]["LTM Comparison"] == "NAME_PRESENT_ADDRESS_DIFFERS"
    assert report.members[0]["Verdict"] == "MANUAL REVIEW"
    assert report.members[0]["Delete"].startswith("NOT RUN: tmsh modify gtm pool")


def test_ltm_address_present_under_other_name_not_deleted(tmp_path):
    path = ltm_snapshot(tmp_path, virtuals=[{"fullPath": "/Common/renamed_vs", "destination": "/Common/192.0.2.1:443"}])
    report = analyze(sample(), parse_ltm_mappings([f"BIGIP1={path}"]))
    assert report.members[0]["LTM Comparison"] == "ADDRESS_PRESENT_DIFFERENT_NAME"
    assert report.members[0]["Delete"].startswith("NOT RUN: tmsh modify gtm pool")


def test_nonexistent_gslb_vs_without_ltm_destination_requires_manual_review(tmp_path):
    snap = sample()
    snap.datasets["server_virtuals::/Common/BIGIP1"] = []
    path = ltm_snapshot(tmp_path, virtuals=[])
    report = analyze(snap, parse_ltm_mappings([f"BIGIP1={path}"]))
    assert report.members[0]["Mapping"] == "DNS_VIRTUAL_MISSING"
    assert report.members[0]["Verdict"] == "MANUAL REVIEW"
    assert report.members[0]["Delete"].startswith("NOT RUN: tmsh modify gtm pool")


def test_orphan_pool_gets_delete_command_only_when_catalog_complete():
    snap = sample()
    snap.datasets["gtm_pool_a"].append({"fullPath": "/Common/orphan_pool"})
    snap.datasets["pool_members::a::/Common/orphan_pool"] = []
    snap.meta["endpoint_results"]["pool_members::a::/Common/orphan_pool"] = "OK"
    report = analyze(snap)
    orphan = next(x for x in report.pools if x["Pool"] == "/Common/orphan_pool")
    assert orphan["Verdict"] == "ORPHAN"
    assert orphan["Delete"] == "NOT RUN: tmsh delete gtm pool a /Common/orphan_pool"
    assert "tmsh list gtm pool a" in orphan["Rollback"]
    assert any(x["Type"] == "POOL" for x in report.candidates)


def test_dynamic_irule_blocks_orphan_deletion():
    snap = sample()
    snap.datasets["gtm_pool_a"].append({"fullPath": "/Common/orphan_pool"})
    snap.datasets["pool_members::a::/Common/orphan_pool"] = []
    snap.meta["endpoint_results"]["pool_members::a::/Common/orphan_pool"] = "OK"
    snap.datasets["gtm_rule"] = [{"fullPath": "/Common/rule1"}]
    report = analyze(snap)
    orphan = next(x for x in report.pools if x["Pool"] == "/Common/orphan_pool")
    assert orphan["Verdict"] == "MANUAL REVIEW"
    assert orphan["Delete"].startswith("NOT RUN: tmsh delete gtm pool")
    assert not any(x["Object"] == "/Common/orphan_pool" for x in report.candidates)


def test_missing_collection_blocks_orphan_deletion():
    snap = sample()
    snap.datasets["gtm_pool_a"].append({"fullPath": "/Common/orphan_pool"})
    snap.meta["endpoint_results"]["pool_members::a::/Common/orphan_pool"] = "HTTP_403"
    report = analyze(snap)
    orphan = next(x for x in report.pools if x["Pool"] == "/Common/orphan_pool")
    assert orphan["Delete"].startswith("NOT RUN: tmsh delete gtm pool")


def test_malformed_identifier_never_generates_tmsh_command():
    assert prepared_member_commands("a", "/Common/pool; delete sys config", "bad", {})[0] == ""
    assert prepared_pool_commands("a", "/Common/pool;", {}, [])[0] == ""


def test_denied_or_incomplete_ltm_snapshot_cannot_prove_absence(tmp_path):
    path = ltm_snapshot(tmp_path, virtuals=[], denied=True)
    with pytest.raises(LtmSnapshotError):
        LtmInventory.load(path)


def test_member_disabled_status_alone_not_candidate():
    snap = sample()
    snap.datasets["pool_members::a::/Common/pool1"][0].update({"disabled": True, "availabilityState": "down"})
    report = analyze(snap)
    assert report.members[0]["Delete"].startswith("NOT RUN: tmsh modify gtm pool")
    assert report.members[0]["Verdict"] == "MANUAL REVIEW"


def test_server_discovery_prevents_virtual_delete(tmp_path):
    snap = sample()
    snap.datasets["gtm_server"][0]["virtualServerDiscovery"] = "enabled-no-delete"
    path = ltm_snapshot(tmp_path, virtuals=[])
    report = analyze(snap, parse_ltm_mappings([f"BIGIP1={path}"]))
    assert report.virtuals[0]["Verdict"] == "MANUAL REVIEW"
    assert report.virtuals[0]["Delete"].startswith("NOT RUN: tmsh modify gtm server")


def test_html_safe_cell_and_excel_sheet_count(tmp_path):
    from f5auditdns.report import SHEETS, as_excel
    assert any(x[0] == "Cleanup Candidates" for x in SHEETS)
    assert len(SHEETS) == 13
    path = tmp_path / "report.xlsx"
    as_excel(analyze(sample()), path)
    assert path.is_file()


def test_old_ltm_snapshot_never_proposes_delete(tmp_path):
    path = ltm_snapshot(tmp_path, virtuals=[])
    report = analyze(sample(), parse_ltm_mappings([f"BIGIP1={path}"]), max_snapshot_gap_hours=1)
    assert report.members[0]["Delete"].startswith("NOT RUN: tmsh modify gtm pool")
    assert report.members[0]["Verdict"] == "MANUAL REVIEW"
    assert not report.candidates


def test_unknown_discovery_blocks_virtual_server_removal(tmp_path):
    path = ltm_snapshot(tmp_path, virtuals=[])
    report = analyze(sample(), parse_ltm_mappings([f"BIGIP1={path}"]))
    assert report.virtuals[0]["Delete"].startswith("NOT RUN: tmsh modify gtm server")
    assert report.virtuals[0]["Verdict"] == "MANUAL REVIEW"


def test_inline_wideip_irule_blocks_orphan_pool_deletion():
    snap = sample()
    snap.datasets["gtm_wideip_a"][0]["rules"] = ["/Common/rule1"]
    snap.datasets["gtm_pool_a"].append({"fullPath": "/Common/not_used"})
    snap.datasets["pool_members::a::/Common/not_used"] = []
    snap.meta["endpoint_results"]["pool_members::a::/Common/not_used"] = "OK"
    report = analyze(snap)
    orphan = next(x for x in report.pools if x["Pool"] == "/Common/not_used")
    assert orphan["Delete"].startswith("NOT RUN: tmsh delete gtm pool")
