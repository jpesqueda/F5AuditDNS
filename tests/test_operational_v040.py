"""Regression cases for runtime stats and endpoint-based cleanup evidence."""
import json

import pytest
from openpyxl import load_workbook

from f5auditdns.analyzer import analyze
from f5auditdns.client import F5APIError
from f5auditdns.collector import Collector, Snapshot
from f5auditdns.destination import parse_destination
from f5auditdns.ltm_compare import discover_ltm_snapshots
from f5auditdns.report import as_excel
from test_auditdns import FakeREST, sample
from test_ltm_auto_scan import create_ltm

NOW = "2026-11-11T00:00:00Z"


def nested(resource, **fields):
    return {"entries": {resource: {"nestedStats": {"entries": {
        key: {"value" if isinstance(value, int) else "description": value}
        for key, value in fields.items()
    }}}}}


@pytest.mark.parametrize("destination, separate, key, state", [
    ("/Common/192.0.2.20:443", None, ("192.0.2.20", 0, 443), "IP AND PORT"),
    ("192.0.2.20%15:https", None, ("192.0.2.20", 15, 443), "IP AND PORT"),
    ("[2001:db8::1%15]:443", None, ("2001:db8::1", 15, 443), "IP AND PORT"),
    ("2001:db8::1%15.443", None, ("2001:db8::1", 15, 443), "IP AND PORT"),
    ("2001:db8::1", 443, ("2001:db8::1", 0, 443), "IP AND PORT"),
    ("2001:db8::443", None, None, "PORT NOT REPORTED"),
    ("192.0.2.20:custom-service", None, None, "UNRESOLVED SERVICE"),
    ("192.0.2.20:custom-service", 8443, ("192.0.2.20", 0, 8443), "IP AND PORT"),
    ("192.0.2.20:443", 8443, None, "CONFLICTING PORT"),
    ("192.0.2.20:any", None, None, "WILDCARD"),
])
def test_parse(destination, separate, key, state):
    parsed = parse_destination(destination, separate)
    assert parsed.key == key
    assert parsed.state == state


def test_rest_stats_and_independent_object_statuses(tmp_path):
    class WithStats(FakeREST):
        def get(self, path, params=None):
            if path == "/mgmt/tm/gtm/pool/a/stats":
                raise F5APIError(404, path)
            if path == "/mgmt/tm/gtm/pool/a/~Common~pool/stats":
                return nested("https://localhost/mgmt/tm/gtm/pool/a/~Common~pool:A/stats",
                              tmName="/Common/pool", preferred=0,
                              **{"status.availabilityState": "offline", "status.enabledState": "enabled",
                                 "status.statusReason": "No available members"})
            if path.endswith("/members/stats"):
                return nested("scoped", serverName="/Common/BIGIP", virtualServerName="/Common/vs",
                              **{"status.availabilityState": "unavailable"})
            if path.endswith("/virtual-servers/stats"):
                return nested("scoped", virtualServerName="/Common/vs",
                              **{"status.availabilityState": "unknown"})
            return super().get(path, params)

    fake = WithStats()
    fake.details["/mgmt/tm/gtm/server/~Common~BIGIP"]["virtualServers"][0]["destination"] = "192.0.2.77:443"
    snap = Collector(fake, "dns.example.test", scope="core").collect()
    snap.write(tmp_path / "raw")
    audit = analyze(Snapshot.read(tmp_path / "raw"))
    pool = audit.pools[0]
    assert (pool["Health"], pool["Availability"], pool["Preferred"], pool["Status Reason"]) == (
        "OFFLINE", "OFFLINE", 0, "No available members")
    assert pool["Health Source"] == "REST /stats" and pool["Stats UTC"]
    assert pool["Members Unavailable"] == 1
    assert audit.members[0]["Health"] == "UNAVAILABLE"
    assert audit.virtuals[0]["Health"] == "UNKNOWN"
    assert audit.virtuals[0]["Port"] == 443
    assert audit.virtuals[0]["Destination IP"] == "192.0.2.77"
    assert any(x["Status"] == "HTTP_404" for x in audit.collection_health if x["Category"] == "OPERATIONAL")
    wb = load_workbook(as_excel(audit, tmp_path / "report.xlsx"))
    sheet = wb["GSLB Pool Findings"]
    col = [c.value for c in sheet[1]].index("Health") + 1
    assert sheet.cell(2, col).fill.fgColor.rgb.endswith("FEE2E2")
    wb.close()


def test_old_raw_and_no_stats_are_not_a_reported_unknown():
    audit = analyze(sample())
    assert audit.virtuals[0]["Health"] == "NOT OBSERVED"
    assert audit.virtuals[0]["Port"] == 443
    assert audit.virtuals[0]["Health Source"] == "NOT COLLECTED"
    fake = FakeREST()
    output = Collector(fake, "dns.example.test", scope="core", collect_stats=False).collect()
    assert output.meta["operational_stats"] == "SKIPPED"
    assert not any(path.endswith("/stats") for _, path in fake.calls)


@pytest.mark.parametrize("ltm_destination, comparison", [
    ("/Common/192.0.2.1:443", "ADDRESS_PRESENT_DIFFERENT_NAME"),
    ("/Common/192.0.2.1:8443", "IP_PRESENT_DIFFERENT_PORT"),
    ("/Common/192.0.2.1%8:443", "IP_PRESENT_DIFFERENT_ROUTE_DOMAIN"),
    ("/Common/192.0.2.1:any", "LTM_PORT_UNVERIFIABLE"),
])
def test_comparison_never_treats_a_related_endpoint_as_absent(tmp_path, ltm_destination, comparison):
    create_ltm(tmp_path, "ltm.example.test", [{"fullPath": "/Common/vip_other", "destination": ltm_destination}])
    scan = discover_ltm_snapshots([str(tmp_path)])
    audit = analyze(sample(), ltm_scan=scan, ltm_coverage_complete=True)
    assert audit.members[0]["LTM Comparison"] == comparison
    assert not audit.candidates


def test_offline_ltm_can_be_joined_even_under_another_name(tmp_path):
    path = create_ltm(tmp_path, "ltm.example.test", [
        {"fullPath": "/Common/vip_other", "destination": "/Common/192.0.2.1:443"}])
    (path / "sys_failover.json").write_text(json.dumps({"data": {
        "apiRawValues": {"apiAnonymous": "Failover active for 7d"}}}))
    (path / "ltm_virtual_stats.json").write_text(json.dumps({"data": nested(
        "https://localhost/mgmt/tm/ltm/virtual/~Common~vip_other/stats", tmName="/Common/vip_other",
        **{"status.availabilityState": "offline", "clientside.totConns": 9})}))
    audit = analyze(sample(), ltm_scan=discover_ltm_snapshots([str(tmp_path)]), ltm_coverage_complete=True)
    row = audit.members[0]
    assert row["LTM Matched Virtual Server"] == "/Common/vip_other"
    assert row["LTM Stats Role"] == "ACTIVE"
    assert row["LTM Health"] == "OFFLINE"
    assert row["LTM Total connections"] == 9
    assert row["Verdict"] == "MANUAL REVIEW"
    assert not audit.candidates


def test_available_gslb_vs_conflicts_with_apparent_ltm_absence(tmp_path):
    create_ltm(tmp_path, "ltm.example.test", [])
    snap = sample()
    snap.datasets["gtm_server"][0]["virtualServerDiscovery"] = "disabled"
    key = "stats_server_virtuals::/Common/BIGIP1"
    snap.datasets[key] = [{"virtualServerName": "/Common/vs1", "status.availabilityState": "available"}]
    snap.meta["endpoint_results"][key] = "OK"
    audit = analyze(snap, ltm_scan=discover_ltm_snapshots([str(tmp_path)]), ltm_coverage_complete=True)
    assert audit.members[0]["LTM Comparison"] == "NOT_FOUND_IN_SCANNED_LTMS"
    assert audit.members[0]["Verdict"] == "MANUAL REVIEW"
    assert not audit.candidates


def test_snapshot_does_not_persist_credential_fields(tmp_path):
    snap = sample()
    snap.datasets["gtm_rule"] = [{"fullPath": "/Common/rule1", "apiAnonymous": "example-payload"}]
    snap.datasets["gtm_monitor_http"] = [{"name": "mon", "password": "example-password",
                                          "send": "example-request", "nested": {"authToken": "example-token"}}]
    folder = tmp_path / "raw"
    snap.write(folder)
    contents = " ".join(p.read_text() for p in folder.glob("*.json"))
    for sentinel in ("example-payload", "example-password", "example-request", "example-token"):
        assert sentinel not in contents
    assert Snapshot.read(folder).datasets["gtm_monitor_http"][0]["name"] == "mon"
