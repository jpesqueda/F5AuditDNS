"""Offline regression tests; no BIG-IP or network access required."""
import pytest

from f5auditdns.analyzer import analyze, resolve_member
from f5auditdns.collector import Snapshot, SnapshotError, inline_items, safe_api_path
from f5auditdns.report import _safe_cell


def sample():
    import runpy
    from pathlib import Path
    # Build a minimal mock without writing to the actual examples folder.
    rows = {
        "gtm_datacenter": [{"fullPath": "/Common/DC1"}],
        "gtm_server": [{"fullPath": "/Common/BIGIP1", "datacenter": "/Common/DC1"}],
        "server_virtuals::/Common/BIGIP1": [{"fullPath": "/Common/vs1", "destination": "192.0.2.1:443"}],
        "gtm_wideip_a": [{"fullPath": "/Common/app.example", "lastResortPool": "/Common/fallback"}],
        "wideip_pools::a::/Common/app.example": [{"name": "pool1"}],
        "gtm_pool_a": [{"fullPath": "/Common/pool1"}],
        "pool_members::a::/Common/pool1": [{"name": "/Common/BIGIP1:/Common/vs1"}],
        "gtm_pool_cname": [{"fullPath": "/Common/fallback"}],
        "pool_members::cname::/Common/fallback": [],
        "gtm_rule": [], "gtm_distributed_app": [],
    }
    from f5auditdns.collector import RECORD_TYPES
    for rr in RECORD_TYPES:
        rows.setdefault(f"gtm_pool_{rr}", [])
        rows.setdefault(f"gtm_wideip_{rr}", [])
    meta = {"tool": "f5auditdns", "collection_id": "test-123", "host": "dns1",
            "scope": "all", "collected_at": "2026-11-11T00:00:00+00:00",
            "endpoint_results": {k: "OK" for k in rows}, "endpoint_paths": {}}
    snap = Snapshot(meta)
    snap.datasets = rows
    return snap


def test_wideip_pool_member_server_chain():
    a = analyze(sample())
    assert len(a.chains) == 2
    assert any(x["Server"] == "/Common/BIGIP1" and x["Virtual Server"] == "/Common/vs1"
               for x in a.chains)
    assert any(x["Pool"] == "/Common/fallback" for x in a.chains)
    assert all(x["Finding"] != "MANUAL REVIEW: no direct Wide IP reference"
               for x in a.pools if x["Pool"] == "/Common/fallback")


def test_missing_member_subcollection_does_not_mean_empty():
    snap = sample()
    snap.datasets.pop("pool_members::a::/Common/pool1")
    snap.meta["endpoint_results"]["pool_members::a::/Common/pool1"] = "UNKNOWN"
    result = analyze(snap)
    p = next(x for x in result.pools if x["Pool"] == "/Common/pool1")
    assert p["Member count"] is None
    assert "unknown" in p["Finding"]


def test_incomplete_core_inventory_is_flagged():
    snap = sample()
    snap.meta["endpoint_results"]["gtm_pool_a"] = "HTTP_403"
    report = analyze(snap)
    assert {x["Metric"]: x["Value"] for x in report.summary}["Complete core catalog"] == "NO"
    assert any("Core inventory incomplete" in x["Reason"] for x in report.manual_review)


def test_ambiguous_server_mapping_is_not_guessed():
    registry = {("/Common/X", "/Common/vs"): "a", ("/Other/X", "/Other/vs"): "b"}
    assert resolve_member("X:vs", registry)[2] == "AMBIGUOUS"


def test_inline_items_and_no_ssrf():
    assert inline_items({"members": ["foo", {"name": "bar"}]}, "members") == [{"name": "foo"}, {"name": "bar"}]
    assert safe_api_path("https://evil.invalid/mgmt/tm/gtm/server?ver=1") == "/mgmt/tm/gtm/server"
    assert safe_api_path("https://evil.invalid/steal-token") is None


def test_snapshot_roundtrip_and_mixed_id_detection(tmp_path):
    snap = sample()
    snap.write(tmp_path / "snapshot")
    loaded = Snapshot.read(tmp_path / "snapshot")
    assert loaded.datasets == snap.datasets
    with pytest.raises(SnapshotError):
        loaded.write(tmp_path / "snapshot")
    file = next(x for x in (tmp_path / "snapshot").glob("*.json") if x.name != "_meta.json")
    file.write_text(file.read_text().replace("test-123", "other-id"))
    with pytest.raises(SnapshotError):
        Snapshot.read(tmp_path / "snapshot")


def test_formula_injection_protection():
    assert _safe_cell("=HYPERLINK('x')").startswith("'")
    assert _safe_cell("-1+2").startswith("'")
    assert _safe_cell("normal") == "normal"

class FakeREST:
    """Tiny iControl REST stub for verifying collector behavior without networking."""
    def __init__(self, fail_path=None):
        self.fail_path = fail_path
        self.calls = []
        self.base = {
            "/mgmt/tm/gtm/datacenter": [{"fullPath": "/Common/DC", "name": "DC"}],
            "/mgmt/tm/gtm/server": [{"fullPath": "/Common/BIGIP", "name": "BIGIP",
                "selfLink": "https://127.0.0.1/mgmt/tm/gtm/server/~Common~BIGIP?ver=17.1"}],
            "/mgmt/tm/gtm/wideip/a": [{"fullPath": "/Common/app.example", "name": "app.example",
                "selfLink": "https://127.0.0.1/mgmt/tm/gtm/wideip/a/~Common~app.example?ver=17.1"}],
            "/mgmt/tm/gtm/pool/a": [{"fullPath": "/Common/pool", "name": "pool",
                "selfLink": "https://127.0.0.1/mgmt/tm/gtm/pool/a/~Common~pool?ver=17.1"}],
        }
        self.details = {
            "/mgmt/tm/gtm/server/~Common~BIGIP": {"virtualServers": [{"fullPath": "/Common/vs"}]},
            "/mgmt/tm/gtm/wideip/a/~Common~app.example": {"pools": [{"name": "pool"}]},
            "/mgmt/tm/gtm/pool/a/~Common~pool": {"members": [{"name": "/Common/BIGIP:/Common/vs"}]},
        }

    def get_collection(self, path, params=None):
        from f5auditdns.client import F5APIError
        self.calls.append(("GET_COLLECTION", path))
        if path == self.fail_path:
            raise F5APIError(403, path)
        return self.base.get(path, [])

    def get(self, path, params=None):
        self.calls.append(("GET", path))
        if path in self.details:
            return self.details[path]
        return {"items": []}


def test_collector_expands_details_and_never_posts():
    from f5auditdns.collector import Collector
    fake = FakeREST()
    result = Collector(fake, "192.0.2.10", scope="core").collect()
    assert result.datasets["pool_members::a::/Common/pool"][0]["name"] == "/Common/BIGIP:/Common/vs"
    assert result.datasets["wideip_pools::a::/Common/app.example"][0]["name"] == "pool"
    assert result.datasets["server_virtuals::/Common/BIGIP"][0]["fullPath"] == "/Common/vs"
    assert all(method.startswith("GET") for method, _ in fake.calls)
    assert result.meta["warning_count"] == 0


def test_http_403_is_data_gap_not_empty():
    from f5auditdns.collector import Collector
    fake = FakeREST(fail_path="/mgmt/tm/gtm/pool/a")
    snapshot = Collector(fake, "192.0.2.10", scope="core").collect()
    assert "gtm_pool_a" not in snapshot.datasets
    assert snapshot.meta["endpoint_results"]["gtm_pool_a"] == "HTTP_403"
    report = analyze(snapshot)
    assert any(item["Priority"] == "DATA GAP" for item in report.manual_review)


def test_network_failure_retains_partial_snapshot():
    from f5auditdns.collector import Collector
    from f5auditdns.client import F5ClientError
    class Broken(FakeREST):
        def get_collection(self, path, params=None):
            if path == "/mgmt/tm/gtm/pool/a":
                raise F5ClientError("simulated timeout")
            return super().get_collection(path, params)
    result = Collector(Broken(), "192.0.2.10", scope="core").collect()
    assert result.meta.get("aborted")
    assert "gtm_datacenter" in result.datasets
    assert result.meta["warning_count"] >= 1


# CLI improvements in v0.1.1: local dated output and follow-up command.
def test_collect_default_folder_uses_actual_device_hostname(tmp_path, monkeypatch, capsys):
    from f5auditdns import cli
    monkeypatch.chdir(tmp_path)

    class HostREST(FakeREST):
        def get(self, path, params=None):
            if path == "/mgmt/tm/sys/global-settings":
                self.calls.append(("GET", path))
                return {"hostname": "dns01.corp.example"}
            return super().get(path, params)

    client = HostREST()
    monkeypatch.setattr(cli, "make_client", lambda args: client)
    code = cli.main(["collect", "-ho", "192.0.2.20", "-u", "auditor", "--insecure"])
    assert code == 0
    folders = list(tmp_path.glob("f5auditDNS_raw_dns01.corp.example_*"))
    assert len(folders) == 1
    assert (folders[0] / "_meta.json").exists()
    saved = Snapshot.read(folders[0])
    assert saved.meta["device_hostname"] == "dns01.corp.example"
    output = capsys.readouterr().out
    assert "Next step: analyze this snapshot" in output
    assert "f5auditdns analyze --from-raw" in output
    assert folders[0].name in output
    assert "DNS_Audit.xlsx" in output
    assert all(not method.startswith("POST") for method, _ in client.calls)


def test_collect_falls_back_to_management_name_when_hostname_forbidden(tmp_path, monkeypatch, capsys):
    from f5auditdns import cli
    from f5auditdns.client import F5APIError
    monkeypatch.chdir(tmp_path)

    class NoHostname(FakeREST):
        def get(self, path, params=None):
            if path == "/mgmt/tm/sys/global-settings":
                raise F5APIError(403, path)
            return super().get(path, params)

    monkeypatch.setattr(cli, "make_client", lambda args: NoHostname())
    code = cli.main(["collect", "-ho", "f5auditdns.com", "-u", "auditor"])
    assert code == 0
    assert len(list(tmp_path.glob("f5auditDNS_raw_f5auditdns.com_*"))) == 1
    assert "using -ho value" in capsys.readouterr().out


def test_collect_explicit_folder_does_not_query_hostname(tmp_path, monkeypatch, capsys):
    from f5auditdns import cli
    monkeypatch.chdir(tmp_path)
    fake = FakeREST()
    monkeypatch.setattr(cli, "make_client", lambda args: fake)
    code = cli.main(["collect", "-ho", "192.0.2.20", "-u", "auditor",
                     "-o", str(tmp_path / "raw_dns")])
    assert code == 0
    assert not any(path == "/mgmt/tm/sys/global-settings" for _, path in fake.calls)
    assert (tmp_path / "raw_dns" / "_meta.json").exists()
    assert "Next step:" in capsys.readouterr().out


def test_default_dir_is_collision_resistant_and_path_safe(tmp_path, monkeypatch):
    from datetime import datetime
    from f5auditdns.cli import auto_snapshot_directory
    monkeypatch.chdir(tmp_path)
    instant = datetime(2026, 11, 11, 16, 53, 0)
    first = auto_snapshot_directory("dns/server:01\\bad", instant)
    assert first.name == "f5auditDNS_raw_dns_server_01_bad_20261111_1653"
    first.mkdir()
    second = auto_snapshot_directory("dns/server:01\\bad", instant)
    assert second.name == first.name + "_02"


def test_help_includes_hostname_and_insecure_examples(capsys):
    from f5auditdns import cli
    import pytest
    for command in ([], ["validate"], ["collect"]):
        with pytest.raises(SystemExit) as result:
            cli.main(command + ["--help"])
        assert result.value.code == 0
        output = capsys.readouterr().out
        assert "f5auditdns.com" in output
        assert "--insecure" in output
        assert "\\raw_dns" in output or command == ["validate"]


def test_default_dir_same_minute_collision_uses_sequence(tmp_path, monkeypatch):
    from datetime import datetime
    from f5auditdns.cli import auto_snapshot_directory
    monkeypatch.chdir(tmp_path)
    first = auto_snapshot_directory("f5dns-prod-01.midominio.com", datetime(2026, 11, 11, 16, 53, 5))
    assert first.name == "f5auditDNS_raw_f5dns-prod-01.midominio.com_20261111_1653"
    first.mkdir()
    second = auto_snapshot_directory("f5dns-prod-01.midominio.com", datetime(2026, 11, 11, 16, 53, 59))
    assert second.name == first.name + "_02"

