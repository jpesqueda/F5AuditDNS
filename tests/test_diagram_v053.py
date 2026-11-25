"""Diagram mode regression tests; uses synthetic device identities only."""
from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path

import pytest

from f5auditdns.cli import main, parser
from f5auditdns.collector import Snapshot
from f5auditdns.diagram import build_diagram, partition_of, write_diagram_json
from f5auditdns.diagram_html import render_diagram_html
from f5auditdns.diagram_mock import mock_snapshot
from f5auditdns.analyzer import analyze
from f5auditdns.report import SHEETS

ROOT = Path(__file__).resolve().parent.parent


def graph():
    return build_diagram(mock_snapshot())


def one(data, kind, path):
    return next(n for n in data['nodes'] if n['kind'] == kind and n['fullPath'] == path)


def test_mock_has_three_partitions_and_global_graph():
    data = graph()
    assert data['summary']['partitions'] == 3
    assert {p['partition'] for p in data['tree']['children']} == {'/Common', '/Prod_GSLB', '/DMZ_Externo'}
    assert data['metadata']['readOnly'] is True


def test_full_path_cross_partition_reference_is_not_orphan():
    data = graph()
    path = '/Common/tcp_443'
    monitor = one(data, 'MONITOR', path)
    assert monitor['orphanStatus'] == 'REFERENCED'
    pool = one(data, 'POOL', '/Prod_GSLB/pool_web')
    edge = next(e for e in data['edges'] if e['source'] == pool['id'] and e['target'] == monitor['id'])
    assert edge['crossPartition'] == 'true'
    assert edge['certainty'] == 'EXACT'


def test_wideip_last_resort_is_preserved_as_distinct_edge():
    data = graph()
    w = one(data, 'WIDE_IP', '/Prod_GSLB/www.example.test')
    relations = {e['relation'] for e in data['edges'] if e['source'] == w['id']}
    assert {'DIRECT_POOL', 'LAST_RESORT'} <= relations


def test_virtual_server_reused_across_two_pools():
    data = graph()
    virtual = one(data, 'VIRTUAL_SERVER', '/DMZ_Externo/vs_web_dr')
    edges = [e for e in data['edges'] if e['target'] == virtual['id'] and e['relation'] == 'MEMBER_TARGET']
    assert len(edges) == 2
    assert virtual['referenceCount'] == 2


def test_degraded_health_propagates_to_wideip():
    data = graph()
    assert one(data, 'POOL', '/Prod_GSLB/pool_web')['effectiveHealth'] == 'DEGRADED'
    assert one(data, 'POOL', '/Prod_GSLB/pool_dr')['effectiveHealth'] == 'OFFLINE'
    assert one(data, 'WIDE_IP', '/Prod_GSLB/www.example.test')['effectiveHealth'] == 'DEGRADED'


def test_iquery_is_not_inferred_from_ordinary_offline_health():
    data = graph()
    srv = one(data, 'GSLB_SERVER', '/DMZ_Externo/LTM_DR')
    assert srv['health'] == 'OFFLINE'
    assert srv['iquery'] != 'DISCONNECTED (REPORTED)'


def test_explicit_iquery_field_is_not_guessed():
    snap = mock_snapshot()
    snap.datasets['gtm_server'][1]['iQueryStatus'] = 'disconnected'
    data = build_diagram(snap)
    assert one(data, 'GSLB_SERVER', '/DMZ_Externo/LTM_DR')['iquery'] == 'DISCONNECTED (REPORTED)'


def test_unlinked_monitor_no_implicit_deletion_approval():
    data = graph()
    mon = one(data, 'MONITOR', '/Common/custom_unused')
    assert mon['orphanStatus'] == 'NO VERIFIED REFERENCES IN SNAPSHOT'
    assert mon['reviewRequired'] is True
    assert data['metadata']['approval'] == 'PENDING'
    assert mon['deleteReference'].startswith('NOT RUN:')


def test_server_without_pool_member_is_review_not_delete():
    snap = mock_snapshot()
    snap.datasets['pool_members::a::/Prod_GSLB/pool_web'] = []
    snap.datasets['pool_members::a::/Prod_GSLB/pool_dr'] = []
    data = build_diagram(snap)
    server = one(data, 'GSLB_SERVER', '/Common/LTM_PRIMARY')
    assert server['orphanStatus'] == 'NO ACTIVE POOL MEMBERS FOUND — REVIEW'


def test_incomplete_inventory_never_claims_verified_unreferenced():
    snap = mock_snapshot()
    snap.meta['endpoint_results']['gtm_rule'] = 'HTTP_403'
    data = build_diagram(snap)
    assert not data['metadata']['coreAndDynamicInventoryComplete']
    assert one(data, 'MONITOR', '/Common/custom_unused')['orphanStatus'] == 'INVENTORY INCOMPLETE'


def test_irule_presence_blocks_orphan_assertion():
    snap = mock_snapshot()
    snap.datasets['gtm_rule'] = [{'fullPath': '/Common/rule_web', 'definition': 'when DNS_REQUEST { pool /Common/pool_unused }'}]
    data = build_diagram(snap)
    assert data['metadata']['dynamicReferencesExist'] is True
    assert one(data, 'POOL', '/Common/pool_unused')['orphanStatus'] == 'POSSIBLE INDIRECT REFERENCES'
    raw = one(data, 'IRULE', '/Common/rule_web')['raw']
    assert 'definition' not in raw  # no embedded opaque rule body


def test_topology_explicit_pool_reference_is_recorded():
    snap = mock_snapshot()
    snap.datasets['gtm_topology'] = [{'fullPath': '/Common/topo1', 'pool': '/Common/pool_unused'}]
    data = build_diagram(snap)
    pool = one(data, 'POOL', '/Common/pool_unused')
    assert any(e['target'] == pool['id'] and e['relation'] == 'TOPOLOGY_OR_DYNAMIC_POOL'
               for e in data['edges'])
    assert pool['orphanStatus'] == 'POSSIBLE INDIRECT REFERENCES'


def test_server_virtual_destination_keeps_port_and_ip():
    data = graph()
    vs = one(data, 'VIRTUAL_SERVER', '/Common/vs_web')
    assert vs['ip'] == '192.0.2.10'
    assert vs['port'] == 443


def test_pool_member_partition_is_parent_pool_partition():
    data = graph()
    member = next(n for n in data['nodes'] if n['kind'] == 'POOL_MEMBER')
    assert member['partition'] == '/Prod_GSLB'
    assert member['targetPartition'] in {'/Common', '/DMZ_Externo'}


def test_html_escapes_script_delimiters(tmp_path):
    data = graph()
    data['nodes'][0]['name'] = '</script><script>alert(1)</script>'
    html = render_diagram_html(data, tmp_path / 'topology.html').read_text(encoding='utf-8')
    assert '</script><script>alert(1)</script>' not in html
    assert '\\u003c/script\\u003e' in html
    assert 'gtm_topology.json' in html


def test_offline_fallback_exists_without_extra_dependencies(tmp_path):
    html = render_diagram_html(graph(), tmp_path / 'topology.html').read_text(encoding='utf-8')
    assert 'Offline SVG fallback' in html
    assert "location.protocol !== 'file:'" in html
    assert 'd3.tree()' in html
    assert '__INLINE_DATA__' not in html


def test_embed_d3_bundle_from_local_file(tmp_path):
    source = tmp_path / 'd3.v7.min.js'
    source.write_text('window.d3={version:"7.9.0"};', encoding='utf-8')
    content = render_diagram_html(graph(), tmp_path / 'diagram.html', d3_js=source).read_text(encoding='utf-8')
    assert 'version:"7.9.0"' in content


def test_refuses_html_script_breakout_in_user_supplied_d3(tmp_path):
    source = tmp_path / 'not_d3.js'
    source.write_text('</script><script>evil()</script>', encoding='utf-8')
    with pytest.raises(ValueError, match='unsafe inline script'):
        render_diagram_html(graph(), tmp_path / 'diagram.html', d3_js=source)


def test_mock_cli_generates_both_files_without_device(tmp_path):
    output = tmp_path / 'diagram'
    assert main(['diagram', '--mock', '-o', str(output)]) == 0
    assert (output/'gtm_topology.json').is_file()
    assert (output/'f5_dns_topology.html').is_file()
    assert json.loads((output/'gtm_topology.json').read_text(encoding='utf-8'))['summary']['partitions'] == 3


def test_alias_diagram_raw_existing_snapshot(tmp_path):
    target = tmp_path / 'render'
    assert main(['--diagram', '--raw', str(ROOT/'examples'/'raw_cleanup_simulado'),
                 '--format', 'json', '-o', str(target)]) == 0
    assert (target/'gtm_topology.json').exists()
    assert not (target/'f5_dns_topology.html').exists()


def test_existing_snapshot_and_ltm_raw_compatible(tmp_path):
    target = tmp_path / 'render'
    assert main(['diagram', '--raw', str(ROOT/'examples'/'raw_cleanup_simulado'),
                 '--ltm-raw-dir', str(ROOT/'examples'/'ltm_raws_multi_simulado'),
                 '-o', str(target)]) == 0
    data = json.loads((target/'gtm_topology.json').read_text(encoding='utf-8'))
    assert data['summary']['nodes'] > 0
    assert any(n['kind']=='VIRTUAL_SERVER' for n in data['nodes'])


def test_no_raw_inspector_excludes_config(tmp_path):
    out = tmp_path / 'x'
    assert main(['diagram', '--mock', '--no-raw-inspector', '-o', str(out)]) == 0
    data = json.loads((out/'gtm_topology.json').read_text(encoding='utf-8'))
    assert all('Object JSON omitted' in n['raw'].get('_note','') for n in data['nodes'])


def test_invalid_options_do_not_create_files(tmp_path):
    assert main(['diagram', '-o', str(tmp_path/'out')]) == 1
    assert main(['diagram', '--mock', '--raw', 'some_dir', '-o', str(tmp_path/'out')]) == 1
    assert not (tmp_path/'out').exists()


def test_no_collect_or_excel_regression():
    args = parser().parse_args(['diagram', '--mock'])
    assert args.command == 'diagram'
    original = [title for title,_ in SHEETS if title not in ('FreedIP','Search Results')]
    assert 'Pool Members' in original and 'GSLB Virtual Servers' in original
    assert len(original) >= 17


def test_fullpath_with_subpath_partition_preserved():
    assert partition_of('/Prod_GSLB/apps/region/service') == '/Prod_GSLB'
    assert partition_of('/Common/my-object') == '/Common'


def test_json_write_creates_parent_directory(tmp_path):
    target = tmp_path / 'nested' / 'graph.json'
    write_diagram_json(graph(), target)
    assert json.loads(target.read_text(encoding='utf-8'))['schema'] == 'f5auditdns.diagram.v1'


def test_tmos_version_is_read_from_existing_sys_version():
    data = graph()
    assert data['metadata']['tmosVersion'] == '17.5.1'
    assert data['metadata']['tmosBuild'] == '0.0.1'


def test_user_can_override_device_display_without_changing_raw(tmp_path):
    folder = tmp_path / 'diagram'
    assert main(['diagram', '--mock', '--device-label', 'dns-alias.example.test', '-o', str(folder)]) == 0
    data = json.loads((folder/'gtm_topology.json').read_text(encoding='utf-8'))
    assert data['metadata']['device'] == 'dns-alias.example.test'
    assert data['tree']['label'] == 'dns-alias.example.test'
    assert data['metadata']['scope'] == 'all'


def test_cross_partition_datacenter_prober_pool_counts_as_reference():
    snap = mock_snapshot()
    snap.datasets['gtm_prober_pool'] = [{'fullPath': '/Common/prober_shared'}]
    snap.datasets['gtm_datacenter'][1]['proberPool'] = '/Common/prober_shared'
    data = build_diagram(snap)
    prober = one(data, 'PROBER_POOL', '/Common/prober_shared')
    dc = one(data, 'DATA_CENTER', '/DMZ_Externo/DC_BACKUP')
    assert any(e['source'] == dc['id'] and e['target'] == prober['id']
               and e['crossPartition'] == 'true' and e['relation']=='USES_PROBER_POOL'
               for e in data['edges'])
    assert prober['orphanStatus'] == 'REFERENCED'


def test_wideip_attached_irule_is_referenced_without_inspecting_rule_body():
    snap = mock_snapshot()
    snap.datasets['gtm_rule'] = [{'fullPath': '/Common/rule_service', 'definition':'redacted'}]
    snap.datasets['gtm_wideip_a'][0]['rules'] = ['/Common/rule_service']
    data = build_diagram(snap)
    rule = one(data, 'IRULE', '/Common/rule_service')
    assert rule['orphanStatus'] == 'REFERENCED'
    assert 'definition' not in rule['raw']
