"""Regression tests for the read-only reference graph and cleanup simulator."""
from __future__ import annotations

import copy
import csv
from pathlib import Path

import pytest

from f5auditdns.analyzer import analyze
from f5auditdns.collector import Snapshot
from f5auditdns.freedip import load_freed_ips, match_freed_ip
from f5auditdns.report import SHEETS, as_excel

ROOT = Path(__file__).resolve().parent.parent


def fixture_snapshot():
    return Snapshot.read(ROOT / 'examples' / 'raw_cleanup_simulado')


def audited(*tokens):
    snap = fixture_snapshot()
    return analyze(snap, freed_ips=load_freed_ips(tokens[0]) if tokens else None)


def test_all_original_sheets_remain_in_the_same_order():
    original = ['Summary', 'Wide IP Findings', 'GSLB Pool Findings', 'Pool Members',
                'GSLB Servers', 'GSLB Virtual Servers', 'Data Centers', 'DNS Chains',
                'Cleanup Candidates', 'LTM Inventories', 'Manual Review',
                'Auxiliary Inventory', 'Collection Health']
    assert [x[0] for x in SHEETS[:13]] == original
    assert [x[0] for x in SHEETS[13:]] == ['Reference Map', 'Object Inventory',
                                             'Pool Impact', 'Cleanup Procedure', 'FreedIP']


def test_direct_and_last_resort_are_distinct():
    a = audited()
    refs = {p['Pool']: p['Wide IP Reference'] for p in a.pools}
    assert '[LAST RESORT]' in refs['/Common/pool_fallback']
    assert '[DIRECT]' not in refs['/Common/pool_fallback']
    assert '[DIRECT]' in refs['/Common/pool_app']


def test_ip_only_freed_evidence_is_never_approval(tmp_path):
    source = tmp_path / 'retired.txt'
    source.write_text('192.0.2.200\n', encoding='utf-8')
    a = audited(source)
    retired = next(m for m in a.members if m['Pool'].endswith('pool_retired'))
    assert retired['FreedIP Match'] == 'IP ONLY - REVIEW'
    assert retired['Approval Status'] == 'PENDING'
    assert 'NOT RUN:' in retired['Delete pool member']
    assert retired['Cleanup Readiness'].startswith('REVIEW')
    impact = next(p for p in a.pool_impact if p['GSLB Pool'].endswith('pool_retired'))
    assert (impact['Current Members'], impact['Marked Members'], impact['Members After Removal']) == (1, 1, 0)
    assert impact['Pool Action'] == 'REVIEW EMPTY POOL'
    assert 'retired.example.test' in impact['Wide IP References']


def test_multi_member_pool_impact_is_stable_across_member_rows(tmp_path):
    file = tmp_path / 'list.txt'
    file.write_text('192.0.2.100\n', encoding='utf-8')
    a = audited(file)
    members = [m for m in a.members if m['Pool'] == '/Common/pool_app']
    assert len(members) == 2
    assert {m['Members After Marked Removal'] for m in members} == {1}
    assert {m['Pool Action'] for m in members} == {'KEEP POOL'}


def test_one_virtual_used_in_multiple_pools():
    snap = fixture_snapshot()
    extra = {'name': 'pool_shared', 'fullPath': '/Common/pool_shared', 'enabled': True}
    snap.datasets['gtm_pool_a'].append(extra)
    snap.datasets['pool_members::a::/Common/pool_shared'] = [
        {'name': '/Common/GDL-F5:/Common/vs_app', 'enabled': True}]
    snap.meta['endpoint_results']['pool_members::a::/Common/pool_shared'] = 'OK'
    a = analyze(snap)
    v = next(v for v in a.virtuals if v['Server'] == '/Common/GDL-F5' and v['Virtual Server'] == '/Common/vs_app')
    assert v['Current Pool Reference Count'] == 2
    assert 'REMOVE 2 POOL MEMBER' in v['VS Cleanup Action']
    assert 'pool_shared' in v['Current Pool References']


def test_auto_discovery_requires_review():
    a = audited()
    v = next(v for v in a.virtuals if v['Server'] == '/Common/QRO-F5')
    assert 'AUTO DISCOVERY' in v['VS Cleanup Action']


def test_dynamic_rules_block_orphan_certainty():
    snap = fixture_snapshot()
    snap.datasets['gtm_rule'] = [{'fullPath': '/Common/dynamic_router'}]
    a = analyze(snap)
    row = next(p for p in a.pools if p['Pool'] == '/Common/pool_orphan')
    assert 'DYNAMIC' in row['Reference Confidence']
    assert row['Approval Status'] == 'PENDING'


def test_incomplete_inventory_never_becomes_verified_unused():
    snap = fixture_snapshot()
    snap.meta['endpoint_results']['gtm_pool_a'] = 'HTTP_403'
    a = analyze(snap)
    assert any('UNVERIFIED' in x.get('Reference Confidence', '')
               or 'UNKNOWN' in x.get('Reference Confidence', '') for x in a.reference_map)
    assert all(r['Approval Status'] == 'PENDING' for r in a.pool_impact)


def test_route_domain_port_and_port_zero(tmp_path):
    fn = tmp_path / 'free.csv'
    fn.write_text('192.0.2.42%3:443,192.0.2.43:0\n192.0.2.44\n', encoding='utf-8')
    entries = load_freed_ips(fn)
    assert len(entries) == 3
    assert match_freed_ip('192.0.2.42', 443, 3, entries)[1].startswith('IP+PORT+ROUTE DOMAIN')
    assert match_freed_ip('192.0.2.42', 443, 4, entries)[1] == 'IP MATCH, ENDPOINT CONFLICT'
    assert match_freed_ip('192.0.2.43', 0, '', entries)[1].startswith('IP+PORT')
    assert match_freed_ip('192.0.2.43', 80, '', entries)[1] == 'IP MATCH, ENDPOINT CONFLICT'


def test_csv_xlsx_multi_column_import(tmp_path):
    from openpyxl import Workbook
    file = tmp_path / 'retired.xlsx'
    wb = Workbook()
    sheet = wb.active
    sheet.append(['Gateway', 'Decommissioned IPs', 'Notes'])
    sheet.append(['192.0.2.25', '198.51.100.77:443', 'do not parse 192.0.2.12 from text'])
    sheet.append(['198.51.100.80', '192.0.2.25', None])
    wb.save(file)
    records = load_freed_ips(file)
    assert {r.ip for r in records} == {'192.0.2.25', '198.51.100.77', '198.51.100.80'}
    assert len(records) == 3


def test_invalid_freed_file_rejected(tmp_path):
    with pytest.raises(ValueError):
        load_freed_ips(tmp_path / 'none.xlsx')
    bad = tmp_path / 'notvalid.exe'
    bad.write_text('192.0.2.1')
    with pytest.raises(ValueError):
        load_freed_ips(bad)


def test_unusual_identifiers_never_create_executable_commands():
    from f5auditdns.reference_engine import _remove_gtm, _dynamic_checks
    assert 'REVIEW REQUIRED' in _remove_gtm('pool', '/Common/bad;rm', 'a')
    assert 'REVIEW REQUIRED' in _dynamic_checks('/Common/$(whoami)')


def test_all_reference_change_commands_non_executable():
    a = audited()
    for group, columns in ((a.members, ('Delete pool member', 'Delete pool')),
                           (a.virtuals, ('Delete virtual server',)),
                           (a.pools, ('Delete pool',)),
                           (a.wideips, ('Delete wide ip',)),
                           (a.servers, ('Delete GSLB Server',)),
                           (a.datacenters, ('Delete Data Center',))):
        for row in group:
            for col in columns:
                assert row[col].startswith(('NOT RUN:', 'REVIEW REQUIRED:'))
    assert all(row['Rollback Status'] == 'ROLLBACK INCOMPLETE' for row in a.members)
    assert all(row['Approval Status'] == 'PENDING' for row in a.members)


def test_old_snapshot_generates_four_new_sheets(tmp_path):
    from zipfile import ZipFile
    a = audited()
    output = tmp_path / 'audit.xlsx'
    as_excel(a, output)
    with ZipFile(output) as z:
        names = z.read('xl/workbook.xml').decode('utf-8')
        for title in ('Reference Map', 'Object Inventory', 'Pool Impact', 'Cleanup Procedure'):
            assert f'name="{title}"' in names
        assert 'name="FreedIP"' not in names
        assert 'name="Summary"' in names


def test_freedip_sheet_is_optional_and_present_when_supplied(tmp_path):
    from zipfile import ZipFile
    path = tmp_path / 'free.txt'
    path.write_text('192.0.2.200')
    a = audited(path)
    output = tmp_path / 'with_free.xlsx'
    as_excel(a, output)
    with ZipFile(output) as z:
        assert 'name="FreedIP"' in z.read('xl/workbook.xml').decode('utf-8')


def test_inventory_contains_unused_and_auxiliary_objects():
    a = audited()
    assert any(x['Object Type'] == 'gtm_listener' for x in a.object_inventory)
    assert any(x['Object Name'] == '/Common/pool_orphan' for x in a.object_inventory)
    assert len(a.object_inventory) >= len(a.members) + len(a.virtuals)


def test_chain_includes_change_pre_and_post_checks():
    a = audited()
    assert any(x.get('Check Wide IP') and x.get('Check Pool') for x in a.chains)
    assert all(x['Approval Status'] == 'PENDING' for x in a.cleanup_procedure)
    assert len(a.cleanup_procedure) >= 11
    assert any('COMPLETE WIDE IP DECOMMISSION' in x['Stage'] for x in a.cleanup_procedure)


def test_original_stats_and_ltm_fields_not_dropped():
    a = audited()
    assert 'LTM Comparison' in a.members[0]
    assert 'LTM Health' in a.members[0]
    assert 'Health Source' in a.members[0]
    assert 'Destination IP' in a.virtuals[0]
    assert a.collection_health
