"""Rollback reference and change procedure tests using synthetic fixtures only."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from unittest.mock import patch

import pytest

from f5auditdns.analyzer import analyze
from f5auditdns.change_plan import Selection, parse_approvals, write_change_plan
from f5auditdns.collector import Snapshot
from f5auditdns.rollback_engine import enrich_rollback
from f5auditdns.tmsh_backup import TmshBackup, _brace_close, capture_tmsh_ssh
from f5auditdns.cli import main, parser

ROOT = Path(__file__).resolve().parent.parent
TM = ROOT / 'examples' / 'tmsh_backup_SIMULATED'
RAW = ROOT / 'examples' / 'raw_cleanup_simulado'


def audit():
    return analyze(Snapshot.read(RAW))


def test_original_rest_only_is_not_marked_restorable():
    a = audit()
    assert all(x['Rollback Status'] == 'ROLLBACK INCOMPLETE' for x in a.pools)


def test_pool_rollback_contains_nested_original_configuration():
    rb = TmshBackup(TM).restore('pool', 'a', '/Common/pool_app')
    assert rb.status == 'CAPTURED - VERIFY TMSH SYNTAX'
    assert 'tmsh create gtm pool a /Common/pool_app' in rb.command
    assert 'load-balancing-mode round-robin' in rb.command
    assert 'ratio 3' in rb.command
    assert 'members {' in rb.command
    assert rb.source_sha256


def test_member_rollback_preserves_original_ratio_order_and_status():
    rb = TmshBackup(TM).restore('pool', 'a', '/Common/pool_app',
                                member='/Common/GDL-F5:/Common/vs_app')
    assert rb.status.startswith('CAPTURED')
    assert 'members add' in rb.command
    assert 'member-order 0' in rb.command
    assert 'ratio 1' in rb.command
    assert 'enabled' in rb.command


def test_gslb_vs_rollback_is_modify_server_not_ltm_virtual():
    rb = TmshBackup(TM).restore('server', '', '/Common/vs_app', server='/Common/GDL-F5')
    assert 'tmsh modify gtm server /Common/GDL-F5 virtual-servers add' in rb.command
    assert 'destination /Common/192.0.2.100:443' in rb.command
    assert 'tmsh create ltm' not in rb.command


def test_missing_original_stays_incomplete():
    rb = TmshBackup(TM).restore('pool', 'a', '/Common/not_in_capture')
    assert rb.status == 'ROLLBACK INCOMPLETE'
    assert not rb.command
    assert 'missing' in rb.reason.lower()


def test_partial_capture_balanced_braces_fail_closed(tmp_path):
    (tmp_path / 'gtm_pool_a.txt').write_text('gtm pool a /Common/bad { members { x { ratio 1 } }', encoding='utf-8')
    with pytest.raises(ValueError, match='Unbalanced'):
        TmshBackup(tmp_path)


def test_sensitive_password_omitted_from_excel_reference(tmp_path):
    (tmp_path / 'gtm_server_all.txt').write_text(
        'gtm server /Common/S {\n  password SENSITIVE_EXAMPLE_DO_NOT_LEAK\n}\n', encoding='utf-8')
    rb = TmshBackup(tmp_path).restore('server', '', '/Common/S')
    assert rb.status == 'BACKUP CAPTURED - SENSITIVE'
    assert 'SENSITIVE_EXAMPLE_DO_NOT_LEAK' not in rb.command
    assert 'tmsh create gtm server' not in rb.command


def test_backs_up_config_hash_enforced(tmp_path):
    content = 'gtm pool a /Common/pool { disabled }\n'
    (tmp_path / 'gtm_pool_a.txt').write_text(content, encoding='utf-8')
    manifest = {'files': {'gtm_pool_a.txt': {'sha256': hashlib.sha256((tmp_path / 'gtm_pool_a.txt').read_bytes()).hexdigest()}}}
    (tmp_path / '_tmsh_manifest.json').write_text(json.dumps(manifest), encoding='utf-8')
    assert len(TmshBackup(tmp_path).blocks) == 1
    (tmp_path / 'gtm_pool_a.txt').write_text(content+'tampered', encoding='utf-8')
    with pytest.raises(ValueError, match='checksum mismatch'):
        TmshBackup(tmp_path)


def test_unknown_tmsh_names_skipped(tmp_path):
    (tmp_path / 'gtm_pool_a.txt').write_text(
        'gtm pool a /Common/ok { enabled }\ngtm pool a /Common/evil;whoami { enabled }\n', encoding='utf-8')
    backup = TmshBackup(tmp_path)
    assert len(backup.blocks) == 1
    assert backup.warnings


def test_enrich_preserves_all_original_audit_sheets():
    a = audit()
    original = {x: len(getattr(a, x)) for x in ('summary', 'pools', 'members', 'virtuals', 'wideips',
                                                 'servers', 'datacenters', 'reference_map','pool_impact')}
    enrich_rollback(a, TmshBackup(TM))
    for sheet, length in original.items():
        assert len(getattr(a, sheet)) == (length+2 if sheet=='summary' else length)
    assert a.members[0]['Rollback Source'] == 'gtm_pool_a.txt'
    assert a.pools[0]['Rollback SHA256']
    assert a.pools[0]['Recreate pool (Rollback)'].startswith('NOT RUN: tmsh create')


def test_approval_manifest_needs_explicit_ticket_and_status(tmp_path):
    f = tmp_path/'approved.txt'
    f.write_text('APPROVED|MEMBER|a|/Common/pool_app|/Common/GDL-F5:/Common/vs_app|CHG-12345\n', encoding='utf-8')
    assert parse_approvals(f)[0].approved
    f.write_text('APPROVED|POOL|a|/Common/pool_app||\n', encoding='utf-8')
    with pytest.raises(ValueError, match='ticket'):
        parse_approvals(f)


def test_no_automatic_approval_from_freed_ip_match(tmp_path):
    a=audit();enrich_rollback(a,TmshBackup(TM))
    sel=[Selection('MEMBER','a','/Common/pool_app','/Common/GDL-F5:/Common/vs_app','CHG-1',False)]
    out=write_change_plan(a,tmp_path/'procedure.txt',sel)
    content=Path(out).read_text(encoding='utf-8')
    assert 'APPROVAL PENDING' in content
    assert 'BLOCKED: resolve all blockers' in content
    assert 'members add' in content


def test_approved_member_can_produce_reference_not_execute(tmp_path):
    a=audit();enrich_rollback(a,TmshBackup(TM))
    sel=[Selection('MEMBER','a','/Common/pool_app','/Common/GDL-F5:/Common/vs_app','CHG-1',True)]
    out=write_change_plan(a,tmp_path/'procedure.txt',sel)
    text=Path(out).read_text(encoding='utf-8')
    assert 'REVIEW-READY - NOT EXECUTED' in text
    assert 'NOT RUN: tmsh modify gtm pool a /Common/pool_app members delete' in text
    assert 'NOT RUN: tmsh modify gtm pool a /Common/pool_app members add' in text


def test_pool_with_active_members_and_wideip_blocked_even_if_approved(tmp_path):
    a=audit();enrich_rollback(a,TmshBackup(TM))
    sel=[Selection('POOL','a','/Common/pool_app','','CHG-1',True)]
    out=write_change_plan(a,tmp_path/'procedure.txt',sel)
    text=Path(out).read_text(encoding='utf-8')
    assert 'POOL HAS 2 MEMBER(S) NOT APPROVED' in text
    assert 'POOL HAS WIDE IP / LAST RESORT REFERENCE' in text
    assert 'BLOCKED: resolve all blockers' in text


def test_missing_backup_blocks_approved_action(tmp_path):
    a=audit()
    sel=[Selection('MEMBER','a','/Common/pool_app','/Common/GDL-F5:/Common/vs_app','CHG-1',True)]
    text=Path(write_change_plan(a,tmp_path/'plan.txt',sel)).read_text(encoding='utf-8')
    assert 'ROLLBACK NOT VERIFIED' in text
    assert 'BLOCKED: resolve all blockers' in text


def test_duplicate_approval_rejected(tmp_path):
    entry='APPROVED|POOL|a|/Common/pool_app||CHG-11111\n'
    f=tmp_path/'ap.txt';f.write_text(entry*2,encoding='utf-8')
    with pytest.raises(ValueError,match='Duplicate'):
        parse_approvals(f)


def test_txt_write_does_not_overwrite(tmp_path):
    f=tmp_path/'plan.txt';f.write_text('existing',encoding='utf-8')
    with pytest.raises(ValueError,match='overwrite'):
        write_change_plan(audit(),f)
    assert f.read_text()=='existing'


def test_ssh_capture_uses_read_only_tmsh_lists_and_host_key(tmp_path):
    from unittest.mock import Mock
    result=Mock(returncode=0,stdout='gtm pool a /Common/P { enabled }\n',stderr='')
    with patch('f5auditdns.tmsh_backup.subprocess.run',return_value=result) as run:
        dest=capture_tmsh_ssh('dns01.example.test','auditor',tmp_path/'backup',include_optional=False)
    assert (dest/'_tmsh_manifest.json').exists()
    assert run.call_count == 14
    for call in run.call_args_list:
        argv=call.args[0]
        assert argv[0]=='ssh'
        assert 'StrictHostKeyChecking=yes' in argv
        assert 'list gtm' in argv[-1]
        assert not any(token in argv[-1] for token in ('delete ', 'modify ', 'create ', 'save '))


def test_cli_end_to_end_offline_backup_and_approved_procedure(tmp_path):
    out=tmp_path/'report.xlsx';plan=tmp_path/'plan.txt'
    rc=main(['analyze','--from-raw',str(RAW),'--tmsh-backup-dir',str(TM),
             '--approval-file',str(ROOT/'examples'/'approved_cleanup_SIMULATED.txt'),
             '--procedure-txt',str(plan),'-o',str(out)])
    assert rc==0 and out.is_file() and plan.is_file()
    assert parser().parse_args(['backup-tmsh','-ho','dns01.example.test','-u','auditor','-o','B']).command=='backup-tmsh'
