"""Enrich existing audit sheets with saved TMSH rollback references.

This is an offline-only overlay. The original report columns and safety verdicts
are retained. A captured `list` block never means validated, executable rollback.
"""
from __future__ import annotations

from .tmsh_backup import TmshBackup, Rollback


def _apply(row: dict, field: str, rb: Rollback):
    row[field] = rb.command if rb.command else (
        'NOT RUN: ROLLBACK INCOMPLETE - ' + (rb.reason or 'original configuration missing')
    )
    row['Rollback Status'] = rb.status
    row['Rollback Source'] = rb.source or 'MISSING'
    row['Rollback SHA256'] = rb.source_sha256 or ''
    row['Rollback Validation'] = rb.reason or 'Capture missing: provide original `tmsh list ... all-properties`'
    # Exclude raw TMSH settings: original source remains in a restricted backup.
    if rb.source and rb.status == 'CAPTURED - VERIFY TMSH SYNTAX':
        row['Rollback Evidence'] = 'TMSH DEFINITION CAPTURED - COMPLETENESS AND RESTORE NOT VERIFIED'
    elif rb.source:
        row['Rollback Evidence'] = 'CAPTURED WITH SENSITIVE DATA - NOT EMBEDDED IN REPORT'
    else:
        row['Rollback Evidence'] = 'NOT CAPTURED'
    if rb.status == 'CAPTURED - VERIFY TMSH SYNTAX':
        row['Rollback'] = rb.command  # retain the legacy Rollback column


def enrich_rollback(audit, backup: TmshBackup) -> None:
    """Refresh all object-specific sheets using verified backup source content."""
    for row in audit.wideips:
        _apply(row, 'Recreate wide ip (Rollback)',
               backup.restore('wideip', str(row['Type']).lower(), row['Wide IP']))
    pool_by_key = {}
    for row in audit.pools:
        rr = str(row['Type']).lower()
        _apply(row, 'Recreate pool (Rollback)', backup.restore('pool', rr, row['Pool']))
        pool_by_key[rr, row['Pool']] = row
    member_by_key = {}
    for row in audit.members:
        rr = str(row['Type']).lower()
        rb = backup.restore('pool', rr, row['Pool'], member=row['Member'])
        _apply(row, 'Recreate pool member (Rollback)', rb)
        parent = pool_by_key.get((rr, row['Pool']), {})
        row['Recreate pool (Rollback)'] = parent.get('Recreate pool (Rollback)', row.get('Recreate pool (Rollback)', ''))
        member_by_key[(rr, row['Pool'], row['Member'])] = row
    for row in audit.servers:
        _apply(row, 'Recreate GSLB Server (Rollback)', backup.restore('server', '', row['Server']))
    for row in audit.virtuals:
        _apply(row, 'Recreate virtual server (Rollback)',
               backup.restore('server', '', row['Virtual Server'], server=row['Server']))
    for row in audit.datacenters:
        _apply(row, 'Recreate Data Center (Rollback)', backup.restore('datacenter', '', row['Data Center']))
    for row in audit.auxiliary:
        dataset = row.get('Dataset', '')
        kind = ''
        if dataset.startswith('gtm_monitor_'):
            # Optional monitor backup import can be extended in subsequent versions.
            continue
        kind = {
            'gtm_rule': 'rule', 'gtm_topology': 'topology',
            'gtm_region': 'region', 'gtm_prober_pool': 'prober-pool',
        }.get(dataset, '')
        if kind:
            _apply(row, 'Recreate Object (Rollback)', backup.restore(kind, '', row['Object']))
    for row in audit.pool_impact:
        parent = pool_by_key.get((str(row.get('Type', '')).lower(), row.get('GSLB Pool', '')), {})
        if parent:
            for col in ('Recreate pool (Rollback)', 'Rollback Status', 'Rollback Source',
                        'Rollback SHA256', 'Rollback Validation', 'Rollback Evidence'):
                row[col] = parent.get(col, row.get(col, ''))
    for row in audit.chains:
        key = (str(row.get('Type', '')).lower(), row.get('Pool', ''), row.get('Member', ''))
        member = member_by_key.get(key)
        pool = pool_by_key.get(key[:2])
        if member:
            row['Recreate pool member (Rollback)'] = member.get('Recreate pool member (Rollback)', '')
            row['Member Rollback Status'] = member.get('Rollback Status', '')
        if pool:
            row['Recreate pool (Rollback)'] = pool.get('Recreate pool (Rollback)', '')
            row['Pool Rollback Status'] = pool.get('Rollback Status', '')
    for row in audit.cleanup_procedure:
        if row.get('Step') in ('07', '08'):
            row['Rollback Notes'] = 'Use per-object verified TMSH backups and approved change plan; never restore from REST guesses.'
    audit.summary.append({'Metric': 'TMSH backup indexed objects', 'Value': len(backup.blocks)})
    audit.summary.append({'Metric': 'TMSH rollback status', 'Value': 'Captured references require TMOS validation; no commands executed'})
    if backup.device:
        audit.summary.append({'Metric': 'TMSH backup declared device', 'Value': backup.device})
        audit.summary.append({'Metric': 'TMSH source identity validation', 'Value': 'OPERATOR MUST VERIFY SAME BIG-IP DNS'})
    if backup.captured_at:
        audit.summary.append({'Metric': 'TMSH backup timestamp UTC', 'Value': backup.captured_at})
    for msg in backup.warnings:
        audit.manual_review.append({'Type': 'TMSH BACKUP', 'Object': 'CAPTURE', 'Priority': 'DATA GAP', 'Reason': msg})
