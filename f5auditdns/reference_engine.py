"""Cross-object GSLB references, non-executable change planning and impact.

The module extends (never replaces) the v0.4.0 analyzer's evidence. It only
works with offline snapshots. Recommendations are simulated and unapproved.
"""
from __future__ import annotations

import json
import shlex
from collections import defaultdict
from typing import Any

from .analyzer import Audit, normalize_path, names_of
from .cleanup import safe_object, safe_member
from .collector import RECORD_TYPES, Snapshot, object_id
from .freedip import FreedIPRecord, match_freed_ip


INCOMPLETE = 'ROLLBACK INCOMPLETE: full original tmsh configuration is not captured in REST JSON'


def reference(command: str, valid: bool = True) -> str:
    if not valid:
        return 'REVIEW REQUIRED: unusual object identifier or unsupported tmsh syntax'
    return '\n'.join('NOT RUN: ' + line for line in command.splitlines())


def restore_note(object_type: str, before: str, partial: str = '') -> str:
    """Do not make a partial REST reconstruction appear to be an exact rollback."""
    lines = [INCOMPLETE,
             '# BEFORE CHANGE: capture the complete output below in an approved change record',
             before,
             '# Restore every non-default and inherited setting from the verified pre-change backup.',
             '# No exact recreate command can be guaranteed from this REST snapshot.']
    if partial:
        lines += ['# OPTIONAL PARTIAL EXAMPLE ONLY (not sufficient for exact rollback):', partial]
    return '\n'.join('NOT RUN: ' + line for line in lines)


def _list_gtm(kind: str, name: str, record: str = '') -> str:
    suffix = ' ' + record if record else ''
    return reference(f'tmsh list gtm {kind}{suffix} {name} all-properties', safe_object(name))


def _show_gtm(kind: str, name: str, record: str = '') -> str:
    suffix = ' ' + record if record else ''
    return reference(f'tmsh show gtm {kind}{suffix} {name} detail', safe_object(name))


def _remove_gtm(kind: str, name: str, record: str = '') -> str:
    suffix = ' ' + record if record else ''
    return reference(f'tmsh delete gtm {kind}{suffix} {name}', safe_object(name))


def _dynamic_checks(name: str, extra: tuple[str, ...] = ()) -> str:
    if not safe_object(name):
        return reference('', False)
    targets = ('rule', 'distributed-app', 'topology') + extra
    # grep is bash-only. shlex.quote prevents shell injection in name values.
    return '\n'.join(reference(f'tmsh list gtm {kind} one-line | grep -F -- {shlex.quote(name)}')
                     for kind in targets)


def _properties(obj: dict[str, Any]) -> str:
    allowed = ('enabled', 'disabled', 'monitor', 'loadBalancingMode', 'loadBalancingModePreferred',
               'loadBalancingModeAlternate', 'loadBalancingModeFallback', 'ratio', 'memberOrder',
               'destination', 'address', 'port', 'virtualServerDiscovery', 'dependsOn',
               'depends-on', 'lastResortPool', 'pools', 'poolsCname', 'rules', 'datacenter',
               'proberPreference', 'ttl', 'minimumMonitors', 'limitMaxBps', 'limitMaxConnections')
    selected = {k: obj[k] for k in allowed if k in obj}
    return json.dumps(selected, ensure_ascii=True, sort_keys=True, default=str)[:6000]


def _pool_key(rr: str, name: str) -> tuple[str, str]:
    return rr.lower(), name


def _wideip_refs(audit: Audit, snap: Snapshot) -> dict[tuple[str, str], set[tuple[str, str, str]]]:
    """Resolve reference types from original subcollections, not report strings.

    The older audit.Wide IP Pools column combines ordinary and Last Resort
    pools, so using it to infer 'DIRECT' would silently mislabel fallback.
    """
    refs: dict[tuple[str, str], set[tuple[str, str, str]]] = defaultdict(set)
    known = {_pool_key(p['Type'], p['Pool']) for p in audit.pools}
    raw_wideips = {(rr, object_id(w)): w for rr in RECORD_TYPES
                   for w in snap.datasets.get(f'gtm_wideip_{rr}', [])}
    for w in audit.wideips:
        rr, wid = str(w['Type']).lower(), str(w['Wide IP'])
        obj = raw_wideips.get((rr, wid), {})
        part = str(obj.get('partition') or wid.strip('/').split('/', 1)[0] or 'Common')
        direct = snap.datasets.get(f'wideip_pools::{rr}::{wid}')
        if not isinstance(direct, list):
            direct = obj.get('pools') if isinstance(obj.get('pools'), list) else []
        for r in direct:
            name = str(r.get('fullPath') or r.get('name') or r.get('pool') or '') if isinstance(r, dict) else str(r)
            partition = str(r.get('partition') or part) if isinstance(r, dict) else part
            key = (rr, normalize_path(name, partition))
            if key in known:
                refs[key].add((rr, wid, 'DIRECT'))
        cname_pools = snap.datasets.get(f'wideip_pools_cname::{rr}::{wid}')
        if not isinstance(cname_pools, list):
            cname_pools = obj.get('poolsCname') if isinstance(obj.get('poolsCname'), list) else []
        for item in cname_pools:
            name = str(item.get('fullPath') or item.get('name') or item.get('pool') or '') if isinstance(item, dict) else str(item)
            key = ('cname', normalize_path(name, part))
            if key in known:
                refs[key].add((rr, wid, 'DIRECT CNAME'))
        last_resort = str(obj.get('lastResortPool') or w.get('Last resort') or '').strip()
        if last_resort and last_resort.lower() != 'none':
            normalized = normalize_path(last_resort, part)
            for typ in (rr, 'cname'):
                if (typ, normalized) in known:
                    refs[(typ, normalized)].add((rr, wid, 'LAST RESORT'))
    return refs


def _references_text(refs: set[tuple[str, str, str]]) -> str:
    return '\n'.join(f'{kind.upper()} {wideip} [{source}]'
                     for kind, wideip, source in sorted(refs))


def _check_wideips(refs: set[tuple[str, str, str]]) -> str:
    commands = []
    for kind, wideip, _ in sorted(refs):
        cmd = _list_gtm('wideip', wideip, kind)
        if cmd not in commands:
            commands.append(cmd)
    return '\n'.join(commands) if commands else 'NOT RUN: # No static Wide IP references found; check iRules/topology/DR.'


def _virtual_dependencies(obj: dict, server_obj: dict, member_count: int,
                          dynamic_unknown: bool) -> str:
    pieces = []
    discovery = str(server_obj.get('virtualServerDiscovery') or 'UNKNOWN')
    if discovery.lower() != 'disabled':
        pieces.append(f'Auto Discovery: {discovery}; VS may be recreated')
    for key in ('dependsOn', 'depends-on', 'dependsOnReference'):
        if obj.get(key):
            pieces.append(f'{key}={obj[key]}')
    if obj.get('monitor'):
        pieces.append(f"Monitor={obj['monitor']}")
    if member_count:
        pieces.append(f'{member_count} Pool Member reference(s)')
    if dynamic_unknown:
        pieces.append('iRules / topology / dynamic references: NOT FULLY VERIFIED')
    return '; '.join(pieces) or 'No explicit dependency found; external references not proven absent'


def build_reference_report(audit: Audit, snap: Snapshot,
                           freed_ips: list[FreedIPRecord] | None = None) -> None:
    """Mutate only the in-memory report, preserving every existing column/row."""
    freed_ips = freed_ips or []
    all_refs = _wideip_refs(audit, snap)
    results = snap.meta.get('endpoint_results', {})
    core_incomplete = any(state != 'OK' for key, state in results.items()
                          if key.startswith(('gtm_pool_', 'gtm_wideip_', 'gtm_server', 'gtm_datacenter')))
    dynamic_uncertain = (snap.meta.get('scope') != 'all'
                         or results.get('gtm_rule') != 'OK'
                         or results.get('gtm_distributed_app') != 'OK'
                         or bool(snap.datasets.get('gtm_rule'))
                         or bool(snap.datasets.get('gtm_distributed_app'))
                         or any(w.get('Rules') for w in audit.wideips))
    pools = {_pool_key(p['Type'], p['Pool']): p for p in audit.pools}
    members: dict[tuple[str, str], list[dict]] = defaultdict(list)
    for member in audit.members:
        members[_pool_key(member['Type'], member['Pool'])].append(member)
    servers = {s['Server']: s for s in audit.servers}
    virtuals = {(v['Server'], v['Virtual Server']): v for v in audit.virtuals}
    server_objects = {object_id(v): v for v in snap.datasets.get('gtm_server', [])}
    raw_virtuals = {(server, object_id(v)): v
                    for server in server_objects for v in snap.datasets.get(f'server_virtuals::{server}', []) or []}
    raw_pools = {(rr, object_id(p)): p for rr in RECORD_TYPES
                 for p in snap.datasets.get(f'gtm_pool_{rr}', [])}
    raw_wideips = {(rr, object_id(w)): w for rr in RECORD_TYPES
                   for w in snap.datasets.get(f'gtm_wideip_{rr}', [])}
    server_members: dict[tuple[str, str], list[dict]] = defaultdict(list)
    for row in audit.members:
        if row.get('GSLB Server') and row.get('Virtual Server'):
            server_members[(row['GSLB Server'], row['Virtual Server'])].append(row)

    audit.freed_ips = [dict(IP=x.ip, Port=x.port, **{'Route Domain': x.route_domain,
                         'Source': x.source, 'Decision': 'EVIDENCE ONLY - APPROVAL PENDING'}) for x in freed_ips]
    audit.reference_map = []
    audit.object_inventory = []
    audit.pool_impact = []
    audit.cleanup_procedure = []

    for w in audit.wideips:
        rr, wid = w['Type'].lower(), w['Wide IP']
        ref_pools = [(typ, pname, source) for (typ, pname), refs in all_refs.items()
                     for typ_w, name_w, source in refs if (typ_w, name_w) == (rr, wid)]
        w['Current Pool References'] = '\n'.join(
            f'{typ.upper()} {pname} [{source}]' for typ, pname, source in sorted(ref_pools))
        w['Approval Status'] = 'PENDING'
        w['Check Wide IP (list)'] = _list_gtm('wideip', wid, rr)
        w['Check Wide IP (show)'] = _show_gtm('wideip', wid, rr)
        w['Check Pool References (list)'] = '\n'.join(_list_gtm('pool', name, typ) for typ, name, _ in sorted(ref_pools))
        w['Check Rules (list)'] = '\n'.join(_list_gtm('rule', x) for x in names_of(raw_wideips.get((rr, wid), {}).get('rules')))
        w['Delete wide ip'] = _remove_gtm('wideip', wid, rr)
        w['Recreate wide ip (Rollback)'] = restore_note('wideip', w['Check Wide IP (list)'])
        w['Rollback Status'] = 'ROLLBACK INCOMPLETE'
        w['Captured Properties'] = _properties(raw_wideips.get((rr, wid), {}))

    # Mark all rows before calculating each pool's simulation totals.
    for m in audit.members:
        source, quality = match_freed_ip(m.get('Destination IP'), m.get('Port'),
                                          m.get('Route Domain'), freed_ips)
        m['IP Marked (Source)'] = source
        m['FreedIP Match'] = quality

    for m in audit.members:
        rr, pname, member = m['Type'].lower(), m['Pool'], m['Member']
        key = rr, pname
        m['Approval Status'] = 'PENDING'
        m['Wide IP Reference'] = _references_text(all_refs.get(key, set()))
        pool_members = members[key]
        member_inventory_complete = (results.get(f'pool_members::{rr}::{pname}') == 'OK'
                                     and isinstance(snap.datasets.get(f'pool_members::{rr}::{pname}'), list))
        m['Current Pool Members'] = '\n'.join(r['Member'] for r in pool_members)
        m['Current Member Count'] = len(pool_members) if member_inventory_complete else None
        m['Members After Marked Removal'] = (sum(not x.get('IP Marked (Source)') for x in pool_members)
                                              if member_inventory_complete else None)
        m['Pool Action'] = ('INVENTORY INCOMPLETE - NO SIMULATION' if not member_inventory_complete else
                            'REVIEW EMPTY POOL' if m['Members After Marked Removal'] == 0 else 'KEEP POOL')
        m['Check Pool (list)'] = _list_gtm('pool', pname, rr)
        m['Check Pool (show)'] = _show_gtm('pool', pname, rr)
        m['Check Wide IP References (list)'] = _check_wideips(all_refs.get(key, set()))
        m['Check GSLB Server (list)'] = _list_gtm('server', m['GSLB Server']) if m.get('GSLB Server') else 'REVIEW REQUIRED: GSLB Server unresolved'
        m['Check Other References (grep)'] = _dynamic_checks(pname)
        valid = rr in RECORD_TYPES and safe_object(pname) and safe_member(member)
        m['Delete pool member'] = reference(f'tmsh modify gtm pool {rr} {pname} members delete {{ {member} }}', valid)
        m['Recreate pool member (Rollback)'] = restore_note('member', m['Check Pool (list)'],
                                                            str(m.get('Rollback', '')).replace('NOT RUN: ', ''))
        m['Delete pool'] = _remove_gtm('pool', pname, rr)
        m['Recreate pool (Rollback)'] = restore_note('pool', m['Check Pool (list)'])
        m['Rollback Status'] = 'ROLLBACK INCOMPLETE'
        raw_member = next((v for v in snap.datasets.get(f'pool_members::{rr}::{pname}', []) or []
                           if str(v.get('fullPath') or v.get('name') or v.get('virtualServer')) == member), {})
        m['Captured Properties'] = _properties(raw_member)
        m['Cleanup Readiness'] = ('REVIEW - MATCH ONLY (NOT APPROVED)' if m['IP Marked (Source)'] else 'NO FREED-IP EVIDENCE')

    for p in audit.pools:
        rr, pname = p['Type'].lower(), p['Pool']
        key = rr, pname
        linked = members[key]
        refs = all_refs.get(key, set())
        member_inventory_complete = (results.get(f'pool_members::{rr}::{pname}') == 'OK'
                                     and isinstance(snap.datasets.get(f'pool_members::{rr}::{pname}'), list))
        marked = sum(bool(m.get('IP Marked (Source)')) for m in linked)
        remaining = len(linked) - marked if member_inventory_complete else None
        action = ('INVENTORY INCOMPLETE - NO SIMULATION' if not member_inventory_complete else
                  'REVIEW EMPTY POOL' if remaining == 0 else 'KEEP POOL')
        p['Wide IP Reference'] = _references_text(refs)
        p['Current Pool Members'] = '\n'.join(m['Member'] for m in linked)
        p['Members Marked IP'] = marked if member_inventory_complete else None
        p['Members After Marked Removal'] = remaining
        p['Pool Action'] = action
        p['Approval Status'] = 'PENDING'
        p['Check Pool (list)'] = _list_gtm('pool', pname, rr)
        p['Check Pool (show)'] = _show_gtm('pool', pname, rr)
        p['Check Wide IP References'] = _check_wideips(refs)
        p['Check Dynamic References (grep)'] = _dynamic_checks(pname)
        p['Delete pool'] = _remove_gtm('pool', pname, rr)
        p['Recreate pool (Rollback)'] = restore_note('pool', p['Check Pool (list)'])
        p['Rollback Status'] = 'ROLLBACK INCOMPLETE'
        p['Captured Properties'] = _properties(raw_pools.get(key, {}))
        p['Reference Confidence'] = ('DIRECT / LAST RESORT' if refs else
                                     'NO DIRECT REFS; DYNAMIC / OTHER UNKNOWN' if dynamic_uncertain else
                                     'NO STATIC REFS IN COMPLETE SNAPSHOT')
        impact = dict(Type=rr.upper(), **{'GSLB Pool': pname,
            'Current Members': len(linked) if member_inventory_complete else None,
            'Marked Members': marked if member_inventory_complete else None,
            'Members After Removal': remaining, 'Wide IP References': _references_text(refs),
            'Reference Count': len(refs), 'LB Method': p.get('Method', ''),
            'Monitor': p.get('Monitor', ''), 'Pool Action': action, 'Approval Status': 'PENDING',
            'Simulation Only': 'YES - NO CHANGE APPROVED',
            'Dynamic References': 'PENDING REVIEW' if dynamic_uncertain else 'NOT DETECTED IN COLLECTED CATALOG',
            'Prechecks': '\n'.join((p['Check Pool (list)'], p['Check Pool (show)'],
                                     p['Check Wide IP References'], p['Check Dynamic References (grep)'])),
            'Delete pool': p['Delete pool'], 'Recreate pool (Rollback)': p['Recreate pool (Rollback)'],
            'Postcheck': p['Check Pool (show)'], 'Rollback Status': p['Rollback Status']})
        audit.pool_impact.append(impact)

    for v in audit.virtuals:
        srv, name = v['Server'], v['Virtual Server']
        raw = raw_virtuals.get((srv, name), {})
        server_obj = server_objects.get(srv, {})
        links = server_members.get((srv, name), [])
        pool_refs = sorted({(m['Type'], m['Pool']) for m in links})
        wide_refs = {(typ, wid, via) for m in links
                     for (typ, wid, via) in all_refs.get((m['Type'].lower(), m['Pool']), set())}
        v['Current Pool References'] = '\n'.join(f'{rr} {name}' for rr, name in pool_refs)
        v['Current Pool Reference Count'] = len(pool_refs)
        v['Wide IP References (via pools)'] = _references_text(wide_refs)
        v['Other VS Dependencies'] = _virtual_dependencies(raw, server_obj, len(links), dynamic_uncertain)
        v['Approval Status'] = 'PENDING'
        v['Check GSLB Server (list)'] = _list_gtm('server', srv)
        v['Check Pool References (list)'] = '\n'.join(_list_gtm('pool', pool, rr.lower()) for rr, pool in pool_refs) or 'NOT RUN: # No Pool Member references in snapshot.'
        v['Check Wide IP References (list)'] = _check_wideips(wide_refs)
        v['Check Other VS References'] = _dynamic_checks(name, ('server',))
        safe = safe_object(srv) and safe_object(name)
        v['Delete virtual server'] = reference(f'tmsh modify gtm server {srv} virtual-servers delete {{ {name} }}', safe)
        v['Recreate virtual server (Rollback)'] = restore_note('virtual', v['Check GSLB Server (list)'],
            str(v.get('Rollback', '')).replace('NOT RUN: ', ''))
        v['Rollback Status'] = 'ROLLBACK INCOMPLETE'
        v['Captured Properties'] = _properties(raw)
        source, quality = match_freed_ip(v.get('Destination IP'), v.get('Port'), v.get('Route Domain'), freed_ips)
        v['IP Marked (Source)'] = source
        v['FreedIP Match'] = quality
        if links:
            v['VS Cleanup Action'] = f'KEEP / REMOVE {len(links)} POOL MEMBER REFERENCE(S) FIRST'
            if str(server_obj.get('virtualServerDiscovery') or 'unknown').lower() != 'disabled':
                v['VS Cleanup Action'] += '; MANUAL REVIEW - AUTO DISCOVERY'
        elif str(server_obj.get('virtualServerDiscovery') or 'unknown').lower() != 'disabled':
            v['VS Cleanup Action'] = 'MANUAL REVIEW - AUTO DISCOVERY'
        else:
            v['VS Cleanup Action'] = 'REVIEW UNUSED VS - VERIFY DYNAMIC DEPENDENCIES'

    for s in audit.servers:
        srv = s['Server']
        children = [v for v in audit.virtuals if v['Server'] == srv]
        links = [m for m in audit.members if m.get('GSLB Server') == srv]
        s['Current Virtual Servers'] = '\n'.join(v['Virtual Server'] for v in children)
        s['Current Pool References'] = '\n'.join(sorted({f"{m['Type']} {m['Pool']}" for m in links}))
        s['Approval Status'] = 'PENDING'
        s['Check GSLB Server (list)'] = _list_gtm('server', srv)
        s['Check GSLB Server (show)'] = _show_gtm('server', srv)
        s['Check Pool Members (list)'] = '\n'.join(sorted({_list_gtm('pool', m['Pool'], m['Type'].lower()) for m in links}))
        s['Check Data Center (list)'] = _list_gtm('datacenter', s['Data Center']) if s.get('Data Center') else 'REVIEW REQUIRED: Data Center unresolved'
        s['Check Other References'] = _dynamic_checks(srv)
        s['Delete GSLB Server'] = _remove_gtm('server', srv)
        s['Recreate GSLB Server (Rollback)'] = restore_note('server', s['Check GSLB Server (list)'])
        s['Rollback Status'] = 'ROLLBACK INCOMPLETE'
        s['Captured Properties'] = _properties(server_objects.get(srv, {}))

    for d in audit.datacenters:
        dc = d['Data Center']
        d['Current GSLB Servers'] = '\n'.join(s['Server'] for s in audit.servers if s.get('Data Center') == dc)
        d['Approval Status'] = 'PENDING'
        d['Check Data Center (list)'] = _list_gtm('datacenter', dc)
        d['Check Data Center (show)'] = _show_gtm('datacenter', dc)
        d['Check Server References'] = '\n'.join(_list_gtm('server', s['Server']) for s in audit.servers if s.get('Data Center') == dc)
        d['Check Topology and Region'] = '\n'.join(reference(f'tmsh list gtm {kind} all-properties') for kind in ('topology', 'region', 'prober-pool'))
        d['Delete Data Center'] = _remove_gtm('datacenter', dc)
        d['Recreate Data Center (Rollback)'] = restore_note('datacenter', d['Check Data Center (list)'])
        d['Rollback Status'] = 'ROLLBACK INCOMPLETE'
        d['Captured Properties'] = _properties(next((x for x in snap.datasets.get('gtm_datacenter', []) if object_id(x) == dc), {}))

    for ch in audit.chains:
        rr, wid, pname = str(ch.get('Type') or '').lower(), ch.get('Wide IP', ''), ch.get('Pool', '')
        ch['Check Wide IP'] = _list_gtm('wideip', wid, rr) if wid else ''
        ch['Check Pool'] = _list_gtm('pool', pname, rr) if pname else ''
        ch['Check GSLB Server'] = _list_gtm('server', ch['Server']) if ch.get('Server') else ''
        mem = next((m for m in audit.members if m['Type'].lower() == rr and m['Pool'] == pname and m['Member'] == ch.get('Member')), {})
        pool = pools.get((rr, pname), {})
        ch['Delete pool member'] = mem.get('Delete pool member', '')
        ch['Recreate pool member (Rollback)'] = mem.get('Recreate pool member (Rollback)', '')
        ch['Delete pool'] = pool.get('Delete pool', '')
        ch['Recreate pool (Rollback)'] = pool.get('Recreate pool (Rollback)', '')
        ch['Approval Status'] = 'PENDING'
        ch['Postcheck'] = '\n'.join((ch['Check Wide IP'], ch['Check Pool'], ch['Check GSLB Server']))

    auxiliary_types = {
        'gtm_listener': ('listener', ''), 'gtm_rule': ('rule', ''),
        'gtm_topology': ('topology', ''), 'gtm_region': ('region', ''),
        'gtm_prober_pool': ('prober-pool', ''), 'gtm_distributed_app': ('distributed-app', ''),
    }
    for x in audit.auxiliary:
        key, name = x['Dataset'], x['Object']
        if key.startswith('gtm_monitor_'):
            kind, rr = 'monitor', key[len('gtm_monitor_'):]
        else:
            kind, rr = auxiliary_types.get(key, ('', ''))
        x['Approval Status'] = 'PENDING'
        x['Check Object (list)'] = _list_gtm(kind, name, rr) if kind else 'REVIEW REQUIRED: unsupported auxiliary object type'
        x['Check Object (show)'] = _show_gtm(kind, name, rr) if kind else 'REVIEW REQUIRED: unsupported auxiliary object type'
        x['Delete Object (Reference)'] = _remove_gtm(kind, name, rr) if kind else 'REVIEW REQUIRED: unsupported auxiliary object type'
        x['Recreate Object (Rollback)'] = restore_note(kind, x['Check Object (list)'])
        x['Rollback Status'] = 'ROLLBACK INCOMPLETE'

    # Build both directions of the object graph, explicitly labelling gaps.
    dc_map = {s['Server']: s.get('Data Center', '') for s in audit.servers}
    seen_pool = set()
    seen_vs = set()
    for m in audit.members:
        key = m['Type'].lower(), m['Pool']
        all_sources = all_refs.get(key, set())
        for ref in (sorted(all_sources) if all_sources else [('', '', 'NO STATIC REFERENCE')]):
            rr, wid, typ = ref
            vkey = (m.get('GSLB Server'), m.get('Virtual Server'))
            seen_pool.add(key)
            seen_vs.add(vkey)
            audit.reference_map.append({
                'Relationship': 'WIDE IP > POOL > MEMBER > SERVER > VS',
                'Reverse Relationship': 'DC > SERVER > VS > MEMBER > POOL > WIDE IP',
                'DNS Record Type': rr.upper(), 'Wide IP': wid, 'Pool Type': m['Type'],
                'GSLB Pool': m['Pool'], 'Pool Member': m['Member'],
                'Data Center': dc_map.get(m.get('GSLB Server'), ''),
                'GSLB Server': m.get('GSLB Server'), 'GSLB Virtual Server': m.get('Virtual Server'),
                'Destination IP': m.get('Destination IP'), 'Port': m.get('Port'),
                'Route Domain': m.get('Route Domain'), 'LTM Location': m.get('LTM Location'),
                'Reference Type': typ,
                'Reference Confidence': 'SNAPSHOT INCOMPLETE - UNVERIFIED' if core_incomplete else (
                    ('DYNAMIC REFERENCES PENDING' if dynamic_uncertain else 'STATIC SNAPSHOT')
                    if typ == 'NO STATIC REFERENCE' else 'STATIC ' + typ),
                'FreedIP Match': m.get('FreedIP Match'), 'IP Marked (Source)': m.get('IP Marked (Source)'),
                'Approval Status': 'PENDING', 'Verdict': m.get('Verdict'),
            })
    for key, p in pools.items():
        if key not in seen_pool:
            audit.reference_map.append({'Relationship': 'POOL WITH NO COLLECTED MEMBERS',
                'GSLB Pool': p['Pool'], 'Pool Type': p['Type'],
                'Reference Type': 'NO MEMBER',
                'Reference Confidence': p['Reference Confidence'], 'Approval Status': 'PENDING'})
    for key, v in virtuals.items():
        if key not in seen_vs:
            audit.reference_map.append({'Relationship': 'VIRTUAL SERVER WITH NO RESOLVED POOL MEMBER',
                'Data Center': dc_map.get(v['Server'], ''), 'GSLB Server': v['Server'],
                'GSLB Virtual Server': v['Virtual Server'], 'Destination IP': v.get('Destination IP'),
                'Port': v.get('Port'), 'Route Domain': v.get('Route Domain'),
                'Reference Type': 'NO RESOLVED MEMBER',
                'Reference Confidence': 'DYNAMIC / TOPOLOGY REFERENCES UNVERIFIED',
                'LTM Location': v.get('LTM Location'), 'Approval Status': 'PENDING'})
    for s in audit.servers:
        if not any(v['Server'] == s['Server'] for v in audit.virtuals):
            audit.reference_map.append({'Relationship': 'SERVER WITH NO COLLECTED VIRTUAL SERVERS',
                'Data Center': s.get('Data Center'), 'GSLB Server': s['Server'],
                'Reference Type': 'NO VIRTUALS', 'Reference Confidence': 'CHECK INVENTORY',
                'Approval Status': 'PENDING'})
    for dc in audit.datacenters:
        if not any(s.get('Data Center') == dc['Data Center'] for s in audit.servers):
            audit.reference_map.append({'Relationship': 'DATA CENTER WITH NO COLLECTED GSLB SERVERS',
                'Data Center': dc['Data Center'], 'Reference Type': 'NO SERVERS',
                'Reference Confidence': 'CHECK TOPOLOGY/PROBERS', 'Approval Status': 'PENDING'})

    # Object Inventory includes *every* collected configuration object, even
    # objects absent from a chain. Match known identities back to original
    # report rows so health and LTM data are retained in the consolidated view.
    wideip_index = {(x['Type'].lower(), x['Wide IP']): x for x in audit.wideips}
    member_index = {(x['Type'].lower(), x['Pool'], x['Member']): x for x in audit.members}
    dc_index = {x['Data Center']: x for x in audit.datacenters}
    for dataset, data in sorted(snap.datasets.items()):
        items = data if isinstance(data, list) else ([data] if isinstance(data, dict) else [])
        for position, obj in enumerate(items):
            if not isinstance(obj, dict):
                obj = {'value': str(obj)}
            name = str(obj.get('fullPath') or obj.get('name') or obj.get('virtualServer')
                       or obj.get('key') or f'entry_{position + 1}')
            top = dataset.split('::', 1)[0]
            category = ('STATS' if dataset.startswith('stats_') else 'SUBCOLLECTION'
                        if '::' in dataset else 'GSLB CONFIG / AUXILIARY')
            related: dict[str, Any] = {}
            if dataset.startswith('gtm_pool_'):
                related = pools.get((dataset.rsplit('_', 1)[-1], name), {})
            elif dataset.startswith('gtm_wideip_'):
                related = wideip_index.get((dataset.rsplit('_', 1)[-1], name), {})
            elif dataset == 'gtm_server':
                related = servers.get(name, {})
            elif dataset == 'gtm_datacenter':
                related = dc_index.get(name, {})
            elif dataset.startswith('server_virtuals::'):
                related = virtuals.get((dataset.split('::', 1)[1], name), {})
            elif dataset.startswith('pool_members::'):
                tokens = dataset.split('::', 2)
                if len(tokens) == 3:
                    related = member_index.get((tokens[1], tokens[2], name), {})
            audit.object_inventory.append({
                'Object Category': category, 'Object Type': top, 'Object Name': name,
                'Source Dataset': dataset, 'Source Index': position + 1,
                'Data Center': related.get('Data Center', obj.get('datacenter', '')),
                'Destination IP': related.get('Destination IP', obj.get('destination') or obj.get('address') or ''),
                'Port': related.get('Port'), 'Route Domain': related.get('Route Domain'),
                'LTM Location': related.get('LTM Location', ''),
                'References': related.get('Wide IP Reference') or related.get('Current Pool References')
                              or obj.get('pool') or obj.get('virtualServer') or '',
                'Health': related.get('Health', ''),
                'Config': related.get('Config', str(obj.get('enabled') if 'enabled' in obj else '')),
                'Check Object (list)': related.get('Check Pool (list)') or related.get('Check GSLB Server (list)')
                                       or related.get('Check Wide IP (list)')
                                       or 'NOT RUN: # Refer to object-specific inventory for tmsh path',
                'Reference Status': related.get('Reference Confidence') or related.get('Finding') or
                                    'UNLINKED / AUXILIARY / RAW INVENTORY - not proof of unused',
                'Approval Status': 'PENDING',
            })

    for row in audit.candidates:
        row['Approval Status'] = 'PENDING'
        row['Change Readiness'] = 'NOT APPROVED - VERIFY DEPENDENCIES AND RESTORATION'
        row['Rollback Status'] = 'ROLLBACK INCOMPLETE'

    # Stage-level plan: each command is a reference, never automatically run.
    stages = [
        ('01', 'COLLECT AND BACKUP', 'Capture exact pre-change tmsh config and approved full backup',
         reference('tmsh list gtm wideip all-properties\ntmsh list gtm pool all-properties\ntmsh list gtm server all-properties'),
         reference('tmsh save sys ucs /var/local/ucs/pre_cleanup_reference.ucs'),
         reference('tmsh show gtm wideip a'), 'Restore only from a verified, approved full backup.'),
        ('02', 'CONFIRM LTM DECOMMISSION', 'Verify target VS removed from all relevant LTM/HA devices',
         reference('tmsh list ltm virtual one-line'), 'NOT RUN: # No LTM deletion is performed by F5AuditDNS',
         reference('tmsh show ltm virtual'), 'Revalidate against LTM evidence and change records.'),
        ('03', 'CHECK ALL DNS REFERENCES', 'Verify Wide IP, pools, fallback, iRules and dependencies',
         reference('tmsh list gtm wideip all-properties\ntmsh list gtm rule one-line\ntmsh list gtm topology all-properties'),
         'NOT RUN: # Review references before planning any change',
         reference('tmsh show gtm wideip a'), 'Correct the plan if new references are discovered.'),
        ('04', 'REMOVE APPROVED POOL MEMBERS', 'Only after an explicit approved change',
         reference('tmsh list gtm pool a all-properties'),
         'NOT RUN: # Use object-specific Delete pool member command after approval',
         reference('tmsh show gtm pool a'), 'Use exact saved member config to re-add.'),
        ('05', 'ASSESS EMPTY POOLS', 'Verify all remaining members and business-continuity requirements',
         reference('tmsh list gtm pool a all-properties'), 'NOT RUN: # Simulation only; no automatic pool deletion',
         reference('tmsh show gtm pool a'), 'Rollback previous member removals if impact is unacceptable.'),
        ('06', 'DETACH POOLS FROM WIDE IPS', 'Modify all approved direct/Last Resort pool references first',
         reference('tmsh list gtm wideip a all-properties'),
         'NOT RUN: # Build an explicit approved modify command from original Wide IP config',
         reference('tmsh show gtm wideip a'), 'Restore exact original pools, order, rules and fallback.'),
        ('07', 'DELETE UNREFERENCED POOLS', 'Delete only after no remaining confirmed dependencies',
         reference('tmsh list gtm pool a all-properties'),
         'NOT RUN: # Use approved object-specific Delete Pool reference',
         reference('tmsh show gtm pool a'), 'Recreate complete pool from saved tmsh config.'),
        ('08', 'REVIEW GSLB VIRTUAL SERVERS', 'Check discovery, depends-on, monitors and all pool members',
         reference('tmsh list gtm server all-properties'),
         'NOT RUN: # Use approved server virtual-servers delete reference',
         reference('tmsh show gtm server'), 'Restore server virtual attributes and dependencies.'),
        ('09', 'REVIEW GSLB SERVERS / DATA CENTERS', 'Separate cleanup; verify probers, topology and discovery',
         reference('tmsh list gtm server all-properties\ntmsh list gtm datacenter all-properties'),
         'NOT RUN: # Do not remove a parent solely because it has no pool references',
         reference('tmsh show gtm server'), 'Restore exact parent objects and child objects in order.'),
        ('10', 'POSTCHECK DNS AND GSLB', 'Validate DNS resolution, health and final configuration',
         reference('tmsh show gtm wideip a\ntmsh show gtm pool a\ntmsh show gtm server'),
         'NOT RUN: # No additional change', reference('tmsh show gtm wideip a'),
         'Rollback approved changes if resolution or failover regresses.'),
        ('11', 'DOCUMENT AND VALIDATE ROLLBACK', 'Record exact inverse commands and verified backup',
         reference('tmsh list gtm wideip all-properties'),
         'NOT RUN: # Restore using approved saved configurations only',
         reference('tmsh show gtm wideip a'), 'Record evidence of successful restoration.'),
        ('12', 'COMPLETE WIDE IP DECOMMISSION', 'Optional, separately approved removal of entire Wide IP',
         reference('tmsh list gtm wideip a all-properties'),
         'NOT RUN: # Use an approved object-specific Delete wide ip command',
         reference('tmsh show gtm wideip a'), 'Restore Wide IP, rules, pools, ordering, fallback and DNS records.'),
    ]
    for order, stage, purpose, pre, change, post, rollback in stages:
        audit.cleanup_procedure.append({
            'Order': order, 'Stage': stage, 'Purpose': purpose, 'Prechecks (show/list)': pre,
            'Delete / Change (REFERENCE ONLY)': change, 'Postchecks (show/list)': post,
            'Rollback (REFERENCE ONLY)': 'NOT RUN: # ' + rollback,
            'Approval Status': 'PENDING', 'Important Notes': 'READ ONLY / SIMULATION; DO NOT EXECUTE DIRECTLY',
        })

    audit.summary.extend([
        {'Metric': 'FreedIP entries (evidence only)', 'Value': len(freed_ips)},
        {'Metric': 'Pool members with FreedIP match', 'Value': sum(bool(m['IP Marked (Source)']) for m in audit.members)},
        {'Metric': 'GSLB virtuals with multi-pool references', 'Value': sum(v['Current Pool Reference Count'] > 1 for v in audit.virtuals)},
        {'Metric': 'Pools simulated empty after marked removal', 'Value': sum(p['Members After Marked Removal'] == 0 for p in audit.pools)},
        {'Metric': 'Cleanup approvals recorded', 'Value': 'NONE; ALL PENDING'},
        {'Metric': 'Rollback reconstruction', 'Value': 'INCOMPLETE unless exact pre-change config independently preserved'},
        {'Metric': 'New graph inventory objects', 'Value': len(audit.object_inventory)},
    ])
