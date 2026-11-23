"""v0.5.2 single --file for highlighting and unapproved impact simulation."""
from pathlib import Path
from openpyxl import load_workbook
from f5auditdns.cli import main, parser
from f5auditdns.freedip import load_freed_ips
from f5auditdns.search import load_search_terms

ROOT = Path(__file__).resolve().parent.parent
RAW = ROOT / 'examples' / 'raw_cleanup_simulado'


def _run(tmp_path, *flags):
    target = tmp_path / 'audit.xlsx'
    status = main(['analyze', '--from-raw', str(RAW), *flags, '-o', str(target)])
    assert status == 0
    return load_workbook(target)


def _dict_rows(sheet):
    data = list(sheet.values)
    return [dict(zip(data[0], row)) for row in data[1:]]


def test_one_txt_file_highlights_and_simulates_cleanup(tmp_path):
    sample = tmp_path / 'freed_ips.txt'
    sample.write_text('# Anonymized sample\n192.0.2.200\n', encoding='utf-8')
    book = _run(tmp_path, '--file', str(sample))
    assert 'Search Results' in book.sheetnames
    assert 'FreedIP' in book.sheetnames
    entries = _dict_rows(book['Pool Impact'])
    pool = next(x for x in entries if x['GSLB Pool'] == '/Common/pool_retired')
    assert (pool['Current Members'], pool['Marked Members'], pool['Members After Removal']) == (1, 1, 0)
    assert pool['Pool Action'] == 'REVIEW EMPTY POOL'
    assert pool['Approval Status'] == 'PENDING'
    members = _dict_rows(book['Pool Members'])
    marked = next(x for x in members if x['Pool'] == '/Common/pool_retired')
    assert marked['FreedIP Match'] == 'IP ONLY - REVIEW'
    assert marked['Cleanup Readiness'] == 'REVIEW - MATCH ONLY (NOT APPROVED)'
    assert marked['Delete pool member'].startswith('NOT RUN:')
    col = {c.value:c.column for c in book['Pool Members'][1]}['Destination IP']
    row = next(r for r in list(book['Pool Members'])[1:] if r[col-1].value == '192.0.2.200')
    assert row[col-1].fill.fgColor.rgb[-6:] == 'FFF59D'
    assert any(x['Search Term'] == '192.0.2.200' and x['Status'] == 'FOUND'
               for x in _dict_rows(book['Search Results']))
    book.close()


def test_search_only_switch_avoids_cleanup_evidence(tmp_path):
    sample = tmp_path / 'queries.txt'
    sample.write_text('192.0.2.200\n', encoding='utf-8')
    book = _run(tmp_path, '--file', str(sample), '--search-only')
    assert 'Search Results' in book.sheetnames
    assert 'FreedIP' not in book.sheetnames
    assert all(x['Marked Members'] == 0 for x in _dict_rows(book['Pool Impact']))
    book.close()


def test_list_of_vs_names_does_not_simulate_ip_decommission(tmp_path):
    sample = tmp_path / 'objects.txt'
    sample.write_text('vs_app\n/Common/pool_app\n', encoding='utf-8')
    book = _run(tmp_path, '--file', str(sample))
    assert 'Search Results' in book.sheetnames
    assert 'FreedIP' not in book.sheetnames
    assert all(x['Marked Members'] == 0 for x in _dict_rows(book['Pool Impact']))
    book.close()


def test_explicit_freed_file_still_works_with_search_only(tmp_path):
    file = tmp_path / 'review.txt'
    file.write_text('192.0.2.200', encoding='utf-8')
    book = _run(tmp_path, '--file', str(file), '--search-only', '--freed-ip-file', str(file))
    assert 'FreedIP' in book.sheetnames
    assert len(_dict_rows(book['FreedIP'])) == 1
    book.close()


def test_file_evidence_deduplicated_when_also_explicit(tmp_path):
    file = tmp_path / 'ips.txt'
    file.write_text('192.0.2.200\n192.0.2.200\n192.0.2.100:443\n', encoding='utf-8')
    book = _run(tmp_path, '--file', str(file), '--freed-ip-file', str(file))
    assert len(_dict_rows(book['FreedIP'])) == 2
    assert all(x['Approval Status'] == 'PENDING' for x in _dict_rows(book['Pool Impact']))
    book.close()


def test_exact_endpoint_matching_does_not_mark_wrong_port(tmp_path):
    file = tmp_path / 'freed.txt'
    file.write_text('192.0.2.200:8443\n', encoding='utf-8')
    book = _run(tmp_path, '--file', str(file))
    candidate = next(x for x in _dict_rows(book['Pool Impact']) if x['GSLB Pool']=='/Common/pool_retired')
    assert candidate['Marked Members'] == 0
    assert candidate['Members After Removal'] == 1
    book.close()


def test_txt_ip_with_route_domain_retains_port_and_rd(tmp_path):
    file=tmp_path/'list.txt'
    file.write_text('192.0.2.42%3:8443\n', encoding='utf-8')
    evidence=load_freed_ips(file)
    assert len(evidence)==1
    assert (evidence[0].ip,evidence[0].port,evidence[0].route_domain)==('192.0.2.42',8443,3)
    terms=load_search_terms(files=[file])
    assert terms[0].kind=='ENDPOINT'


def test_help_describes_new_single_file_behavior():
    args=parser().parse_args(['analyze','--from-raw','snap','--file','ips.txt'])
    assert args.file == ['ips.txt'] and not args.search_only
    help_text=parser().format_help()
    assert '--file' in help_text and 'simula' in help_text.lower()
