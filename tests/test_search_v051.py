"""Search/highlight regression tests. All identities are fabricated."""
from __future__ import annotations

import csv
from pathlib import Path

import pytest
from openpyxl import Workbook, load_workbook

from f5auditdns.analyzer import analyze
from f5auditdns.collector import Snapshot
from f5auditdns.cli import main, parser
from f5auditdns.report import SHEETS, as_csv, as_excel, search_matches
from f5auditdns.search import load_search_terms, make_term, matching_columns

ROOT = Path(__file__).resolve().parent.parent


def fixture_audit():
    return analyze(Snapshot.read(ROOT / 'examples' / 'raw_cleanup_simulado'))


def test_virtual_server_name_is_exact_not_substring():
    term = make_term('vs_app', 'VIRTUAL SERVER')
    assert matching_columns({'Virtual Server': '/Common/vs_app'}, term) == {'Virtual Server'}
    assert not matching_columns({'Virtual Server': '/Common/vs_application'}, term)
    assert 'Member' in matching_columns({'Member': '/Common/GDL-F5:/Common/vs_app'}, term)


def test_scoped_virtual_server_requires_matching_server():
    term = make_term('/Common/GDL-F5:/Common/vs_app', 'VIRTUAL SERVER')
    assert matching_columns({'Server': '/Common/GDL-F5', 'Virtual Server': '/Common/vs_app'}, term)
    assert not matching_columns({'Server': '/Common/QRO-F5', 'Virtual Server': '/Common/vs_app'}, term)


def test_ip_search_never_matches_prefix():
    term = make_term('192.0.2.4')
    assert matching_columns({'Destination IP': '192.0.2.4'}, term)
    assert not matching_columns({'Destination IP': '192.0.2.42'}, term)
    assert not matching_columns({'Destination IP': '192.0.2.420'}, term)


def test_ip_plus_port_requires_exact_port_and_route_domain_when_supplied():
    term = make_term('192.0.2.42%3:8443')
    assert matching_columns({'Destination IP': '192.0.2.42', 'Port': 8443, 'Route Domain': 3}, term) == {
        'Destination IP', 'Port', 'Route Domain'}
    assert not matching_columns({'Destination IP': '192.0.2.42', 'Port': 443, 'Route Domain': 3}, term)
    assert not matching_columns({'Destination IP': '192.0.2.42', 'Port': 8443, 'Route Domain': 4}, term)


def test_file_multi_columns_headers_and_de_duplicates(tmp_path):
    source = tmp_path / 'search.xlsx'
    book = Workbook()
    sheet = book.active
    sheet.title = 'Targets'
    sheet.append(['IP', 'Virtual Server', 'Comment'])
    sheet.append(['192.0.2.100', 'vs_app', None])
    sheet.append(['192.0.2.100', 'vs_app', None])
    book.save(source)
    terms = load_search_terms(files=[source])
    assert {(x.value, x.kind) for x in terms} == {('192.0.2.100', 'IP'), ('vs_app', 'OBJECT')}


def test_file_csv_and_txt_are_supported(tmp_path):
    csv_file = tmp_path / 'search.csv'
    csv_file.write_text('Name,IP\nvs_retired,192.0.2.200\n', encoding='utf-8')
    txt_file = tmp_path / 'search.txt'
    txt_file.write_text('# note\n/Common/vs_app\n', encoding='utf-8')
    terms = load_search_terms(files=[csv_file, txt_file])
    assert {x.value for x in terms} == {'vs_retired', '192.0.2.200', '/Common/vs_app'}


def test_unknown_file_is_a_command_error(tmp_path):
    with pytest.raises(ValueError, match='Search file not found'):
        load_search_terms(files=[tmp_path / 'missing.txt'])


def test_search_results_include_negative_matches():
    audit = fixture_audit()
    terms = load_search_terms(virtual_servers=['vs_app', 'vs_nonexistent'])
    marks, results = search_matches(audit, terms)
    assert marks
    assert any(x['Search Term'] == 'vs_app' and x['Status'] == 'FOUND' for x in results)
    assert any(x['Search Term'] == 'vs_nonexistent' and x['Status'] == 'NOT FOUND' for x in results)
    assert all(x['Read Only'] == 'YES - HIGHLIGHT ONLY' for x in results)


def test_excel_highlights_matching_cells_without_removing_sheets(tmp_path):
    audit = fixture_audit()
    terms = load_search_terms(virtual_servers=['vs_app'], objects=['192.0.2.200'])
    output = tmp_path / 'result.xlsx'
    as_excel(audit, output, search_terms=terms)
    book = load_workbook(output)
    original = [title for title, _ in SHEETS if title != 'FreedIP']
    assert book.sheetnames == original + ['Search Results']
    vs_sheet = book['GSLB Virtual Servers']
    vs_column = {cell.value: cell.column for cell in vs_sheet[1]}['Virtual Server']
    vs_cells = [row[vs_column - 1] for row in list(vs_sheet)[1:]
                if row[vs_column - 1].value == '/Common/vs_app']
    assert vs_cells
    assert all(cell.fill.fgColor.rgb[-6:] == 'FFF59D' for cell in vs_cells)
    assert any(row[0].value == 'vs_app' for row in book['Search Results'].iter_rows(min_row=2))
    assert all(row[0].value != 'Search Results' for row in book['Search Results'].iter_rows(min_row=2))
    book.close()


def test_search_does_not_change_audit_verdict_or_approval(tmp_path):
    audit = fixture_audit()
    before = [(row['Verdict'], row.get('Approval Status')) for row in audit.members]
    as_excel(audit, tmp_path / 'search.xlsx', search_terms=load_search_terms(objects=['vs_app']))
    assert before == [(row['Verdict'], row.get('Approval Status')) for row in audit.members]


def test_csv_adds_search_results_only_with_search(tmp_path):
    audit = fixture_audit()
    terms = load_search_terms(virtual_servers=['vs_app'])
    paths = as_csv(audit, tmp_path / 'report', search_terms=terms)
    assert any(path.endswith('Search_Results.csv') for path in paths)
    with (tmp_path / 'report' / 'Search_Results.csv').open(encoding='utf-8-sig', newline='') as handle:
        rows = list(csv.DictReader(handle))
    assert any(row['Status'] == 'FOUND' for row in rows)
    plain = as_csv(audit, tmp_path / 'without')
    assert not any(path.endswith('Search_Results.csv') for path in plain)


def test_cli_search_on_existing_raw_and_file(tmp_path):
    path = tmp_path / 'terms.txt'
    path.write_text('192.0.2.200\n', encoding='utf-8')
    output = tmp_path / 'highlight.xlsx'
    code = main(['analyze', '--from-raw', str(ROOT / 'examples' / 'raw_cleanup_simulado'),
                 '--virtual-server', 'vs_app', '--file', str(path), '-o', str(output)])
    assert code == 0
    book = load_workbook(output, read_only=True)
    assert 'Search Results' in book.sheetnames
    assert 'FreedIP' in book.sheetnames
    assert 'Pool Impact' in book.sheetnames
    book.close()


def test_search_arguments_remain_optional_and_existing_flags_work():
    args = parser().parse_args(['analyze', '--from-raw', 'snapshot', '--ltm-raw-dir', 'LTMS',
                                '--ltm-coverage-complete', '--freed-ip-file', 'freed.csv',
                                '--file', 'queries.xlsx', '--vs', 'vs_app', '-o', 'output.xlsx'])
    assert args.ltm_coverage_complete
    assert args.freed_ip_file == 'freed.csv'
    assert args.file == ['queries.xlsx']
    assert args.virtual_server == ['vs_app']


def test_no_search_keeps_exact_old_sheet_count(tmp_path):
    output = tmp_path / 'plain.xlsx'
    as_excel(fixture_audit(), output)
    book = load_workbook(output, read_only=True)
    assert len(book.sheetnames) == 17
    book.close()


def test_search_file_header_only_must_fail(tmp_path):
    path = tmp_path / 'headers.csv'
    path.write_text('IP,Name,Status,Comment\n', encoding='utf-8')
    code = main(['analyze', '--from-raw', str(ROOT / 'examples' / 'raw_cleanup_simulado'),
                 '--file', str(path), '-o', str(tmp_path / 'report.xlsx')])
    assert code == 1


def test_full_server_virtual_search_does_not_match_other_inventory_server():
    term = make_term('/Common/GDL-F5:/Common/vs_app', 'VIRTUAL SERVER')
    assert matching_columns({'Object Name': '/Common/vs_app',
                             'Source Dataset': 'server_virtuals::/Common/GDL-F5'}, term) == {'Object Name'}
    assert not matching_columns({'Object Name': '/Common/vs_app',
                                 'Source Dataset': 'server_virtuals::/Common/QRO-F5'}, term)
    assert not matching_columns({'Object Name': '/Common/vs_app',
                                 'Source Dataset': 'server_virtuals::'}, term)


def test_narrative_excel_cells_are_not_search_queries(tmp_path):
    file = tmp_path / 'list.csv'
    file.write_text('IP,Name,Notes\n192.0.2.100,vs_app,This is not a decommission approval\n', encoding='utf-8')
    terms = load_search_terms(files=[file])
    assert {x.value for x in terms} == {'192.0.2.100', 'vs_app'}


def test_bilingual_help_and_readme_present():
    assert 'amarillo' in parser().format_help().lower()
    assert 'Español' in (ROOT / 'README.md').read_text(encoding='utf-8')
    assert 'English' in (ROOT / 'README.md').read_text(encoding='utf-8')
    assert (ROOT / 'docs' / 'USER_GUIDE_ES.md').exists()
    assert (ROOT / 'docs' / 'USER_GUIDE_EN.md').exists()
