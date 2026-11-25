"""v0.5.4 focused-view regression tests with synthetic GSLB identities only."""
from __future__ import annotations

import json
import re
import shutil
import subprocess
from copy import deepcopy
from pathlib import Path

import pytest

from f5auditdns.cli import main
from f5auditdns.diagram import build_diagram
from f5auditdns.diagram_html import render_diagram_html
from f5auditdns.diagram_mock import mock_snapshot


def large_mock_graph(size: int = 295) -> dict:
    """Create a stress case without importing customer inventory or network data."""
    graph = build_diagram(mock_snapshot())
    partition = next(p for p in graph["tree"]["children"] if p["partition"] == "/Prod_GSLB")
    branch = next(b for b in partition["children"] if b["id"].startswith("branch|live|"))
    prototype = branch["children"][0]
    original = next(n for n in graph["nodes"] if n["kind"] == "WIDE_IP")
    branch["children"] = []
    graph["nodes"] = [n for n in graph["nodes"] if n["kind"] != "WIDE_IP"]
    for i in range(size):
        entry = deepcopy(prototype)
        entry["label"] = f"app-{i:03d}.example.test"
        entry["id"] = f"wideip|a|/Prod_GSLB/app-{i:03d}.example.test"
        entry["fullPath"] = f"/Prod_GSLB/app-{i:03d}.example.test"
        branch["children"].append(entry)
        graph["nodes"].append({**original, "id": entry["id"], "fullPath": entry["fullPath"], "name": entry["label"]})
    graph["summary"]["wideIPs"] = size
    return graph


def test_focused_mode_is_initial_and_legacy_overview_remains(tmp_path):
    output = render_diagram_html(build_diagram(mock_snapshot()), tmp_path / "topology.html")
    html = output.read_text(encoding="utf-8")
    assert '<div class="main focus-mode"' in html
    assert "let viewMode='focused'" in html
    assert 'id="focused-view"' in html
    assert 'id="overview-view"' in html
    assert 'id="overview-pager"' in html


def test_25_service_page_and_bounded_subtrees(tmp_path):
    graph = large_mock_graph()
    output = render_diagram_html(graph, tmp_path / "stress.html")
    html = output.read_text(encoding="utf-8")
    assert "SERVICE_PAGE_SIZE=25, TREE_PAGE_SIZE=25" in html
    assert "allChildren.slice(safePage*TREE_PAGE_SIZE" in html
    assert 'id="service-next"' in html
    assert 'id="overview-next"' in html
    assert len(graph["tree"]["children"][2]["children"][0]["children"]) == 295
    assert graph["summary"]["wideIPs"] == 295


def test_search_and_navigation_are_offline_and_scoped(tmp_path):
    html = render_diagram_html(large_mock_graph(), tmp_path / "topology.html").read_text(encoding="utf-8")
    assert 'serviceIndex.sort' in html
    assert "function filteredServices()" in html
    assert "const query=viewMode==='overview'" in html
    assert 'function subtreeText(' in html
    assert 'servicesByObject' in html
    assert 'Show Dependencies' in html
    assert "filteredServices()[0]?.id" in html


def test_unlinked_audit_and_security_existing(tmp_path):
    html = render_diagram_html(build_diagram(mock_snapshot()), tmp_path / "topology.html").read_text(encoding="utf-8")
    assert "activeFilter==='orphans'" in html
    assert 'data-filter="orphans"' in html
    assert "NOT RUN" in html
    assert "never unroll thousands" in html
    assert "No incoming verified links" in html
    assert 'READ ONLY / NO CHANGES' in html


def test_generated_html_still_contains_all_canonical_objects(tmp_path):
    graph = large_mock_graph()
    html = render_diagram_html(graph, tmp_path / "topology.html").read_text(encoding="utf-8")
    match = re.search(r'<script type="application/json" id="topology-data">(.*?)</script>', html, re.DOTALL)
    assert match is not None
    payload = json.loads(match.group(1))
    assert payload["summary"]["wideIPs"] == 295
    assert len(payload["nodes"]) == len(graph["nodes"])
    assert len(payload["edges"]) == len(graph["edges"])
    assert len(payload["tree"]["children"][2]["children"][0]["children"]) == 295
    assert payload["metadata"]["readOnly"] is True


def test_local_js_bundle_syntax(tmp_path):
    node = shutil.which("node")
    if not node:
        pytest.skip("Node not present; CI can still test Python and HTML structure")
    html = render_diagram_html(build_diagram(mock_snapshot()), tmp_path / "topology.html").read_text(encoding="utf-8")
    scripts = re.findall(r'<script(?:\s[^>]*)?>(.*?)</script>', html, flags=re.DOTALL | re.IGNORECASE)
    assert len(scripts) >= 3
    for i, script in enumerate(scripts):
        if not script.strip().startswith(('use strict', "'use strict'", '// Avoid')):
            continue
        js = tmp_path / f"script_{i}.js"
        js.write_text(script, encoding="utf-8")
        subprocess.run([node, "--check", str(js)], check=True, capture_output=True, text=True)


def test_diagram_cli_backward_compatible(tmp_path):
    assert main(["diagram", "--mock", "-o", str(tmp_path / "out")]) == 0
    assert (tmp_path / "out" / "gtm_topology.json").is_file()
    assert (tmp_path / "out" / "f5_dns_topology.html").is_file()


def test_interactive_inspector_keeps_snapshot_data_safe(tmp_path):
    graph = build_diagram(mock_snapshot())
    graph["nodes"][0]["name"] = '</script><script>alert("bad")</script>'
    html = render_diagram_html(graph, tmp_path / "topology.html").read_text(encoding="utf-8")
    assert '</script><script>alert' not in html
    assert "\\u003c/script\\u003e" in html
    assert "Read Only" not in html or "READ ONLY" in html


def test_focus_mode_does_not_add_f5_operations(tmp_path):
    html = render_diagram_html(build_diagram(mock_snapshot()), tmp_path / "topology.html").read_text(encoding="utf-8")
    assert 'function setView(' in html
    assert 'function renderNavigator(' in html
    assert 'function renderInspector(' in html
    assert 'function forest(' in html
    assert 'F5ReadOnlyClient' not in html
