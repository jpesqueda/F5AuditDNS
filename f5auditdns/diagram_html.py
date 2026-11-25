"""Generate a single-file topology viewer with embedded, safe graph JSON.

D3.js v7 is used when browser network policy permits. A fully offline SVG
renderer implements the same interactive functionality when the D3 CDN is
unavailable. The HTML never calls the BIG-IP or any backend service.
"""
from __future__ import annotations

import json
from importlib import resources
from pathlib import Path
from typing import Any


def render_diagram_html(graph: dict[str, Any], output: str | Path, *, d3_js: str | Path | None = None) -> Path:
    """Export a portable HTML; protect JSON script context from injection."""
    target = Path(output)
    template = resources.files("f5auditdns").joinpath("static/diagram_template.html").read_text(encoding="utf-8")
    data = json.dumps(graph, ensure_ascii=False, separators=(",", ":"), default=str)
    # A BIG-IP object name or description is untrusted. Prevent HTML/script
    # break-out including </script>, U+2028 and U+2029.
    data = (data.replace("<", "\\u003c").replace(">", "\\u003e")
            .replace("&", "\\u0026").replace("\u2028", "\\u2028")
            .replace("\u2029", "\\u2029"))
    if d3_js is not None:
        source = Path(d3_js)
        if source.stat().st_size > 2_000_000:
            raise ValueError("--d3-js exceeds 2 MB; expected the official minified D3 v7 bundle")
        d3_source = source.read_text(encoding="utf-8")
        if "</script" in d3_source.lower():
            raise ValueError("D3 JavaScript contains an unsafe inline script delimiter")
    else:
        d3_source = "/* Optional D3 v7 bundle was not supplied; native offline SVG renderer is available. */"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(template.replace("__INLINE_DATA__", data).replace("__D3_SOURCE__", d3_source), encoding="utf-8")
    return target
