"""HTML report generator (BRAIN.md D27).

A thin library consumer (invariant 1): turns a `ScanResult` into a single,
self-contained HTML file via jinja2 — inline CSS only, no external fonts/scripts,
so the report opens offline (the demo runs with wifi off).

Two things matter here:

* **Autoescaping is ON.** Findings embed real, possibly attacker-controlled
  response bodies (XSS markers, ``<script>`` …). The report must render them as
  inert text, never execute them — otherwise the security tool's own output is an
  XSS vector. jinja2's HTML autoescape does this; `tests/test_report.py` asserts it.
* **The AI trace is surfaced.** For every AI-adjudicated finding the report shows
  the model, seed, temperature, the confidence signals (as bars) and the oracle's
  prompt + raw response — the explainability that distinguishes the BOLA engine.
"""

from __future__ import annotations

from pathlib import Path

import jinja2

from doppel.core.models import ScanResult

_DIR = Path(__file__).resolve().parent
_TEMPLATE = "template.html"

_SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]


def _environment() -> jinja2.Environment:
    return jinja2.Environment(
        loader=jinja2.FileSystemLoader(str(_DIR)),
        autoescape=jinja2.select_autoescape(["html", "htm"]),  # escape untrusted bodies
        trim_blocks=True,
        lstrip_blocks=True,
    )


def render_report(result: ScanResult, *, generated_at: str | None = None) -> str:
    """Render a ScanResult to a self-contained HTML string."""
    template = _environment().get_template(_TEMPLATE)
    return template.render(
        r=result,
        severity_counts=result.severity_counts(),
        severity_order=_SEVERITY_ORDER,
        generated_at=generated_at,
        n_findings=len(result.findings),
        n_endpoints=len(result.endpoints),
        n_ai=sum(1 for f in result.findings if f.ai_trace is not None),
    )


def write_report(result: ScanResult, out_path: str, *, generated_at: str | None = None) -> Path:
    """Render and write the HTML report; returns the path written."""
    path = Path(out_path)
    if path.parent != Path(""):
        path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_report(result, generated_at=generated_at), encoding="utf-8")
    return path
