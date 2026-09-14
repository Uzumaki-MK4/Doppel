"""Tests for doppel.report.generator — the HTML report (Day 27).

Pure rendering; no network. The security-critical assertion is autoescaping:
a finding's response body is untrusted and must never render as live markup.
"""

from doppel.core.models import AITrace, Endpoint, Evidence, Finding, ScanResult, Severity
from doppel.report.generator import render_report, write_report


def _evidence(body: str) -> Evidence:
    return Evidence(
        request_method="GET", request_url="http://localhost:5000/books/v1/x",
        request_headers={"Authorization": "Bearer B"}, request_body=None,
        response_status=200, response_headers={"Content-Type": "application/json"},
        response_body=body, curl_repro="curl -H 'Authorization: Bearer B' http://localhost:5000/books/v1/x",
    )


def _bola_finding() -> Finding:
    return Finding(
        id="bola-get-books-v1-book-title-x",
        title="BOLA: User B can read User A's object via GET /books/v1/{book_title}",
        scanner="bola",
        endpoint=Endpoint(path="/books/v1/{book_title}", method="GET", parameters=[],
                          request_body_schema=None, security=["bearerAuth"]),
        severity=Severity.HIGH, owasp_id="API1:2023", confidence=0.8123,
        description="User B accessed User A's object and received A's secret.",
        remediation="Enforce object-level authorization.",
        evidence=_evidence('{"book_title": "x", "owner": "A", "secret": "A_TOPSECRET"}'),
        ai_trace=AITrace(
            model="qwen3:8b", seed=42, temperature=0.0,
            prompt="RESPONSE_A ... RESPONSE_B_CROSS ...",
            raw_response='{"is_leak": true, "leaked_fields": ["secret"], "reasoning": "B got A data"}',
            signals={"id_echo": 1.0, "field_overlap": 1.0, "status_match": 1.0,
                     "body_divergence": 0.27, "oracle_verdict": 1.0},
        ),
    )


def _misconfig_finding(body: str = "{}") -> Finding:
    return Finding(
        id="misconfig-missing-security-headers", title="Missing security response headers",
        scanner="misconfig",
        endpoint=Endpoint(path="/", method="GET", parameters=[], request_body_schema=None, security=[]),
        severity=Severity.LOW, owasp_id="API8:2023", confidence=0.9,
        description="No X-Content-Type-Options / CSP / HSTS.", remediation="Add the headers.",
        evidence=_evidence(body), ai_trace=None,
    )


def _result(findings) -> ScanResult:
    return ScanResult(
        target="http://localhost:5000", spec_url="http://localhost:5000/openapi.json",
        model="qwen3:8b", seed=42, payload_mode="ai",
        endpoints=[Endpoint(path="/", method="GET", parameters=[], request_body_schema=None, security=[])],
        findings=findings, requests_sent=82,
    )


def test_report_has_structure_and_findings():
    html = render_report(_result([_bola_finding(), _misconfig_finding()]), generated_at="2026-09-14T10:00:00")
    assert html.lstrip().startswith("<!DOCTYPE html>")
    assert "Doppel report" in html
    assert "http://localhost:5000" in html          # target
    assert "qwen3:8b" in html and "seed 42" in html  # reproducibility surfaced
    # both findings rendered
    assert "BOLA: User B can read User A" in html
    assert "Missing security response headers" in html
    assert "API1:2023" in html and "API8:2023" in html
    assert "0.81" in html                            # bola confidence
    assert "curl -H" in html                         # evidence repro


def test_report_surfaces_ai_trace():
    html = render_report(_result([_bola_finding()]))
    # AI trace block: model/seed/temp + every signal name + the raw oracle response
    assert "AI oracle trace" in html
    for signal in ("Id echo", "Field overlap", "Body divergence", "Oracle verdict"):
        assert signal in html                        # humanised signal labels
    assert "0.27" in html                            # a signal value
    assert "is_leak" in html                         # raw schema-validated response shown


def test_report_autoescapes_untrusted_response_body():
    """A reflected-XSS-style body must render as inert text, not live markup."""
    payload = "<script>alert('pwned')</script>"
    html = render_report(_result([_misconfig_finding(body=payload)]))
    assert "<script>alert('pwned')</script>" not in html   # never raw
    assert "&lt;script&gt;" in html                        # escaped instead


def test_report_handles_no_findings():
    html = render_report(_result([]))
    assert "No findings" in html
    assert "0 findings" in html


def test_write_report_creates_file(tmp_path):
    out = tmp_path / "sub" / "report.html"
    path = write_report(_result([_bola_finding()]), str(out), generated_at="2026-09-14T10:00:00")
    assert path.exists()
    text = path.read_text(encoding="utf-8")
    assert "BOLA" in text and "qwen3:8b" in text
