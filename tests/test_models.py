"""Tests for apiguard.core.models (Day 2).

Proves the Day-2 done-condition: a Finding builds and serializes, plus the
hardening we added (confidence bounds, extra=forbid, string severity) and the
ScanResult shape.
"""

import pytest
from pydantic import ValidationError

from apiguard.core.models import (
    AITrace,
    Endpoint,
    Evidence,
    Finding,
    Parameter,
    ScanResult,
    Severity,
)


def _make_finding(**overrides) -> Finding:
    """A fully-populated Finding, with fields overridable per test."""
    endpoint = Endpoint(
        path="/users/{id}",
        method="GET",
        parameters=[Parameter(name="id", location="path", type_="integer", required=True)],
        security=["bearerAuth"],
        operation_id="get_user_by_id",
    )
    evidence = Evidence(
        request_method="GET",
        request_url="http://localhost:5000/users/1",
        request_headers={"Authorization": "Bearer A"},
        request_body=None,
        response_status=200,
        response_headers={"Content-Type": "application/json"},
        response_body='{"id": 1, "email": "a@example.com"}',
        curl_repro="curl -H 'Authorization: Bearer A' http://localhost:5000/users/1",
    )
    data = dict(
        id="F-0001",
        title="BOLA on /users/{id}",
        scanner="bola",
        endpoint=endpoint,
        severity=Severity.HIGH,
        owasp_id="API1:2023",
        confidence=0.82,
        description="User B read User A's object.",
        remediation="Enforce object-level authorization on the resource.",
        evidence=evidence,
    )
    data.update(overrides)
    return Finding(**data)


def test_finding_builds_and_serializes_roundtrip():
    f = _make_finding()
    js = f.model_dump_json()
    assert '"severity":"high"' in js.replace(" ", "")
    assert Finding.model_validate_json(js) == f


def test_confidence_bounds_enforced():
    with pytest.raises(ValidationError):
        _make_finding(confidence=1.5)
    with pytest.raises(ValidationError):
        _make_finding(confidence=-0.1)


def test_severity_serializes_as_string():
    assert _make_finding(severity=Severity.CRITICAL).model_dump()["severity"] == "critical"


def test_ai_trace_optional_and_attaches():
    assert _make_finding().ai_trace is None
    trace = AITrace(
        model="qwen3:8b",
        seed=42,
        temperature=0.0,
        prompt="Compare response A and B ...",
        raw_response='{"is_leak": true}',
        signals={"id_echo": 1.0, "field_overlap": 0.75},
    )
    f = _make_finding(ai_trace=trace)
    assert f.ai_trace.signals["id_echo"] == 1.0


def test_extra_fields_forbidden():
    with pytest.raises(ValidationError):
        Parameter(name="x", location="query", type_="string", bogus=1)


def test_scanresult_counts_and_roundtrip():
    r = ScanResult(
        target="http://localhost:5000",
        spec_url="http://localhost:5000/openapi.json",
        model="qwen3:8b",
        seed=42,
        payload_mode="both",
        findings=[_make_finding(), _make_finding(id="F-0002", severity=Severity.LOW)],
        requests_sent=137,
    )
    counts = r.severity_counts()
    assert counts["high"] == 1
    assert counts["low"] == 1
    assert counts["info"] == 0
    assert ScanResult.model_validate_json(r.model_dump_json()) == r
