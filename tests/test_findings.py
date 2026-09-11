"""Tests for apiguard.core.findings — dedup, OWASP, evidence validation (D11)."""

import pytest

from apiguard.core.findings import (
    OWASP_API_2023,
    dedupe,
    finalize,
    is_valid_owasp_id,
    owasp_name,
)
from apiguard.core.models import Endpoint, Evidence, Finding, Severity


def _finding(fid="f1", severity=Severity.LOW, confidence=0.5, owasp="API8:2023", curl="curl x") -> Finding:
    return Finding(
        id=fid,
        title=fid,
        scanner="s",
        endpoint=Endpoint(path="/x", method="GET", parameters=[], request_body_schema=None, security=[]),
        severity=severity,
        owasp_id=owasp,
        confidence=confidence,
        description="d",
        remediation="r",
        evidence=Evidence(
            request_method="GET",
            request_url="http://localhost/x",
            response_status=200,
            response_body="{}",
            curl_repro=curl,
        ),
    )


def test_owasp_catalog_and_lookup():
    assert len(OWASP_API_2023) == 10
    assert owasp_name("API1:2023") == "Broken Object Level Authorization"
    assert owasp_name("nope") == "Unmapped"
    assert is_valid_owasp_id("API7:2023")
    assert not is_valid_owasp_id("API99:2023")


def test_dedupe_keeps_highest_severity():
    low = _finding("dup", severity=Severity.LOW, confidence=0.9)
    high = _finding("dup", severity=Severity.HIGH, confidence=0.3)
    result = dedupe([low, high])
    assert len(result) == 1
    assert result[0].severity == Severity.HIGH  # severity wins over confidence


def test_dedupe_keeps_higher_confidence_at_same_severity():
    a = _finding("dup", severity=Severity.MEDIUM, confidence=0.4)
    b = _finding("dup", severity=Severity.MEDIUM, confidence=0.8)
    assert dedupe([a, b])[0].confidence == 0.8


def test_finalize_sorts_by_severity_then_id():
    findings = [
        _finding("z-low", severity=Severity.LOW),
        _finding("a-crit", severity=Severity.CRITICAL),
        _finding("b-crit", severity=Severity.CRITICAL),
        _finding("m-high", severity=Severity.HIGH),
    ]
    ordered = [f.id for f in finalize(findings)]
    assert ordered == ["a-crit", "b-crit", "m-high", "z-low"]


def test_finalize_rejects_missing_curl():
    with pytest.raises(ValueError):
        finalize([_finding(curl="   ")])


def test_finalize_rejects_invalid_owasp():
    with pytest.raises(ValueError):
        finalize([_finding(owasp="API42:2023")])


def test_finalize_no_dupes_and_each_has_curl():
    findings = [_finding("dup"), _finding("dup"), _finding("other")]
    result = finalize(findings)
    assert len({f.id for f in result}) == len(result)  # no duplicate ids
    assert all(f.evidence.curl_repro.strip() for f in result)
