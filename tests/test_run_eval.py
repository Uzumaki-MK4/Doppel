"""Tests for benchmark/run_eval.py — the precision/recall/F1 harness (Day 25).

Pure-function tests over synthetic findings; no live target, no Ollama.
`benchmark/` is a script dir, not a package, so we load run_eval by path.
"""

import importlib.util
import sys
from pathlib import Path

import pytest

from apiguard.core.models import Endpoint, Evidence, Finding, ScanResult, Severity

_RUN_EVAL = Path(__file__).resolve().parent.parent / "benchmark" / "run_eval.py"
_spec = importlib.util.spec_from_file_location("run_eval", _RUN_EVAL)
run_eval = importlib.util.module_from_spec(_spec)
sys.modules["run_eval"] = run_eval  # dataclass annotation resolution needs it registered
_spec.loader.exec_module(run_eval)


def _finding(scanner, path, fid, method="GET", owasp="API1:2023"):
    ev = Evidence(request_method=method, request_url=f"http://x{path}", response_status=200,
                  response_body="{}", curl_repro="curl http://x")
    return Finding(
        id=fid, title=f"{scanner} {path}", scanner=scanner,
        endpoint=Endpoint(path=path, method=method, parameters=[], request_body_schema=None, security=["bearerAuth"]),
        severity=Severity.HIGH, owasp_id=owasp, confidence=0.9,
        description="d", remediation="r", evidence=ev, ai_trace=None,
    )


def _result(target, findings, requests_sent=42):
    return ScanResult(target=target, spec_url=f"{target}/openapi.json", model="m", seed=42,
                      payload_mode="static", endpoints=[], findings=findings, requests_sent=requests_sent)


VAMPI = "http://localhost:5000"

_GT_DICT = {
    "targets": {"vampi": {"base_url_contains": ":5000"}, "crapi": {"base_url_contains": ":8888"}},
    "vulns": [
        {"id": "v-jwt", "target": "vampi", "title": "weak jwt", "owasp_id": "API2:2023",
         "vuln_class": "broken_auth", "detectable": True, "match": {"scanner": "jwt"}},
        {"id": "v-sqli", "target": "vampi", "title": "sqli", "owasp_id": "API8:2023",
         "vuln_class": "injection", "detectable": True,
         "match": {"scanner": "injection", "path": "/users/v1/{username}", "id_contains": "sqli"}},
        {"id": "v-bola-book", "target": "vampi", "title": "book bola", "owasp_id": "API1:2023",
         "vuln_class": "bola", "detectable": True,
         "match": {"scanner": "bola", "path": "/books/v1/{book_title}"}},
        {"id": "v-headers", "target": "vampi", "title": "headers", "owasp_id": "API8:2023",
         "vuln_class": "misconfig", "detectable": True,
         "match": {"scanner": "misconfig", "id_contains": "missing-security-headers"}},
        {"id": "v-mass-assign", "target": "vampi", "title": "mass assignment (no detector)",
         "owasp_id": "API6:2023", "vuln_class": "mass_assignment", "detectable": False},
    ],
}


def _gt():
    return run_eval.GroundTruth.model_validate(_GT_DICT)


def test_match_scanner_only_and_path():
    gt = _gt()
    jwt = next(v for v in gt.vulns if v.id == "v-jwt")
    # jwt matches on scanner alone, regardless of the (incidental) endpoint
    assert jwt.match.matches(_finding("jwt", "/books/v1/{book_title}", "jwt-weak-secret-get-books-v1-book-title"))
    assert not jwt.match.matches(_finding("bola", "/books/v1/{book_title}", "bola-x"))

    sqli = next(v for v in gt.vulns if v.id == "v-sqli")
    assert sqli.match.matches(_finding("injection", "/users/v1/{username}", "injection-sqli-get-users-v1-username-username"))
    # right scanner+path but XSS id (no 'sqli' substring) -> not the SQLi vuln
    assert not sqli.match.matches(_finding("injection", "/users/v1/{username}", "injection-xss-get-users-v1-username-username"))


def test_vacuous_match_rejected():
    with pytest.raises(Exception):
        run_eval.Match.model_validate({})


def test_detectable_requires_match_and_vice_versa():
    with pytest.raises(Exception):
        run_eval.GroundTruthEntry.model_validate(
            {"id": "x", "target": "vampi", "title": "t", "owasp_id": "API1:2023",
             "vuln_class": "bola", "detectable": True})  # detectable, no match
    with pytest.raises(Exception):
        run_eval.GroundTruthEntry.model_validate(
            {"id": "x", "target": "vampi", "title": "t", "owasp_id": "API1:2023",
             "vuln_class": "bola", "detectable": False, "match": {"scanner": "bola"}})  # non-detectable, has match


def test_target_routing():
    gt = _gt()
    assert gt.route("http://localhost:5000") == "vampi"
    assert gt.route("http://127.0.0.1:8888") == "crapi"
    assert gt.route("http://example.org:9999") is None


def test_evaluate_tp_fp_fn():
    gt = _gt()
    findings = [
        _finding("jwt", "/books/v1/{book_title}", "jwt-weak-secret-get-books-v1-book-title"),   # -> v-jwt
        _finding("injection", "/users/v1/{username}", "injection-sqli-get-users-v1-username-username"),  # -> v-sqli
        _finding("bola", "/books/v1/{book_title}", "bola-get-books-v1-book-title-x"),           # -> v-bola-book
        _finding("misconfig", "/", "misconfig-missing-security-headers"),                       # -> v-headers
        _finding("bola", "/unknown/{id}", "bola-get-unknown-id-x"),                             # FP (matches nothing)
    ]
    m = run_eval.evaluate("full", _result(VAMPI, findings), gt)
    assert m.target == "vampi"
    assert m.tp == 4                       # jwt, sqli, bola-book, headers
    assert m.fp == 1                       # the /unknown finding
    assert m.fn == 1                       # v-mass-assign (no detector)
    assert m.precision == pytest.approx(4 / 5)
    assert m.recall == pytest.approx(4 / 5)
    assert m.f1 == pytest.approx(0.8)
    assert m.missed_vuln_ids == ["v-mass-assign"]
    assert m.fp_finding_ids == ["bola-get-unknown-id-x"]
    assert m.ambiguous == []


def test_evaluate_perfect_and_empty():
    gt = _gt()
    # only the 4 detectable vulns found, nothing spurious -> precision 1.0
    findings = [
        _finding("jwt", "/x", "jwt-weak-secret-get-x"),
        _finding("injection", "/users/v1/{username}", "injection-sqli-get-users-v1-username-username"),
        _finding("bola", "/books/v1/{book_title}", "bola-get-books-v1-book-title-x"),
        _finding("misconfig", "/", "misconfig-missing-security-headers"),
    ]
    m = run_eval.evaluate("full", _result(VAMPI, findings), gt)
    assert m.fp == 0 and m.precision == pytest.approx(1.0)
    assert m.recall == pytest.approx(4 / 5)  # still misses the non-detectable one

    empty = run_eval.evaluate("none", _result(VAMPI, []), gt)
    assert empty.tp == 0 and empty.fp == 0 and empty.fn == 5
    assert empty.precision == 0.0 and empty.recall == 0.0 and empty.f1 == 0.0


def test_evaluate_flags_matcher_overlap():
    # two detectable entries that BOTH match the same finding -> ambiguous (double-count smell)
    gt = run_eval.GroundTruth.model_validate({
        "targets": {"vampi": {"base_url_contains": ":5000"}},
        "vulns": [
            {"id": "a", "target": "vampi", "title": "a", "owasp_id": "API1:2023", "vuln_class": "bola",
             "detectable": True, "match": {"scanner": "bola"}},
            {"id": "b", "target": "vampi", "title": "b", "owasp_id": "API1:2023", "vuln_class": "bola",
             "detectable": True, "match": {"path": "/books/v1/{book_title}"}},
        ],
    })
    m = run_eval.evaluate("x", _result(VAMPI, [_finding("bola", "/books/v1/{book_title}", "bola-x")]), gt)
    assert len(m.ambiguous) == 1
    assert m.ambiguous[0][0] == "bola-x"
    assert sorted(m.ambiguous[0][1]) == ["a", "b"]


def test_unknown_target_raises():
    gt = _gt()
    with pytest.raises(ValueError):
        run_eval.evaluate("x", _result("http://example.org:1234", []), gt)


def test_real_ground_truth_file_is_valid():
    """The committed ground_truth.yaml must load, route, and have consistent matchers."""
    gt = run_eval.load_ground_truth()
    assert gt.vulns, "ground truth is empty"
    assert set(gt.targets) >= {"vampi"}
    # every entry routes to a declared target; detectable<->match already validated by the model
    for v in gt.vulns:
        assert v.target in gt.targets
