"""Tests for benchmark/zap_adapt.py — the ZAP-report -> scorable-arm adapter (Day 26).

Synthetic ZAP report; no Docker, no live target, no spec fetch (templates passed in).
"""

import importlib.util
import sys
from pathlib import Path

from doppel.core.models import Endpoint

_BENCH = Path(__file__).resolve().parent.parent / "benchmark"


def _load(name):
    spec = importlib.util.spec_from_file_location(name, _BENCH / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod  # dataclass annotation resolution needs it registered
    spec.loader.exec_module(mod)
    return mod


zap_adapt = _load("zap_adapt")
run_eval = _load("run_eval")


def _templates():
    return [
        Endpoint(path="/users/v1/{username}", method="GET", parameters=[], request_body_schema=None, security=[]),
        Endpoint(path="/books/v1", method="GET", parameters=[], request_body_schema=None, security=[]),
    ]


_REPORT = {
    "site": [{
        "@name": "http://localhost:5000",
        "alerts": [
            {"pluginid": "40024", "name": "SQL Injection - SQLite", "riskcode": "3", "confidence": "2",
             "desc": "d", "instances": [{"uri": "http://localhost:5000/users/v1/name1", "method": "GET"}]},
            {"pluginid": "10036", "name": "Server Leaks Version Information via \"Server\" Header",
             "riskcode": "1", "instances": [{"uri": "http://localhost:5000/"}]},
            {"pluginid": "10021", "name": "X-Content-Type-Options Header Missing",
             "riskcode": "1", "instances": [{"uri": "http://localhost:5000/"}]},
            {"pluginid": "10038", "name": "Content Security Policy (CSP) Header Not Set",
             "riskcode": "1", "instances": [{"uri": "http://localhost:5000/books/v1"}]},
            {"pluginid": "10096", "name": "Timestamp Disclosure",  # info noise -> skip
             "riskcode": "1", "instances": [{"uri": "http://localhost:5000/"}]},
            {"pluginid": "10202", "name": "Absence of Anti-CSRF Tokens",  # unmapped Low -> FP
             "riskcode": "1", "instances": [{"uri": "http://localhost:5000/"}]},
        ],
    }]
}


def test_classify_dispositions():
    assert zap_adapt._classify("40024", "SQL Injection - SQLite", 3)[0] == "injection"
    assert zap_adapt._classify("10036", "Server Leaks Version Information", 1)[:2] == ("misconfig", "zap-version-disclosure")
    assert zap_adapt._classify("10021", "X-Content-Type-Options Header Missing", 1)[:2] == ("misconfig", "zap-missing-security-headers")
    assert zap_adapt._classify("10096", "Timestamp Disclosure", 1) is None      # skip plugin
    assert zap_adapt._classify("99999", "Something Weird", 0) is None            # info riskcode
    assert zap_adapt._classify("10202", "Absence of Anti-CSRF Tokens", 1)[0] == "zap-unmapped"  # FP
    assert zap_adapt._classify("10099", "Source Code Disclosure - SQL", 2)[0] == "__oos__"  # real, out-of-scope
    assert zap_adapt._classify("90022", "Application Error Disclosure", 1)[0] == "__oos__"


def test_normalise_path():
    t = _templates()
    assert zap_adapt._normalise_path("/users/v1/name1", t) == "/users/v1/{username}"
    assert zap_adapt._normalise_path("/books/v1", t) == "/books/v1"
    assert zap_adapt._normalise_path("/unknown/thing", t) == "/unknown/thing"  # no template -> unchanged


def test_adapt_produces_scorable_findings():
    result, dispositions = zap_adapt.adapt(_REPORT, _templates(), "5000")
    scanners = sorted(f.scanner for f in result.findings)
    # sqli(injection) + version(misconfig) + headers(misconfig, 2 alerts deduped to 1) + 1 unmapped FP
    assert scanners == ["injection", "misconfig", "misconfig", "zap-unmapped"]
    sqli = next(f for f in result.findings if f.scanner == "injection")
    assert sqli.endpoint.path == "/users/v1/{username}"    # normalised
    # the timestamp info alert was skipped
    assert not any("Timestamp" in f.title for f in result.findings)
    assert sum(1 for d in dispositions if d["disposition"].startswith("skip")) == 1


def test_zap_arm_scores_against_ground_truth():
    result, _ = zap_adapt.adapt(_REPORT, _templates(), "5000")
    gt = run_eval.GroundTruth.model_validate({
        "targets": {"vampi": {"base_url_contains": ":5000"}},
        "vulns": [
            {"id": "sqli", "target": "vampi", "title": "s", "owasp_id": "API8:2023", "vuln_class": "injection",
             "detectable": True, "match": {"scanner": "injection", "path": "/users/v1/{username}", "id_contains": "sqli"}},
            {"id": "ver", "target": "vampi", "title": "v", "owasp_id": "API8:2023", "vuln_class": "misconfig",
             "detectable": True, "match": {"scanner": "misconfig", "id_contains": "version-disclosure"}},
            {"id": "hdr", "target": "vampi", "title": "h", "owasp_id": "API8:2023", "vuln_class": "misconfig",
             "detectable": True, "match": {"scanner": "misconfig", "id_contains": "missing-security-headers"}},
            {"id": "bola", "target": "vampi", "title": "b", "owasp_id": "API1:2023", "vuln_class": "bola",
             "detectable": True, "match": {"scanner": "bola", "path": "/books/v1/{book_title}"}},  # ZAP can't find -> FN
        ],
    })
    m = run_eval.evaluate("zap", result, gt)
    assert m.tp == 3                      # sqli, version, headers
    assert m.fn == 1                      # bola (ZAP has no cross-user notion)
    assert m.fp == 1                      # the unmapped Anti-CSRF alert
    assert m.ambiguous == []
