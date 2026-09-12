"""Tests for apiguard.scanners.injection (Day 8). respx mocks the target."""

import asyncio
from urllib.parse import unquote

import respx
from httpx import Response

from apiguard.core.http_engine import HttpEngine
from apiguard.core.models import Endpoint, Parameter
from apiguard.scanners.base import ScanContext
from apiguard.scanners.injection import InjectionScanner, _first_sql_signature

BASE = "http://localhost:5000"
SQL_ERROR = (
    '<html><title>sqlalchemy.exc.OperationalError: (sqlite3.OperationalError) '
    'unrecognized token</title></html>'
)


def _endpoint_with_query() -> Endpoint:
    return Endpoint(
        path="/search",
        method="GET",
        parameters=[Parameter(name="q", location="query", type_="string", required=True)],
        request_body_schema=None,
        security=[],
    )


def _run(scanner: InjectionScanner, endpoint: Endpoint):
    return asyncio.run(scanner.run(endpoint))


def test_sql_signature_matcher():
    assert _first_sql_signature(SQL_ERROR) is not None  # matches one of the SQL signatures
    assert _first_sql_signature('{"ok": true}') is None


@respx.mock
def test_finds_error_based_sqli():
    def handler(request):
        q = unquote(request.url.params.get("q", ""))
        if "'" in q:
            return Response(500, text=SQL_ERROR, headers={"content-type": "text/html"})
        return Response(200, json={"results": []})

    respx.get(f"{BASE}/search").mock(side_effect=handler)

    async def go():
        async with HttpEngine(rate_limit_per_s=0) as engine:
            scanner = InjectionScanner(
                ScanContext(engine=engine, base_url=BASE),
                sqli_payloads=["'"],
                xss_payloads=[],
            )
            return await scanner.run(_endpoint_with_query())

    findings = asyncio.run(go())
    assert len(findings) == 1
    f = findings[0]
    assert f.scanner == "injection"
    assert f.severity.value == "high"
    assert f.confidence == 0.9
    assert "SQL injection" in f.title
    assert "sqlite3" in f.evidence.response_body.lower()
    assert f.evidence.curl_repro.startswith("curl -X GET")


@respx.mock
def test_clean_endpoint_no_finding():
    respx.get(f"{BASE}/search").mock(return_value=Response(200, json={"results": []}))

    async def go():
        async with HttpEngine(rate_limit_per_s=0) as engine:
            scanner = InjectionScanner(
                ScanContext(engine=engine, base_url=BASE),
                sqli_payloads=["'", "' OR 1=1--"],
                xss_payloads=["<x>"],
            )
            return await scanner.run(_endpoint_with_query())

    assert asyncio.run(go()) == []


@respx.mock
def test_detects_reflected_xss_only_in_html():
    marker = "<apiguardXSSMARKER>"

    def handler(request):
        q = unquote(request.url.params.get("q", ""))
        if marker in q:
            return Response(200, text=f"<html>hello {q}</html>", headers={"content-type": "text/html"})
        return Response(200, json={"results": []})

    respx.get(f"{BASE}/search").mock(side_effect=handler)

    async def go():
        async with HttpEngine(rate_limit_per_s=0) as engine:
            scanner = InjectionScanner(
                ScanContext(engine=engine, base_url=BASE),
                sqli_payloads=[],
                xss_payloads=[marker],
            )
            return await scanner.run(_endpoint_with_query())

    findings = asyncio.run(go())
    assert len(findings) == 1
    assert findings[0].title.startswith("Reflected XSS")
    assert findings[0].severity.value == "medium"


@respx.mock
def test_xss_marker_in_json_is_not_flagged():
    marker = "<apiguardXSSMARKER>"
    # Echoed back, but as JSON (not HTML) -> must NOT be flagged.
    respx.get(f"{BASE}/search").mock(
        return_value=Response(200, json={"echo": marker}, headers={"content-type": "application/json"})
    )

    async def go():
        async with HttpEngine(rate_limit_per_s=0) as engine:
            scanner = InjectionScanner(
                ScanContext(engine=engine, base_url=BASE),
                sqli_payloads=[],
                xss_payloads=[marker],
            )
            return await scanner.run(_endpoint_with_query())

    assert asyncio.run(go()) == []


@respx.mock
def test_detects_boolean_based_sqli():
    """TRUE condition leaks data a FALSE condition does not -> 200-OK boolean SQLi."""

    def handler(request):
        from urllib.parse import unquote

        q = unquote(request.url.params.get("q", ""))
        if "'1'='1" in q:  # true condition -> returns the whole table
            return Response(200, json={"users": [{"u": "a"}, {"u": "b"}, {"u": "c"}, {"u": "d"}]})
        # false condition and baseline ("test") -> empty / not found
        return Response(200, json={"users": []})

    respx.get(f"{BASE}/search").mock(side_effect=handler)
    ep = _endpoint_with_query()

    async def go():
        async with HttpEngine(rate_limit_per_s=0) as engine:
            scanner = InjectionScanner(
                ScanContext(engine=engine, base_url=BASE), sqli_payloads=[], xss_payloads=[]
            )
            return await scanner.run(ep)

    findings = asyncio.run(go())
    assert len(findings) == 1
    assert "SQL injection" in findings[0].title
    assert findings[0].confidence == 0.85  # boolean-based confidence


@respx.mock
def test_boolean_no_false_positive_when_responses_match():
    """A non-injectable endpoint returns the same body for true/false -> no finding."""
    respx.get(f"{BASE}/search").mock(return_value=Response(200, json={"results": []}))

    async def go():
        async with HttpEngine(rate_limit_per_s=0) as engine:
            scanner = InjectionScanner(
                ScanContext(engine=engine, base_url=BASE), sqli_payloads=[], xss_payloads=[]
            )
            return await scanner.run(_endpoint_with_query())

    assert asyncio.run(go()) == []


@respx.mock
def test_xss_not_flagged_on_error_page():
    """Reflection inside a 5xx debug page is the verbose-error misconfig, not XSS."""
    marker = "<apiguardXSSMARKER>"

    def handler(request):
        q = unquote(request.url.params.get("q", ""))
        if marker in q:  # reflected, but in a 500 debug page
            return Response(500, text=f"<html>Traceback ... {q}</html>", headers={"content-type": "text/html"})
        return Response(200, json={})

    respx.get(f"{BASE}/search").mock(side_effect=handler)

    async def go():
        async with HttpEngine(rate_limit_per_s=0) as engine:
            scanner = InjectionScanner(
                ScanContext(engine=engine, base_url=BASE), sqli_payloads=[], xss_payloads=[marker]
            )
            return await scanner.run(_endpoint_with_query())

    assert asyncio.run(go()) == []  # not flagged as XSS
