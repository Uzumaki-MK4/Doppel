"""Tests for doppel.scanners.ssrf (Day 9)."""

import asyncio
from urllib.parse import unquote

import respx
from httpx import Response

from doppel.core.http_engine import HttpEngine
from doppel.core.models import Endpoint, Parameter
from doppel.scanners.base import ScanContext
from doppel.scanners.ssrf import SsrfScanner, _looks_like_url_param

BASE = "http://localhost:5000"


def _endpoint(param: Parameter) -> Endpoint:
    return Endpoint(path="/fetch", method="GET", parameters=[param], request_body_schema=None, security=[])


def test_url_param_detection():
    assert _looks_like_url_param(Parameter(name="callback_url", location="query", type_="string"))
    assert _looks_like_url_param(Parameter(name="x", location="query", type_="string", format_="uri"))
    assert not _looks_like_url_param(Parameter(name="q", location="query", type_="string"))


@respx.mock
def test_detects_ssrf_metadata():
    def handler(request):
        if "169.254.169.254" in unquote(request.url.params.get("url", "")):
            return Response(200, text="ami-id: ami-123\ninstance-id: i-abc")
        return Response(200, json={})

    respx.get(f"{BASE}/fetch").mock(side_effect=handler)

    async def go():
        async with HttpEngine(rate_limit_per_s=0) as engine:
            scanner = SsrfScanner(ScanContext(engine=engine, base_url=BASE))
            return await scanner.run(_endpoint(Parameter(name="url", location="query", type_="string")))

    findings = asyncio.run(go())
    assert len(findings) == 1
    assert findings[0].scanner == "ssrf"
    assert findings[0].severity.value == "high"


def test_no_url_shaped_param_no_findings():
    async def go():
        async with HttpEngine(rate_limit_per_s=0) as engine:
            scanner = SsrfScanner(ScanContext(engine=engine, base_url=BASE))
            # 'q' is not URL-shaped, so no request is even sent.
            return await scanner.run(_endpoint(Parameter(name="q", location="query", type_="string")))

    assert asyncio.run(go()) == []
