"""Tests for apiguard.scanners.rate_limit (Day 10)."""

import asyncio

import respx
from httpx import Response

from apiguard.core.http_engine import HttpEngine
from apiguard.core.models import Endpoint, Parameter
from apiguard.scanners.base import ScanContext
from apiguard.scanners.rate_limit import RateLimitScanner

BASE = "http://localhost:5000"


def _root() -> Endpoint:
    return Endpoint(path="/", method="GET", parameters=[], request_body_schema=None, security=[])


def _run(endpoint, handler_kwargs, burst=5):
    respx.get(f"{BASE}{endpoint.path}").mock(**handler_kwargs)

    async def go():
        async with HttpEngine(rate_limit_per_s=0, max_concurrency=5) as engine:
            scanner = RateLimitScanner(ScanContext(engine=engine, base_url=BASE), burst=burst)
            return await scanner.run(endpoint)

    return asyncio.run(go())


@respx.mock
def test_flags_absence_of_rate_limit():
    findings = _run(_root(), {"return_value": Response(200, json={})})
    assert len(findings) == 1
    assert findings[0].scanner == "rate_limit"
    assert findings[0].owasp_id == "API4:2023"


@respx.mock
def test_no_finding_when_429_seen():
    calls = {"n": 0}

    def handler(request):
        calls["n"] += 1
        return Response(429 if calls["n"] > 2 else 200)

    findings = _run(_root(), {"side_effect": handler})
    assert findings == []


def test_skips_endpoint_with_params():
    ep = Endpoint(
        path="/x/{id}",
        method="GET",
        parameters=[Parameter(name="id", location="path", type_="string")],
        request_body_schema=None,
        security=[],
    )

    async def go():
        async with HttpEngine(rate_limit_per_s=0) as engine:
            return await RateLimitScanner(ScanContext(engine=engine, base_url=BASE)).run(ep)

    assert asyncio.run(go()) == []  # no request sent for a parameterised endpoint
