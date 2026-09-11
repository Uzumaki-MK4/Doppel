"""Tests for apiguard.scanners.misconfig (Day 10)."""

import asyncio

import respx
from httpx import Response

from apiguard.core.http_engine import HttpEngine
from apiguard.core.models import Endpoint
from apiguard.scanners.base import ScanContext
from apiguard.scanners.misconfig import MisconfigScanner

BASE = "http://localhost:5000"
_ALL_SEC_HEADERS = {
    "x-content-type-options": "nosniff",
    "x-frame-options": "DENY",
    "content-security-policy": "default-src 'self'",
    "strict-transport-security": "max-age=31536000",
    "referrer-policy": "no-referrer",
}


def _ep() -> Endpoint:
    return Endpoint(path="/", method="GET", parameters=[], request_body_schema=None, security=[])


def _run() -> list:
    async def go():
        async with HttpEngine(rate_limit_per_s=0) as engine:
            return await MisconfigScanner(ScanContext(engine=engine, base_url=BASE)).run(_ep())

    return asyncio.run(go())


@respx.mock
def test_missing_headers_and_version_disclosure():
    respx.get(f"{BASE}/").mock(
        return_value=Response(200, json={}, headers={"server": "Werkzeug/2.2.3 Python/3.11"})
    )
    ids = {f.id for f in _run()}
    assert "misconfig-missing-security-headers" in ids
    assert "misconfig-version-disclosure" in ids
    assert "misconfig-permissive-cors" not in ids


@respx.mock
def test_all_headers_present_no_header_finding():
    respx.get(f"{BASE}/").mock(return_value=Response(200, json={}, headers=_ALL_SEC_HEADERS))
    ids = {f.id for f in _run()}
    assert "misconfig-missing-security-headers" not in ids
    assert "misconfig-version-disclosure" not in ids  # no server header


@respx.mock
def test_verbose_error_stacktrace():
    respx.get(f"{BASE}/").mock(
        return_value=Response(
            500,
            text="Traceback (most recent call last): sqlalchemy error",
            headers={"content-type": "text/html"},
        )
    )
    assert any("verbose-error" in f.id for f in _run())


@respx.mock
def test_permissive_cors_reflected_with_credentials():
    def handler(request):
        headers = {"server": "x/1.0"}
        origin = request.headers.get("origin")
        if origin:
            headers["access-control-allow-origin"] = origin
            headers["access-control-allow-credentials"] = "true"
        return Response(200, json={}, headers=headers)

    respx.get(f"{BASE}/").mock(side_effect=handler)
    cors = [f for f in _run() if f.id == "misconfig-permissive-cors"]
    assert len(cors) == 1
    assert cors[0].severity.value == "high"
