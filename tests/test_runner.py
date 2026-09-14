"""Tests for doppel.runner (Day 6). respx mocks spec + auth + probes."""

import asyncio

import pytest
import respx
from httpx import Response

from doppel.runner import _base_url_of, dry_run, scan
from doppel.settings import Settings

BASE = "http://localhost:5000"

SPEC = {
    "openapi": "3.0.0",
    "info": {"title": "t", "version": "1.0.0"},
    "paths": {
        "/ping": {"get": {"responses": {"200": {"description": "ok"}}}},
        "/me": {
            "get": {
                "security": [{"bearerAuth": []}],
                "responses": {"200": {"description": "ok"}},
            }
        },
    },
    "components": {"securitySchemes": {"bearerAuth": {"type": "http", "scheme": "bearer"}}},
}


def test_base_url_derivation():
    assert _base_url_of("http://localhost:5000/openapi.json") == "http://localhost:5000"
    with pytest.raises(ValueError):
        _base_url_of("openapi.yaml")  # a file path has no host


@respx.mock
def test_dry_run_end_to_end():
    respx.get(f"{BASE}/openapi.json").mock(return_value=Response(200, json=SPEC))
    respx.post(f"{BASE}/users/v1/register").mock(return_value=Response(200, json={}))
    respx.post(f"{BASE}/users/v1/login").mock(
        return_value=Response(200, json={"auth_token": "tok"})
    )
    ping = respx.get(f"{BASE}/ping").mock(return_value=Response(200))
    me = respx.get(f"{BASE}/me").mock(return_value=Response(200, json={}))

    events: list[tuple[int, int, str]] = []

    async def run():
        return await dry_run(
            f"{BASE}/openapi.json",
            Settings(),
            on_progress=lambda i, total, desc: events.append((i, total, desc)),
        )

    result = asyncio.run(run())

    assert result.target == BASE
    assert {(e.method, e.path) for e in result.endpoints} == {("GET", "/ping"), ("GET", "/me")}
    assert result.findings == []
    # 2 users x (register + login) = 4 auth calls, + 2 endpoint probes = 6
    assert result.requests_sent == 6
    assert ping.called and me.called
    # /me probe carried the bearer token from the primary session
    assert me.calls.last.request.headers.get("authorization") == "Bearer tok"
    # progress reported once per endpoint, with the right total
    assert [e[1] for e in events] == [2, 2]


@respx.mock
def test_dry_run_blocks_out_of_scope():
    async def run():
        return await dry_run("http://evil.example/openapi.json", Settings())

    from doppel.core.scope import ScopeError

    with pytest.raises(ScopeError):
        asyncio.run(run())


PING_SPEC = {
    "openapi": "3.0.0",
    "info": {"title": "t", "version": "1.0.0"},
    "paths": {"/ping": {"get": {"responses": {"200": {"description": "ok"}}}}},
}


@respx.mock
def test_scan_fans_scanners_and_collects_findings():
    respx.get(f"{BASE}/openapi.json").mock(return_value=Response(200, json=PING_SPEC))
    respx.post(f"{BASE}/users/v1/register").mock(return_value=Response(200, json={}))
    respx.post(f"{BASE}/users/v1/login").mock(return_value=Response(200, json={"auth_token": "t"}))
    # /ping has no security headers and discloses a server version -> misconfig fires;
    # no 429 across the burst -> rate_limit fires.
    respx.get(f"{BASE}/ping").mock(return_value=Response(200, json={}, headers={"server": "Werkzeug/2.2.3"}))

    settings = Settings(http={"rate_limit_per_s": 0})

    async def run():
        return await scan(f"{BASE}/openapi.json", settings)

    result = asyncio.run(run())

    scanners_that_fired = {f.scanner for f in result.findings}
    assert "misconfig" in scanners_that_fired
    assert "rate_limit" in scanners_that_fired
    assert result.requests_sent > 0
    assert result.payload_mode == "static"
