"""Tests for doppel.engines.bfla (Day 23)."""

import asyncio

import respx
from httpx import Response

from doppel.core.http_engine import HttpEngine
from doppel.core.identity import Session
from doppel.core.models import Endpoint
from doppel.engines.bfla import _is_privileged, find_bfla_findings

BASE = "http://localhost:5000"


def _ep(path, method="GET", security=None):
    return Endpoint(path=path, method=method, parameters=[], request_body_schema=None, security=security or [])


def _sessions():
    return {"userB": Session(username="apiguard_b", token="B", headers={"Authorization": "Bearer B"})}


def test_is_privileged_by_path_segment():
    assert _is_privileged(_ep("/users/v1/_debug"))
    assert _is_privileged(_ep("/admin/config"))
    assert _is_privileged(_ep("/internal/metrics"))
    assert not _is_privileged(_ep("/books/v1/{book_title}"))
    assert not _is_privileged(_ep("/users/v1/{username}"))


def _run(endpoints, mocks):
    for pattern, resp in mocks.items():
        respx.get(pattern).mock(return_value=resp)

    async def go():
        async with HttpEngine(rate_limit_per_s=0) as engine:
            return await find_bfla_findings(engine, BASE, _sessions(), endpoints)

    return asyncio.run(go())


@respx.mock
def test_flags_credential_leaking_debug_endpoint_critical():
    findings = _run(
        [_ep("/users/v1/_debug")],
        {f"{BASE}/users/v1/_debug": Response(200, json={"users": [{"username": "n", "password": "pass1"}]})},
    )
    assert len(findings) == 1
    f = findings[0]
    assert f.scanner == "bfla"
    assert f.owasp_id == "API5:2023"
    assert f.severity.value == "critical"   # response leaks 'password'
    assert f.confidence == 0.95


@respx.mock
def test_privileged_but_forbidden_is_not_flagged():
    findings = _run(
        [_ep("/admin/users")],
        {f"{BASE}/admin/users": Response(403, json={"error": "forbidden"})},
    )
    assert findings == []  # authorization is working


@respx.mock
def test_privileged_accessible_without_sensitive_data_is_high():
    findings = _run(
        [_ep("/internal/status")],
        {f"{BASE}/internal/status": Response(200, json={"ok": True, "uptime": 42})},
    )
    assert len(findings) == 1
    assert findings[0].severity.value == "high"
    assert findings[0].confidence == 0.85


def test_non_privileged_endpoints_are_skipped():
    async def go():
        async with HttpEngine(rate_limit_per_s=0) as engine:
            return await find_bfla_findings(engine, BASE, _sessions(), [_ep("/books/v1/{x}")])

    assert asyncio.run(go()) == []  # no request sent for a non-privileged path
