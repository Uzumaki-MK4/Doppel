"""Tests for doppel.core.http_engine (Day 4). No live target — respx mocks."""

import asyncio
import time

import httpx
import respx
from httpx import Response

from doppel.core.http_engine import (
    HttpEngine,
    _example_from_schema,
    _RateLimiter,
    build_curl,
    build_request,
)
from doppel.core.models import Endpoint, Parameter


def _endpoint(**kw) -> Endpoint:
    base = dict(path="/x", method="GET", parameters=[], request_body_schema=None, security=[])
    base.update(kw)
    return Endpoint(**base)


def test_build_request_substitutes_path_and_query():
    ep = _endpoint(
        path="/users/{id}",
        method="GET",
        parameters=[
            Parameter(name="id", location="path", type_="integer", required=True),
            Parameter(name="q", location="query", type_="string", required=True, example="hi"),
        ],
    )
    method, url, headers, query, body = build_request(ep, "http://localhost:5000")
    assert method == "GET"
    assert url == "http://localhost:5000/users/1"  # integer placeholder
    assert query == {"q": "hi"}  # example used
    assert body is None


def test_build_request_synthesizes_json_body():
    ep = _endpoint(
        path="/register",
        method="POST",
        request_body_schema={"type": "object", "properties": {"username": {"type": "string"}}},
    )
    method, url, headers, query, body = build_request(ep, "http://localhost:5000")
    assert method == "POST"
    assert headers["Content-Type"] == "application/json"
    assert body == '{"username": "test"}'


def test_example_from_schema_nested():
    schema = {"type": "object", "properties": {"n": {"type": "integer"}, "ok": {"type": "boolean"}}}
    assert _example_from_schema(schema) == {"n": 1, "ok": True}


def test_build_curl_quotes():
    curl = build_curl("POST", "http://localhost:5000/x", {"Authorization": "Bearer a b"}, '{"k":1}')
    assert curl.startswith("curl -X POST http://localhost:5000/x")
    assert "-H 'Authorization: Bearer a b'" in curl
    assert "--data '{\"k\":1}'" in curl


@respx.mock
def test_send_builds_evidence():
    respx.get("http://localhost:5000/me").mock(
        return_value=Response(401, json={"error": "no token"}, headers={"X-Test": "1"})
    )

    async def run():
        async with HttpEngine(rate_limit_per_s=0) as engine:
            ex = await engine.send("GET", "http://localhost:5000/me")
            return ex, engine.requests_sent

    ex, sent = asyncio.run(run())
    assert ex.status == 401
    assert ex.evidence.response_status == 401
    assert ex.evidence.request_method == "GET"
    assert ex.evidence.curl_repro.startswith("curl -X GET http://localhost:5000/me")
    assert ex.evidence.response_headers.get("x-test") == "1"
    assert sent == 1


@respx.mock
def test_send_retries_transport_error_then_succeeds():
    state = {"n": 0}

    def flaky(request):
        state["n"] += 1
        if state["n"] == 1:
            raise httpx.ConnectError("boom", request=request)
        return Response(200, json={"ok": True})

    respx.get("http://localhost:5000/x").mock(side_effect=flaky)

    async def run():
        async with HttpEngine(rate_limit_per_s=0, retries=2) as engine:
            ex = await engine.send("GET", "http://localhost:5000/x")
            return ex, engine.requests_sent

    ex, sent = asyncio.run(run())
    assert ex.status == 200
    assert sent == 2  # one failed attempt + one success


@respx.mock
def test_probe_uses_built_request():
    route = respx.post("http://localhost:5000/register").mock(return_value=Response(200))
    ep = _endpoint(
        path="/register",
        method="POST",
        request_body_schema={"type": "object", "properties": {"username": {"type": "string"}}},
    )

    async def run():
        async with HttpEngine(rate_limit_per_s=0) as engine:
            return await engine.probe(ep, "http://localhost:5000")

    ex = asyncio.run(run())
    assert ex.status == 200
    assert route.called
    sent_body = route.calls.last.request.content.decode()
    assert sent_body == '{"username": "test"}'


@respx.mock
def test_send_json_body_sets_content_type():
    route = respx.post("http://localhost:5000/login").mock(return_value=Response(200))

    async def run():
        async with HttpEngine(rate_limit_per_s=0) as engine:
            return await engine.send(
                "POST", "http://localhost:5000/login", json_body={"u": "a", "p": "b"}
            )

    ex = asyncio.run(run())
    assert ex.status == 200
    sent = route.calls.last.request
    assert sent.headers["content-type"] == "application/json"
    assert sent.content.decode() == '{"u": "a", "p": "b"}'
    assert ex.evidence.request_body == '{"u": "a", "p": "b"}'


def test_rate_limiter_spaces_starts():
    async def run():
        rl = _RateLimiter(per_second=20)  # 0.05s min interval
        start = time.monotonic()
        await rl.wait()
        await rl.wait()
        await rl.wait()
        return time.monotonic() - start

    elapsed = asyncio.run(run())
    assert elapsed >= 0.08  # ~2 intervals of 0.05s, with margin
