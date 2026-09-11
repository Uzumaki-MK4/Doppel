"""Tests for HTTP cassettes: record then replay offline (Day 12)."""

import asyncio

import httpx
import pytest
import respx
from httpx import Response

from apiguard.core.http_engine import Cassette, CassetteMiss, HttpEngine, _response_from_stored

# Nothing listens on this port: if replay tried the network the test would fail,
# which is exactly the offline guarantee we want to prove.
BASE = "http://localhost:5999"


@respx.mock
def _record_into(tmp_path):
    respx.get(f"{BASE}/x").mock(
        return_value=Response(200, json={"ok": True}, headers={"x-test": "1"})
    )
    respx.post(f"{BASE}/y").mock(return_value=Response(201, json={"created": True}))

    async def go():
        cassette = Cassette(mode="record")
        async with HttpEngine(rate_limit_per_s=0, cassette=cassette) as engine:
            await engine.send("GET", f"{BASE}/x")
            await engine.send("POST", f"{BASE}/y", json_body={"a": 1})
        cassette.save(str(tmp_path), meta={"spec_source": f"{BASE}/openapi.json"})

    asyncio.run(go())


def test_record_then_replay_is_offline(tmp_path):
    _record_into(tmp_path)

    assert Cassette.read_meta(str(tmp_path))["spec_source"] == f"{BASE}/openapi.json"

    cassette = Cassette.load(str(tmp_path))

    async def go():
        # No respx here and nothing on :5999 -> responses must come from the cassette.
        async with HttpEngine(rate_limit_per_s=0, cassette=cassette) as engine:
            gx = await engine.send("GET", f"{BASE}/x")
            py = await engine.send("POST", f"{BASE}/y", json_body={"a": 1})
            return gx, py

    gx, py = asyncio.run(go())
    assert gx.status == 200
    assert gx.response.json() == {"ok": True}
    assert gx.evidence.response_headers.get("x-test") == "1"
    assert py.status == 201
    assert py.response.json() == {"created": True}


def test_replay_miss_raises(tmp_path):
    _record_into(tmp_path)
    cassette = Cassette.load(str(tmp_path))

    async def go():
        async with HttpEngine(rate_limit_per_s=0, cassette=cassette) as engine:
            await engine.send("GET", f"{BASE}/never-recorded")

    with pytest.raises(CassetteMiss):
        asyncio.run(go())


def test_repeated_identical_requests_replay_in_order(tmp_path):
    """Identical requests (e.g. a rate-limit burst) must replay each recorded
    response, not just the last one."""
    calls = {"n": 0}

    @respx.mock
    def record():
        def handler(request):
            calls["n"] += 1
            return Response(200 if calls["n"] == 1 else 429)

        respx.get(f"{BASE}/burst").mock(side_effect=handler)

        async def go():
            cassette = Cassette(mode="record")
            async with HttpEngine(rate_limit_per_s=0, cassette=cassette) as engine:
                await engine.send("GET", f"{BASE}/burst")
                await engine.send("GET", f"{BASE}/burst")
            cassette.save(str(tmp_path))

        asyncio.run(go())

    record()
    cassette = Cassette.load(str(tmp_path))

    async def replay():
        async with HttpEngine(rate_limit_per_s=0, cassette=cassette) as engine:
            first = (await engine.send("GET", f"{BASE}/burst")).status
            second = (await engine.send("GET", f"{BASE}/burst")).status
            third = (await engine.send("GET", f"{BASE}/burst")).status
            return [first, second, third]

    # First two match the recording in order; a third request repeats the last.
    assert asyncio.run(replay()) == [200, 429, 429]


def test_replay_strips_content_encoding():
    """A stored Content-Encoding must not make httpx re-decode the (already
    decoded) body and crash."""
    request = httpx.Request("GET", "http://localhost/x")
    resp = _response_from_stored(
        request,
        {"status": 200, "headers": {"content-encoding": "gzip", "x-keep": "1"}, "body": "hello"},
    )
    assert resp.text == "hello"
    assert "content-encoding" not in {k.lower() for k in resp.headers}
    assert resp.headers.get("x-keep") == "1"
