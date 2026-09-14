"""Tests for doppel.ai.payload_gen and injection consuming AI payloads (Day 15)."""

import asyncio
import types

import respx
from httpx import Response

from doppel.ai.client import OllamaClient
from doppel.ai.payload_gen import PayloadGenerator
from doppel.core.http_engine import HttpEngine
from doppel.core.models import Endpoint, Parameter
from doppel.scanners.base import ScanContext
from doppel.scanners.injection import InjectionScanner

BASE = "http://localhost:5000"

PAYLOAD_JSON = (
    '{"candidates": ['
    '{"value": "a\'--@x.com", "attack_type": "sqli", "rationale": "quote in localpart"},'
    '{"value": "a\'--@x.com", "attack_type": "sqli", "rationale": "dup"},'
    '{"value": "<svg>@x.com", "attack_type": "xss", "rationale": "tag in localpart"}'
    ']}'
)


class FakeOllama:
    def __init__(self, content):
        self.content = content
        self.calls = 0

    async def chat(self, **kwargs):
        self.calls += 1
        return types.SimpleNamespace(message=types.SimpleNamespace(content=self.content))


def _generator(tmp_path):
    client = OllamaClient(model="qwen3:8b", seed=42, log_dir=str(tmp_path), client=FakeOllama(PAYLOAD_JSON))
    return PayloadGenerator(client, temperature=0.8)


def test_for_parameter_buckets_and_dedupes(tmp_path):
    gen = _generator(tmp_path)
    result = asyncio.run(
        gen.for_parameter(name="user_email", type_="string", format_="email", path="/x", method="PUT")
    )
    assert result["sqli"] == ["a'--@x.com"]  # deduped
    assert result["xss"] == ["<svg>@x.com"]


def test_for_parameter_caches_by_shape(tmp_path):
    gen = _generator(tmp_path)
    asyncio.run(gen.for_parameter(name="q", type_="string"))
    asyncio.run(gen.for_parameter(name="q", type_="string"))
    assert gen._client._client.calls == 1  # second call served from cache


def test_generator_is_graceful_on_error(tmp_path):
    class Boom:
        async def chat(self, **kwargs):
            raise RuntimeError("ollama down")

    client = OllamaClient(model="m", seed=1, log_dir=str(tmp_path), client=Boom())
    gen = PayloadGenerator(client)
    result = asyncio.run(gen.for_parameter(name="q", type_="string"))
    assert result == {"sqli": [], "xss": []}  # no raise, empty buckets


class _FakeGenerator:
    """Minimal duck-typed generator for the injection scanner."""

    def __init__(self, sqli, xss):
        self._sqli, self._xss = sqli, xss
        self.seen = []

    async def for_parameter(self, **kwargs):
        self.seen.append(kwargs)
        return {"sqli": self._sqli, "xss": self._xss}


@respx.mock
def test_injection_uses_ai_payloads():
    from urllib.parse import unquote

    def handler(request):
        if "PWNED" in unquote(request.url.params.get("q", "")):
            return Response(500, text="sqlite3.OperationalError: boom", headers={"content-type": "text/html"})
        return Response(200, json={})

    respx.get(f"{BASE}/search").mock(side_effect=handler)
    endpoint = Endpoint(
        path="/search", method="GET",
        parameters=[Parameter(name="q", location="query", type_="string", required=True)],
        request_body_schema=None, security=[],
    )
    fake_gen = _FakeGenerator(sqli=["PWNED' OR 1=1--"], xss=[])

    async def go():
        async with HttpEngine(rate_limit_per_s=0) as engine:
            ctx = ScanContext(
                engine=engine, base_url=BASE, payload_mode="ai", payload_generator=fake_gen
            )
            scanner = InjectionScanner(ctx, sqli_payloads=["static-never-used"], xss_payloads=[])
            return await scanner.run(endpoint)

    findings = asyncio.run(go())
    assert len(findings) == 1
    assert "SQL injection" in findings[0].title
    # the AI generator was consulted for the parameter
    assert fake_gen.seen and fake_gen.seen[0]["name"] == "q"
