"""Tests for doppel.ai.repair — the self-repair loop (Day 16)."""

import asyncio
import types

import respx
from httpx import Response

from doppel.ai.client import OllamaClient
from doppel.ai.repair import RepairLoop
from doppel.core.http_engine import HttpEngine
from doppel.core.models import Endpoint, Parameter
from doppel.scanners.base import ScanContext
from doppel.scanners.injection import InjectionScanner

BASE = "http://localhost:5000"


class FakeOllama:
    """Returns queued JSON contents in order (repeats the last)."""

    def __init__(self, contents):
        self._contents = list(contents)

    async def chat(self, **kwargs):
        content = self._contents.pop(0) if len(self._contents) > 1 else self._contents[0]
        return types.SimpleNamespace(message=types.SimpleNamespace(content=content))


def _client(contents, tmp_path):
    return OllamaClient(model="m", seed=42, log_dir=str(tmp_path), client=FakeOllama(contents))


def _exchange(status):
    ev = types.SimpleNamespace(response_body=f"error-{status}")
    return types.SimpleNamespace(status=status, evidence=ev)


def test_repair_succeeds_on_retry(tmp_path):
    loop = RepairLoop(_client(['{"value": "fixed", "rationale": "added field"}'], tmp_path))
    sent = []

    async def send(value):
        sent.append(value)
        return _exchange(200)  # the corrected value is accepted

    result = asyncio.run(
        loop.repair_value(
            send=send,
            initial_value="bad",
            context="register body",
            error_body="'email' is a required property",
            attack_goal="register",
        )
    )
    assert result.repaired is True
    assert result.final_status == 200
    assert result.final_value == "fixed"
    assert sent == ["fixed"]


def test_repair_gives_up_after_cap(tmp_path):
    loop = RepairLoop(_client(['{"value": "still-bad", "rationale": "r"}'], tmp_path), max_retries=2)

    async def send(value):
        return _exchange(400)  # never accepted

    result = asyncio.run(
        loop.repair_value(
            send=send, initial_value="bad", context="c", error_body="e", attack_goal="g"
        )
    )
    assert result.repaired is False
    assert result.attempts == 2  # capped


@respx.mock
def test_injection_repairs_a_rejected_payload(tmp_path):
    """A payload that the server 400s gets repaired, then detection runs on the
    repaired (accepted) response."""
    from urllib.parse import unquote

    def handler(request):
        q = unquote(request.url.params.get("q", ""))
        if q == "BAD":
            return Response(400, json={"message": "'q' is not of type 'string'"})
        if q == "FIXED":
            # repaired value reaches the app and errors out -> SQLi signature
            return Response(500, text="sqlite3.OperationalError: boom", headers={"content-type": "text/html"})
        return Response(200, json={})  # baseline ("test" placeholder) is clean

    respx.get(f"{BASE}/search").mock(side_effect=handler)
    endpoint = Endpoint(
        path="/search", method="GET",
        parameters=[Parameter(name="q", location="query", type_="string", required=True)],
        request_body_schema=None, security=[],
    )
    repair = RepairLoop(
        OllamaClient(model="m", seed=1, log_dir=str(tmp_path), client=FakeOllama(['{"value": "FIXED", "rationale": "r"}']))
    )

    async def go():
        async with HttpEngine(rate_limit_per_s=0) as engine:
            ctx = ScanContext(engine=engine, base_url=BASE, repair_loop=repair)
            scanner = InjectionScanner(ctx, sqli_payloads=["BAD"], xss_payloads=[])
            return await scanner.run(endpoint)

    findings = asyncio.run(go())
    assert len(findings) == 1
    assert "SQL injection" in findings[0].title  # detection ran on the repaired response
