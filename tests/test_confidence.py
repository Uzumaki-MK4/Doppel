"""Tests for apiguard.scoring.confidence and the BOLA finding producer (Day 22)."""

import asyncio
import json
import types

import respx
from httpx import Response

from apiguard.ai.client import OllamaClient
from apiguard.ai.oracle import BolaOracle
from apiguard.core.http_engine import HttpEngine
from apiguard.core.identity import Session
from apiguard.core.models import Endpoint, Evidence, Parameter
from apiguard.engines.bola import AccessTriple
from apiguard.runner import find_bola_findings
from apiguard.scoring.confidence import compute_signals, confidence
from apiguard.settings import Settings

BASE = "http://localhost:5000"
A_BODY = '{"book_title": "bookA", "owner": "apiguard_a", "secret": "apiguard-userA-secret"}'
B_OWN = '{"book_title": "bookB", "owner": "apiguard_b", "secret": "apiguard-userB-secret"}'


def _ev(status, body):
    return Evidence(request_method="GET", request_url="http://x/1", response_status=status,
                    response_body=body, curl_repro="curl http://x/1")


def _ep():
    return Endpoint(path="/books/v1/{book_title}", method="GET", parameters=[], request_body_schema=None, security=["bearerAuth"])


def _triple():
    return AccessTriple(
        object_endpoint=_ep(), a_object_id="bookA",
        a_access=_ev(200, A_BODY), b_cross_access=_ev(200, A_BODY), b_control=_ev(200, B_OWN),
    )


def test_compute_signals_full():
    s = compute_signals(_triple(), oracle_verdict=1.0)
    assert s["id_echo"] == 1.0                    # bookA in cross body
    assert s["field_overlap"] == 1.0              # same top-level keys
    assert s["status_match"] == 1.0               # both 200
    assert 0.0 < s["body_divergence"] <= 1.0      # cross (A's) differs from B's control
    assert s["oracle_verdict"] == 1.0
    assert len(s) == 5


def test_compute_signals_without_control_or_oracle():
    t = _triple()
    t.b_control = None
    s = compute_signals(t, oracle_verdict=None)
    assert set(s) == {"id_echo", "field_overlap", "status_match"}  # 3 signals still measurable
    assert len(s) >= 3


def test_confidence_normalises_over_present_signals():
    weights = {"id_echo": 0.30, "field_overlap": 0.20, "body_divergence": 0.20, "status_match": 0.10, "oracle_verdict": 0.20}
    # all signals 1.0 -> confidence 1.0
    assert confidence({k: 1.0 for k in weights}, weights) == 1.0
    # only two signals present -> normalised, not deflated
    assert confidence({"id_echo": 1.0, "status_match": 1.0}, weights) == 1.0
    assert confidence({"id_echo": 0.0, "status_match": 1.0}, weights) == round(0.10 / 0.40, 4)


class FakeOllama:
    def __init__(self, content):
        self.content = content

    async def chat(self, **kwargs):
        return types.SimpleNamespace(message=types.SimpleNamespace(content=self.content))


@respx.mock
def test_find_bola_findings_builds_scored_finding(tmp_path):
    owners = {"apiguard_userA_book_title": "apiguard_a", "apiguard_userB_book_title": "apiguard_b"}

    def post_books(request):
        body = json.loads(request.content.decode())
        who = "apiguard_a" if request.headers.get("authorization") == "Bearer A" else "apiguard_b"
        owners[body["book_title"]] = who
        return Response(200, json={"status": "success"})

    def list_books(request):
        return Response(200, json={"Books": [{"book_title": t, "user": u} for t, u in owners.items()]})

    def get_book(request):
        title = request.url.path.rsplit("/", 1)[-1]
        return Response(200, json={"book_title": title, "owner": owners.get(title, "?"), "secret": f"s-{title}"})

    respx.post(f"{BASE}/books/v1").mock(side_effect=post_books)
    respx.get(f"{BASE}/books/v1").mock(side_effect=list_books)
    respx.get(url__regex=rf"{BASE}/books/v1/.+").mock(side_effect=get_book)

    endpoints = [
        Endpoint(path="/books/v1", method="GET", parameters=[], request_body_schema=None, security=["bearerAuth"]),
        Endpoint(path="/books/v1", method="POST", parameters=[],
                 request_body_schema={"type": "object", "properties": {"book_title": {"type": "string"}, "secret": {"type": "string"}}},
                 security=["bearerAuth"]),
        Endpoint(path="/books/v1/{book_title}", method="GET",
                 parameters=[Parameter(name="book_title", location="path", type_="string", required=True)],
                 request_body_schema=None, security=["bearerAuth"]),
    ]
    sessions = {
        "userA": Session(username="apiguard_a", token="A", headers={"Authorization": "Bearer A"}),
        "userB": Session(username="apiguard_b", token="B", headers={"Authorization": "Bearer B"}),
    }
    oracle = BolaOracle(OllamaClient(model="m", seed=42, log_dir=str(tmp_path),
                                     client=FakeOllama('{"is_leak": true, "leaked_fields": ["secret"], "reasoning": "B got A data"}')))
    weights = Settings().confidence_weights.model_dump()

    async def go():
        async with HttpEngine(rate_limit_per_s=0) as engine:
            return await find_bola_findings(engine, BASE, sessions, endpoints, oracle, weights)

    findings = asyncio.run(go())
    assert len(findings) == 1
    f = findings[0]
    assert f.scanner == "bola"
    assert f.owasp_id == "API1:2023"
    assert f.severity.value == "high"          # authed endpoint
    assert 0.0 < f.confidence <= 1.0
    assert f.ai_trace is not None
    assert len(f.ai_trace.signals) >= 4        # >= 4 measurable signals (done-condition)
    assert f.evidence.curl_repro               # every finding carries evidence
