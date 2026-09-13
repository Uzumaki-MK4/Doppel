"""Tests for apiguard.ai.oracle — the BOLA gate + response oracle (Day 21)."""

import asyncio
import types

from apiguard.ai.client import OllamaClient
from apiguard.ai.oracle import BolaOracle, gate
from apiguard.core.models import Endpoint, Evidence
from apiguard.engines.bola import AccessTriple

A_BODY = '{"book_title": "bookA", "owner": "apiguard_a", "secret": "apiguard-userA-secret"}'
B_OWN_BODY = '{"book_title": "bookB", "owner": "apiguard_b", "secret": "apiguard-userB-secret"}'


def _ev(status: int, body: str) -> Evidence:
    return Evidence(
        request_method="GET",
        request_url="http://localhost:5000/books/v1/bookA",
        response_status=status,
        response_body=body,
        curl_repro="curl ...",
    )


def _ep() -> Endpoint:
    return Endpoint(path="/books/v1/{book_title}", method="GET", parameters=[], request_body_schema=None, security=["bearerAuth"])


def _triple(*, cross_status=200, cross_body=A_BODY, control_body=B_OWN_BODY, a_id="bookA") -> AccessTriple:
    return AccessTriple(
        object_endpoint=_ep(),
        a_object_id=a_id,
        a_access=_ev(200, A_BODY),
        b_cross_access=_ev(cross_status, cross_body),
        b_control=_ev(200, control_body) if control_body is not None else None,
    )


class FakeOllama:
    def __init__(self, content):
        self.content = content
        self.calls = 0

    async def chat(self, **kwargs):
        self.calls += 1
        return types.SimpleNamespace(message=types.SimpleNamespace(content=self.content))


def _oracle(content, tmp_path):
    client = OllamaClient(model="m", seed=42, log_dir=str(tmp_path), client=FakeOllama(content))
    return BolaOracle(client), client._client


# --- gate ---------------------------------------------------------------- #
def test_gate_clears_rejected():
    assert gate(_triple(cross_status=403))[0] == "not_leak"
    assert gate(_triple(cross_status=404))[0] == "not_leak"


def test_gate_clears_identical_to_control():
    assert gate(_triple(cross_body=B_OWN_BODY, control_body=B_OWN_BODY))[0] == "not_leak"


def test_gate_escalates_when_id_absent_but_status_ok():
    # D21 review: id-absent is NO LONGER a hard clear (would drop URL-only-id leaks).
    # It escalates to the oracle; id-presence is a confidence signal instead.
    assert gate(_triple(cross_body='{"owner": "apiguard_a", "secret": "x"}', a_id="bookA"))[0] == "ambiguous"


def test_gate_ambiguous_when_id_present_and_bodies_differ():
    assert gate(_triple(cross_body=A_BODY, control_body=B_OWN_BODY, a_id="bookA"))[0] == "ambiguous"


# --- oracle -------------------------------------------------------------- #
def test_oracle_flags_a_leak(tmp_path):
    oracle, fake = _oracle('{"is_leak": true, "leaked_fields": ["secret"], "reasoning": "B got A secret"}', tmp_path)
    d = asyncio.run(oracle.adjudicate(_triple(cross_body=A_BODY, a_id="bookA")))
    assert d.is_leak is True
    assert d.called_llm is True
    assert d.oracle_verdict == 1.0
    assert d.leaked_fields == ["secret"]
    assert d.trace is not None


def test_oracle_clears_a_legitimate_access(tmp_path):
    # Ambiguous by the gate (id present), but the oracle judges B's data is B's own.
    body = A_BODY.replace("bookA", "bookX")  # contains a_id token? ensure gate ambiguous
    oracle, fake = _oracle('{"is_leak": false, "leaked_fields": [], "reasoning": "B own data"}', tmp_path)
    d = asyncio.run(oracle.adjudicate(_triple(cross_body=A_BODY, a_id="bookA")))
    assert d.is_leak is False
    assert d.called_llm is True
    assert d.oracle_verdict == 0.0


def test_gate_decision_does_not_call_llm(tmp_path):
    oracle, fake = _oracle('{"is_leak": true, "leaked_fields": [], "reasoning": "x"}', tmp_path)
    d = asyncio.run(oracle.adjudicate(_triple(cross_status=403)))  # gate clears
    assert d.is_leak is False
    assert d.called_llm is False
    assert fake.calls == 0  # oracle never invoked


def test_oracle_inconclusive_is_not_a_leak(tmp_path):
    oracle, _ = _oracle("not valid json", tmp_path)  # never validates -> inconclusive
    d = asyncio.run(oracle.adjudicate(_triple(cross_body=A_BODY, a_id="bookA")))
    assert d.is_leak is False
    assert d.decided_by == "oracle:inconclusive"
    assert d.oracle_verdict is None
