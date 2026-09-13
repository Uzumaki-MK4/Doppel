"""BOLA response oracle + ambiguity gate (BRAIN.md D21). Semantic heart.

The gate (Section 5) resolves cheap cases deterministically so the LLM is called
ONLY on genuinely ambiguous triples (invariant 4). When ambiguous, the oracle
adjudicates whether User B's cross-access leaked User A's data, via a strict,
schema-constrained yes/no at temperature 0.0 (invariants 2/3/5). An inconclusive
oracle result is treated, conservatively, as not-a-leak.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import httpx

from apiguard.ai.client import OllamaClient
from apiguard.ai.prompts import ORACLE_SYSTEM, OracleVerdict, oracle_user_prompt
from apiguard.engines.bola import AccessTriple

_REJECTED = (401, 403, 404)


def gate(triple: AccessTriple) -> tuple[str, str]:
    """Cheap deterministic checks. Returns ('not_leak'|'ambiguous', reason).

    Only the two SAFE clears remain: a rejected cross-access, or one byte-identical
    to B's own control. The Section-5 'id absent from body -> not_leak' clear was
    REMOVED (D21 review): many endpoints carry the id only in the URL, so it
    silently dropped real 200-OK leaks (crAPI). Id presence is instead a confidence
    signal (`id_echo`), never a hard veto.
    """
    cross = triple.b_cross_access
    if cross.response_status in _REJECTED:
        return ("not_leak", f"gate:rejected({cross.response_status})")
    if triple.b_control is not None and cross.response_body == triple.b_control.response_body:
        return ("not_leak", "gate:identical-to-control")
    return ("ambiguous", "gate:ambiguous")


@dataclass
class BolaDecision:
    triple: AccessTriple
    is_leak: bool
    leaked_fields: list[str]
    reasoning: str
    decided_by: str  # a gate reason, "oracle", or "oracle:inconclusive"
    called_llm: bool
    oracle_verdict: float | None  # 1.0/0.0 from the LLM; None if the gate decided
    trace: dict | None = field(default=None)  # model/seed/temperature/prompt/raw for AITrace


class BolaOracle:
    def __init__(self, client: OllamaClient, *, temperature: float = 0.0) -> None:
        self._client = client
        self._temperature = temperature

    async def adjudicate(self, triple: AccessTriple) -> BolaDecision:
        decision, reason = gate(triple)
        if decision == "not_leak":
            return BolaDecision(
                triple=triple,
                is_leak=False,
                leaked_fields=[],
                reasoning=reason,
                decided_by=reason,
                called_llm=False,
                oracle_verdict=None,
            )

        try:
            result = await self._client.structured(
                OracleVerdict,
                system=ORACLE_SYSTEM,
                prompt=oracle_user_prompt(
                    triple.a_access.response_body, triple.b_cross_access.response_body
                ),
                temperature=self._temperature,
                label="oracle",
            )
        except (ConnectionError, TimeoutError, OSError, httpx.HTTPError) as exc:
            # Ollama down/unreachable mid-scan: degrade, do not crash (invariant 4).
            # Narrow on purpose — a code defect (KeyError/AttributeError/...) must still
            # surface rather than be masked as 'unavailable' (D21 review).
            return BolaDecision(
                triple=triple,
                is_leak=False,
                leaked_fields=[],
                reasoning=f"oracle unavailable: {exc}",
                decided_by="oracle:unavailable",
                called_llm=True,
                oracle_verdict=None,
                trace=None,
            )
        trace = {
            "model": result.model,
            "seed": result.seed,
            "temperature": result.temperature,
            "prompt": result.prompt,
            "raw_response": result.raw_response,
        }
        if not result.ok or result.value is None:
            return BolaDecision(
                triple=triple,
                is_leak=False,
                leaked_fields=[],
                reasoning="oracle inconclusive after retries",
                decided_by="oracle:inconclusive",
                called_llm=True,
                oracle_verdict=None,
                trace=trace,
            )

        verdict = result.value
        return BolaDecision(
            triple=triple,
            is_leak=verdict.is_leak,
            leaked_fields=list(verdict.leaked_fields),
            reasoning=verdict.reasoning,
            decided_by="oracle",
            called_llm=True,
            oracle_verdict=1.0 if verdict.is_leak else 0.0,
            trace=trace,
        )
