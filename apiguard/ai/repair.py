"""Self-repair loop (BRAIN.md D16).

When a request is rejected by input validation (HTTP 400/422), feed the error
body back to the model, get a corrected value, and retry — capped at
`max_retries`. The actual sending is a caller-supplied `send` callback, so the
same loop serves the injection scanner (re-probe a parameter) and a body repair.

Never raises: an LLM error just ends the loop with `repaired=False`.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable

from apiguard.ai.client import OllamaClient
from apiguard.ai.prompts import REPAIR_SYSTEM, RepairedPayload, repair_user_prompt

# A send callback: given a corrected value, performs the request and returns an
# object exposing `.status` and `.evidence.response_body` (an HttpExchange).
SendFn = Callable[[str], Awaitable[Any]]

_REJECTED = (400, 422)


@dataclass
class RepairResult:
    repaired: bool
    attempts: int
    final_value: str | None
    final_status: int
    final_exchange: Any | None = None
    history: list[dict] = field(default_factory=list)


class RepairLoop:
    def __init__(self, client: OllamaClient, *, max_retries: int = 2, temperature: float = 0.8) -> None:
        self._client = client
        self._max_retries = max_retries
        self._temperature = temperature

    async def repair_value(
        self,
        *,
        send: SendFn,
        initial_value: str,
        context: str,
        error_body: str,
        attack_goal: str,
    ) -> RepairResult:
        """Loop: ask for a corrected value, re-send, until accepted or capped."""
        value = initial_value
        last_error = error_body
        history: list[dict] = []
        final_exchange = None

        for attempt in range(1, self._max_retries + 1):
            corrected = await self._suggest(value, context, last_error, attack_goal)
            if corrected is None:
                break
            exchange = await send(corrected)
            history.append({"value": corrected, "status": exchange.status})
            final_exchange = exchange
            value = corrected
            if exchange.status not in _REJECTED:
                return RepairResult(
                    repaired=True,
                    attempts=attempt,
                    final_value=corrected,
                    final_status=exchange.status,
                    final_exchange=exchange,
                    history=history,
                )
            last_error = exchange.evidence.response_body

        return RepairResult(
            repaired=False,
            attempts=len(history),
            final_value=value if history else None,
            final_status=final_exchange.status if final_exchange is not None else -1,
            final_exchange=final_exchange,
            history=history,
        )

    async def _suggest(self, value: str, context: str, error_body: str, attack_goal: str) -> str | None:
        result = await self._client.structured(
            RepairedPayload,
            system=REPAIR_SYSTEM,
            prompt=repair_user_prompt(
                rejected_value=value,
                error_body=error_body,
                context=context,
                attack_goal=attack_goal,
            ),
            temperature=self._temperature,
            label="repair",
        )
        if result.ok and result.value is not None:
            return result.value.value
        return None
