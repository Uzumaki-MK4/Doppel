"""AI payload generation, wired behind --payloads {static,ai,both} (BRAIN.md D15).

`PayloadGenerator.for_parameter()` asks the LLM (via `OllamaClient` + the versioned
payload prompt) for context-aware payloads, buckets them into sqli/xss, dedupes,
and caches by parameter shape so the same parameter is not regenerated. It never
raises — an Ollama error yields empty buckets so a scan degrades gracefully
(invariant 4).
"""

from __future__ import annotations

from typing import Any

from doppel.ai.client import OllamaClient
from doppel.ai.prompts import PAYLOAD_SYSTEM, PayloadSet, payload_user_prompt


class PayloadGenerator:
    """Generates context-tailored attack payloads for a parameter via the LLM."""

    def __init__(self, client: OllamaClient, *, temperature: float = 0.8, count: int = 8) -> None:
        self._client = client
        self._temperature = temperature
        self._count = count
        self._cache: dict[tuple, dict[str, list[str]]] = {}

    async def for_parameter(
        self,
        *,
        name: str,
        type_: str,
        format_: str | None = None,
        example: Any | None = None,
        path: str | None = None,
        method: str | None = None,
        schema: dict | None = None,
        attack_types: tuple[str, ...] = ("sqli", "xss"),
    ) -> dict[str, list[str]]:
        """Return {"sqli": [...], "xss": [...]} of AI-generated payloads for a parameter."""
        key = (name, type_, format_, attack_types)
        if key in self._cache:
            return self._cache[key]

        buckets: dict[str, list[str]] = {"sqli": [], "xss": []}
        try:
            result = await self._client.structured(
                PayloadSet,
                system=PAYLOAD_SYSTEM,
                prompt=payload_user_prompt(
                    name=name,
                    type_=type_,
                    format_=format_,
                    example=example,
                    path=path,
                    method=method,
                    schema=schema,
                    count=self._count,
                    attack_types=attack_types,
                ),
                temperature=self._temperature,
                label=f"payload-{name}",
            )
        except Exception:
            result = None

        if result is not None and result.ok and result.value is not None:
            for candidate in result.value.candidates:
                bucket = "xss" if candidate.attack_type == "xss" else "sqli"
                if candidate.value and candidate.value not in buckets[bucket]:
                    buckets[bucket].append(candidate.value)

        self._cache[key] = buckets
        return buckets
