"""Ollama client with schema-enforced structured output (BRAIN.md D13).

Every call uses Ollama's ``format`` = a Pydantic JSON schema and validates the
reply with ``model_validate_json()`` — never regex (invariant 2). The seed is
pinned from config (invariant 3) and qwen3 "thinking" is disabled. On a
validation failure the call retries up to ``max_retries`` times, bumping the seed
each attempt so retries differ yet stay reproducible; if all attempts fail it
returns an *inconclusive* result rather than raising. Every call is logged to
``logs/llm/`` as JSON (explainability, upgrade 6).

The underlying client is injectable (`client=`) so tests need no live Ollama.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import ollama
from pydantic import BaseModel, ValidationError


@dataclass
class StructuredResult:
    """Outcome of one structured LLM call."""

    ok: bool
    value: BaseModel | None
    model: str
    seed: int
    temperature: float
    prompt: str
    raw_response: str
    attempts: int
    error: str | None = None

    @property
    def inconclusive(self) -> bool:
        return not self.ok


def _content_of(response: Any) -> str:
    message = getattr(response, "message", None)
    if message is not None:
        return getattr(message, "content", "") or ""
    try:
        return response["message"]["content"] or ""
    except Exception:
        return ""


def _render(messages: list[dict]) -> str:
    return "\n".join(f"[{m.get('role')}] {m.get('content')}" for m in messages)


class OllamaClient:
    """Schema-constrained, seed-pinned, logged Ollama wrapper."""

    def __init__(
        self,
        *,
        model: str,
        host: str = "http://127.0.0.1:11434",
        seed: int = 42,
        max_retries: int = 2,
        timeout_s: float = 120.0,
        log_dir: str = "logs/llm",
        client: Any | None = None,
    ) -> None:
        self._model = model
        self._seed = seed
        self._max_retries = max_retries
        self._log_dir = Path(log_dir)
        self._client = client if client is not None else ollama.AsyncClient(host=host, timeout=timeout_s)
        self._counter = 0

    @classmethod
    def from_settings(cls, settings, **overrides) -> OllamaClient:
        return cls(
            model=settings.model,
            host=settings.ollama_host,
            seed=settings.seed,
            **overrides,
        )

    async def available(self) -> bool:
        """True if the Ollama server is reachable (for the invariant-4 degrade check)."""
        try:
            await self._client.list()
            return True
        except Exception:
            return False

    async def structured(
        self,
        response_model: type[BaseModel],
        *,
        prompt: str | None = None,
        messages: list[dict] | None = None,
        system: str | None = None,
        temperature: float = 0.0,
        label: str = "call",
    ) -> StructuredResult:
        """Return a validated `response_model`, retrying on invalid output."""
        msgs = self._build_messages(prompt, messages, system)
        schema = response_model.model_json_schema()
        raw = ""
        error: str | None = None
        attempts = 0

        for attempt in range(self._max_retries + 1):
            attempts = attempt + 1
            seed = self._seed + attempt  # bump so retries differ yet stay reproducible
            response = await self._client.chat(
                model=self._model,
                messages=msgs,
                format=schema,
                think=False,
                options={"temperature": temperature, "seed": seed},
            )
            raw = _content_of(response)
            try:
                value = response_model.model_validate_json(raw)
            except ValidationError as exc:
                error = str(exc)
                continue
            result = StructuredResult(
                ok=True,
                value=value,
                model=self._model,
                seed=seed,
                temperature=temperature,
                prompt=_render(msgs),
                raw_response=raw,
                attempts=attempts,
            )
            self._log(label, result)
            return result

        result = StructuredResult(
            ok=False,
            value=None,
            model=self._model,
            seed=self._seed,
            temperature=temperature,
            prompt=_render(msgs),
            raw_response=raw,
            attempts=attempts,
            error=error,
        )
        self._log(label, result)
        return result

    @staticmethod
    def _build_messages(prompt, messages, system) -> list[dict]:
        if messages is not None:
            return list(messages)
        built: list[dict] = []
        if system:
            built.append({"role": "system", "content": system})
        built.append({"role": "user", "content": prompt or ""})
        return built

    def _log(self, label: str, result: StructuredResult) -> None:
        try:
            self._log_dir.mkdir(parents=True, exist_ok=True)
            self._counter += 1
            path = self._log_dir / f"{self._counter:04d}-{label}.json"
            path.write_text(
                json.dumps(
                    {
                        "ts": datetime.now(timezone.utc).isoformat(),
                        "label": label,
                        "model": result.model,
                        "seed": result.seed,
                        "temperature": result.temperature,
                        "ok": result.ok,
                        "attempts": result.attempts,
                        "prompt": result.prompt,
                        "raw_response": result.raw_response,
                        "error": result.error,
                    },
                    indent=2,
                    ensure_ascii=False,
                ),
                encoding="utf-8",
            )
        except Exception:
            pass  # logging must never break a scan
