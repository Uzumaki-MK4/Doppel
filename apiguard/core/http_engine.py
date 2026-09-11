"""Async HTTP engine (BRAIN.md D4).

One shared `httpx.AsyncClient` for the whole scan (invariant 8), gated by a
concurrency semaphore and an async rate limiter, both from config. `send()`
retries transport/timeout errors only (an HTTP status is a real answer, never a
retryable failure) and returns an `HttpExchange` that bundles the raw response
with a fully-built `Evidence` record, including a copy-pasteable curl string
(invariant 6).

Cassette record/replay is added on D12; auth/session management is D5. Until
then, authenticated endpoints simply return 401 — still a status.
"""

from __future__ import annotations

import asyncio
import json
import shlex
import time
from dataclasses import dataclass
from typing import Any

import httpx

from apiguard.core.models import Endpoint, Evidence, Parameter


# --------------------------------------------------------------------------- #
# Rate limiting
# --------------------------------------------------------------------------- #
class _RateLimiter:
    """Spaces request *starts* to at most `per_second`. <= 0 disables it."""

    def __init__(self, per_second: float) -> None:
        self._min_interval = 1.0 / per_second if per_second > 0 else 0.0
        self._lock = asyncio.Lock()
        self._next = 0.0

    async def wait(self) -> None:
        if self._min_interval <= 0:
            return
        async with self._lock:
            now = time.monotonic()
            if self._next > now:
                await asyncio.sleep(self._next - now)
            self._next = max(time.monotonic(), self._next) + self._min_interval


# --------------------------------------------------------------------------- #
# Request building (pure) and evidence
# --------------------------------------------------------------------------- #
def _placeholder(param: Parameter) -> str:
    if param.example is not None:
        return str(param.example)
    return {"integer": "1", "number": "1", "boolean": "true"}.get(
        (param.type_ or "string").lower(), "test"
    )


def _example_from_schema(schema: Any) -> Any:
    """Best-effort example value for a JSON schema (for baseline probing)."""
    if not isinstance(schema, dict):
        return "test"
    if "example" in schema:
        return schema["example"]
    type_ = schema.get("type")
    if type_ == "object" or "properties" in schema:
        return {k: _example_from_schema(v) for k, v in (schema.get("properties") or {}).items()}
    if type_ == "array":
        return [_example_from_schema(schema.get("items") or {})]
    if type_ in ("integer", "number"):
        return 1
    if type_ == "boolean":
        return True
    return "test"


def build_request(
    endpoint: Endpoint,
    base_url: str,
    values: dict[str, Any] | None = None,
    headers: dict[str, str] | None = None,
) -> tuple[str, str, dict[str, str], dict[str, str], str | None]:
    """Turn an Endpoint into (method, url, headers, query, body_text)."""
    values = dict(values or {})
    headers = dict(headers or {})
    path = endpoint.path
    query: dict[str, str] = {}

    for param in endpoint.parameters:
        supplied = param.name in values
        if param.location == "path":
            value = values.get(param.name, _placeholder(param))
            path = path.replace("{" + param.name + "}", str(value))
        elif param.location == "query" and (param.required or supplied):
            query[param.name] = str(values.get(param.name, _placeholder(param)))
        elif param.location == "header" and (param.required or supplied):
            headers.setdefault(param.name, str(values.get(param.name, _placeholder(param))))

    url = base_url.rstrip("/") + path
    body_text: str | None = None
    if endpoint.request_body_schema is not None:
        body_text = json.dumps(_example_from_schema(endpoint.request_body_schema))
        headers.setdefault("Content-Type", "application/json")

    return endpoint.method.upper(), url, headers, query, body_text


def build_curl(method: str, url: str, headers: dict[str, str], body: str | None = None) -> str:
    """A copy-pasteable curl command reproducing the request (invariant 6)."""
    parts = ["curl", "-X", method.upper(), shlex.quote(url)]
    for key, value in headers.items():
        parts.extend(["-H", shlex.quote(f"{key}: {value}")])
    if body:
        parts.extend(["--data", shlex.quote(body)])
    return " ".join(parts)


def _build_evidence(
    method: str, url: str, req_headers: dict[str, str], body: str | None, resp: httpx.Response
) -> Evidence:
    return Evidence(
        request_method=method.upper(),
        request_url=url,
        request_headers=dict(req_headers),
        request_body=body,
        response_status=resp.status_code,
        response_headers=dict(resp.headers),
        response_body=resp.text,
        curl_repro=build_curl(method, url, req_headers, body),
    )


@dataclass
class HttpExchange:
    """A completed request/response pair plus its evidence."""

    response: httpx.Response
    evidence: Evidence

    @property
    def status(self) -> int:
        return self.response.status_code


# --------------------------------------------------------------------------- #
# The engine
# --------------------------------------------------------------------------- #
class HttpEngine:
    """Shared async HTTP client with rate limiting, concurrency cap, retries."""

    def __init__(
        self,
        *,
        max_concurrency: int = 10,
        rate_limit_per_s: float = 20.0,
        timeout_s: float = 15.0,
        retries: int = 2,
        default_headers: dict[str, str] | None = None,
        follow_redirects: bool = False,
    ) -> None:
        self._client = httpx.AsyncClient(timeout=timeout_s, follow_redirects=follow_redirects)
        self._sem = asyncio.Semaphore(max_concurrency)
        self._rl = _RateLimiter(rate_limit_per_s)
        self._retries = retries
        self._default_headers = dict(default_headers or {})
        self.requests_sent = 0

    async def __aenter__(self) -> HttpEngine:
        return self

    async def __aexit__(self, *_exc: object) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        await self._client.aclose()

    async def send(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        params: dict[str, str] | None = None,
        body: str | None = None,
    ) -> HttpExchange:
        """Send one request with rate limiting, concurrency cap, and retries."""
        req_headers = {**self._default_headers, **(headers or {})}
        content = body.encode() if body is not None else None
        last_exc: Exception | None = None

        for attempt in range(self._retries + 1):
            async with self._sem:
                await self._rl.wait()
                self.requests_sent += 1
                try:
                    resp = await self._client.request(
                        method.upper(), url, headers=req_headers, params=params or None, content=content
                    )
                except (httpx.TransportError, httpx.TimeoutException) as exc:
                    last_exc = exc
                else:
                    return HttpExchange(
                        response=resp,
                        evidence=_build_evidence(
                            method, str(resp.request.url), req_headers, body, resp
                        ),
                    )
            await asyncio.sleep(0.25 * (2**attempt))  # backoff between retries

        assert last_exc is not None
        raise last_exc

    async def probe(
        self,
        endpoint: Endpoint,
        base_url: str,
        *,
        values: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
    ) -> HttpExchange:
        """Send a baseline request built from an Endpoint (path params filled)."""
        method, url, req_headers, query, body_text = build_request(
            endpoint, base_url, values, headers
        )
        return await self.send(method, url, headers=req_headers, params=query, body=body_text)
