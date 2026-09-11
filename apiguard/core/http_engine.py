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
from dataclasses import dataclass, field
from pathlib import Path
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
# Cassettes: record/replay HTTP for offline demos + fast tests (upgrade 4)
# --------------------------------------------------------------------------- #
class CassetteMiss(RuntimeError):
    """Raised in replay mode when a request has no recorded interaction."""


# Headers that change the response and so must be part of the cassette key
# (the JWT scanner varies only Authorization; the CORS check varies only Origin).
_SIGNIFICANT_HEADERS = ("authorization", "origin", "content-type")


def _cassette_key(request: httpx.Request, body: str | None) -> str:
    sig = ";".join(f"{h}={request.headers.get(h, '')}" for h in _SIGNIFICANT_HEADERS)
    return f"{request.method} {request.url} {body or ''} {sig}"


# Stripped on replay: we store the DECODED body (resp.text), so a stale
# Content-Encoding/Length would make httpx re-decode and crash or mislead.
_ENCODING_HEADERS = frozenset({"content-encoding", "content-length", "transfer-encoding"})


def _response_from_stored(request: httpx.Request, stored: dict) -> httpx.Response:
    headers = {
        k: v for k, v in (stored.get("headers") or {}).items() if k.lower() not in _ENCODING_HEADERS
    }
    return httpx.Response(
        status_code=stored["status"],
        headers=headers,
        content=(stored.get("body") or "").encode("utf-8"),
        request=request,
    )


@dataclass
class Cassette:
    """A recorded set of HTTP interactions, keyed by method+url+body+significant headers.

    mode="record": every send() is appended, then persisted with save().
    mode="replay": send() returns the stored response and never hits the network
    (a miss raises CassetteMiss, so replay cannot silently fall back to live).

    Each key maps to an ORDERED list of responses, so repeated identical requests
    (e.g. the rate-limit burst) replay faithfully; once a key's list is exhausted
    the last response repeats.

    Limitations (honest): only status/headers/body are captured, not timing — so
    time-based detectors (e.g. time-based SQLi) are live-only and will not fire on
    replay. Non-UTF-8 response bodies may not round-trip exactly.
    """

    mode: str | None = None  # "record" | "replay" | None
    meta: dict = field(default_factory=dict)
    _store: dict[str, list[dict]] = field(default_factory=dict)
    _cursor: dict[str, int] = field(default_factory=dict)
    _interactions: list[dict] = field(default_factory=list)

    def lookup(self, key: str) -> dict:
        responses = self._store.get(key)
        if not responses:
            raise CassetteMiss(f"No recorded interaction for: {key}")
        index = self._cursor.get(key, 0)
        self._cursor[key] = index + 1
        return responses[min(index, len(responses) - 1)]

    def record(self, key: str, request: dict, response: dict) -> None:
        self._store.setdefault(key, []).append(response)
        self._interactions.append({"key": key, "request": request, "response": response})

    def save(self, directory: str, meta: dict | None = None) -> None:
        path = Path(directory)
        path.mkdir(parents=True, exist_ok=True)
        payload = {"meta": meta or self.meta, "interactions": self._interactions}
        (path / "cassette.json").write_text(
            json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8"
        )

    @classmethod
    def load(cls, directory: str) -> Cassette:
        data = json.loads((Path(directory) / "cassette.json").read_text(encoding="utf-8"))
        cassette = cls(mode="replay", meta=data.get("meta", {}))
        for interaction in data.get("interactions", []):
            cassette._store.setdefault(interaction["key"], []).append(interaction["response"])
        return cassette

    @staticmethod
    def read_meta(directory: str) -> dict:
        data = json.loads((Path(directory) / "cassette.json").read_text(encoding="utf-8"))
        return data.get("meta", {})


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
        cassette: Cassette | None = None,
    ) -> None:
        self._client = httpx.AsyncClient(timeout=timeout_s, follow_redirects=follow_redirects)
        self._sem = asyncio.Semaphore(max_concurrency)
        self._rl = _RateLimiter(rate_limit_per_s)
        self._retries = retries
        self._default_headers = dict(default_headers or {})
        self._cassette = cassette
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
        json_body: Any | None = None,
    ) -> HttpExchange:
        """Send one request with rate limiting, concurrency cap, and retries.

        Pass `json_body` (a JSON-able value) to serialize it and set
        `Content-Type: application/json` automatically; or `body` for a raw
        string body. Not both.
        """
        req_headers = {**self._default_headers, **(headers or {})}
        if json_body is not None:
            if body is not None:
                raise ValueError("Pass either body or json_body, not both.")
            body = json.dumps(json_body)
            req_headers.setdefault("Content-Type", "application/json")
        content = body.encode() if body is not None else None

        def _build():
            return self._client.build_request(
                method.upper(), url, headers=req_headers, params=params or None, content=content
            )

        # Replay: return the recorded response, no network (a miss raises).
        if self._cassette is not None and self._cassette.mode == "replay":
            request = _build()
            stored = self._cassette.lookup(_cassette_key(request, body))
            resp = _response_from_stored(request, stored)
            self.requests_sent += 1
            return HttpExchange(
                response=resp,
                evidence=_build_evidence(method, str(request.url), req_headers, body, resp),
            )

        key = _cassette_key(_build(), body)
        last_exc: Exception | None = None

        for attempt in range(self._retries + 1):
            async with self._sem:
                await self._rl.wait()
                self.requests_sent += 1
                try:
                    resp = await self._client.send(_build())
                except (httpx.TransportError, httpx.TimeoutException) as exc:
                    last_exc = exc
                else:
                    if self._cassette is not None and self._cassette.mode == "record":
                        self._cassette.record(
                            key,
                            {"method": method.upper(), "url": str(resp.request.url), "body": body},
                            {
                                "status": resp.status_code,
                                "headers": dict(resp.headers),
                                "body": resp.text,
                            },
                        )
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
