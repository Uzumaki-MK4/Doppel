"""Rate-limit scanner (BRAIN.md D10).

Bursts N requests at one simple, no-parameter GET endpoint and flags the absence
of rate limiting if none of them returns HTTP 429. Runs once per scan.

Caveat: requests go through the shared engine, whose own client-side rate limiter
paces them; a very low configured `rate_limit_per_s` could mask a server limit.
The burst still sends N requests, which is enough to detect a server that never
limits (as VAmPI does not).
"""

from __future__ import annotations

import asyncio
import re

from doppel.core.http_engine import build_request
from doppel.core.models import Endpoint, Finding, Severity
from doppel.scanners.base import Scanner


def _slug(*parts: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", "-".join(parts).lower()).strip("-")


class RateLimitScanner(Scanner):
    name = "rate_limit"
    owasp_id = "API4:2023"  # Unrestricted Resource Consumption
    burst = 20

    def __init__(self, context, *, burst: int | None = None) -> None:
        super().__init__(context)
        self._burst = burst if burst is not None else self.burst
        self._ran = False

    def _headers_for(self, endpoint: Endpoint) -> dict[str, str]:
        if endpoint.security and self.context.sessions:
            primary = self.context.sessions.get("userA") or next(
                iter(self.context.sessions.values()), None
            )
            if primary is not None:
                return dict(primary.headers)
        return {}

    async def run(self, endpoint: Endpoint) -> list[Finding]:
        # Burst a single simple, no-parameter GET to keep it cheap and safe.
        if self._ran or endpoint.method.upper() != "GET" or endpoint.parameters:
            return []
        self._ran = True

        headers = self._headers_for(endpoint)

        async def one():
            method, url, req_headers, query, body = build_request(
                endpoint, self.base_url, headers=headers
            )
            return await self.engine.send(method, url, headers=req_headers, params=query, body=body)

        results = await asyncio.gather(*[one() for _ in range(self._burst)])
        statuses = [r.status for r in results]
        if 429 in statuses:
            return []

        return [
            Finding(
                id=_slug("rate-limit", endpoint.method, endpoint.path),
                title=f"No rate limiting on {endpoint.method} {endpoint.path}",
                scanner=self.name,
                endpoint=endpoint,
                severity=Severity.LOW,
                owasp_id=self.owasp_id,
                confidence=0.7,
                description=(
                    f"Sent {self._burst} rapid requests to {endpoint.method} {endpoint.path}; "
                    f"none returned HTTP 429, so no rate limiting is enforced."
                ),
                remediation="Enforce per-client rate limits and return 429 when exceeded.",
                evidence=results[0].evidence,
            )
        ]
