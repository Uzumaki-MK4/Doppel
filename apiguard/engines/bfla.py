"""BFLA engine — Broken Function Level Authorization (BRAIN.md D23, API5:2023).

Finds privileged/admin/debug endpoints (by path) and checks whether the
LOW-PRIVILEGE user (B) can reach them. If a normal user gets a 2xx with data
from a privileged function, that is BFLA; CRITICAL if the response also leaks
credential-like fields (VAmPI's `/users/v1/_debug` dumps every user's password).

Deterministic (no oracle). Only GET endpoints are probed, so we never trigger a
privileged write. Reported separately from BOLA.
"""

from __future__ import annotations

import re

from apiguard.core.http_engine import HttpEngine, build_request
from apiguard.core.identity import Session
from apiguard.core.models import Endpoint, Finding, Severity

_PRIVILEGED_HINTS = (
    "admin", "_debug", "debug", "internal", "manage", "management",
    "root", "superuser", "sysadmin", "privileged",
)
_SENSITIVE_MARKERS = (
    "password", "passwd", "secret", "token", "api_key", "apikey",
    "private_key", "hash", "credential",
)


def _is_privileged(endpoint: Endpoint) -> bool:
    segments = endpoint.path.lower().strip("/").split("/")
    return any(any(hint in segment for hint in _PRIVILEGED_HINTS) for segment in segments)


def _slug(*parts: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", "-".join(parts).lower()).strip("-")


async def find_bfla_findings(
    engine: HttpEngine,
    base_url: str,
    sessions: dict[str, Session],
    endpoints: list[Endpoint],
    *,
    low_priv: str = "userB",
) -> list[Finding]:
    """Probe privileged endpoints as the low-privilege user; flag any that succeed."""
    session = sessions.get(low_priv) or next(iter(sessions.values()), None)
    headers = dict(session.headers) if session is not None else {}
    who = session.username if session is not None else "anonymous"
    base = base_url.rstrip("/")

    findings: list[Finding] = []
    for endpoint in endpoints:
        if endpoint.method.upper() != "GET" or not _is_privileged(endpoint):
            continue

        method, url, req_headers, query, body = build_request(endpoint, base, headers=headers)
        exchange = await engine.send(method, url, headers=req_headers, params=query, body=body)
        if exchange.status >= 400 or not exchange.evidence.response_body.strip():
            continue  # not accessible -> authorization is working -> no finding

        low = exchange.evidence.response_body.lower()
        leaked = [marker for marker in _SENSITIVE_MARKERS if marker in low]
        sensitive = bool(leaked)
        public = not endpoint.security

        findings.append(
            Finding(
                id=_slug("bfla", endpoint.method, endpoint.path),
                title=f"BFLA: low-privilege access to privileged function {endpoint.method} {endpoint.path}",
                scanner="bfla",
                endpoint=endpoint,
                severity=Severity.CRITICAL if sensitive else Severity.HIGH,
                owasp_id="API5:2023",
                confidence=0.95 if sensitive else 0.85,
                description=(
                    f"The low-privilege user {who!r}"
                    + (" (and even unauthenticated callers)" if public else "")
                    + f" can call the privileged endpoint {endpoint.method} {endpoint.path} and "
                    "receive data"
                    + (f", leaking sensitive fields: {leaked}." if sensitive else ".")
                ),
                remediation=(
                    "Enforce function-level authorization: restrict admin/debug/internal endpoints "
                    "to authorized roles; deny by default."
                ),
                evidence=exchange.evidence,
            )
        )
    return findings
