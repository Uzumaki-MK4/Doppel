"""Misconfiguration scanner (BRAIN.md D10).

Checks a few things that are largely server-global (run once): missing security
headers, server/version disclosure, and permissive CORS. Verbose errors (stack
traces / debug pages) are checked per-endpoint on whatever responses appear.
"""

from __future__ import annotations

import re

from doppel.core.http_engine import build_request
from doppel.core.models import Endpoint, Finding, Severity
from doppel.scanners.base import Scanner

_SECURITY_HEADERS = (
    "x-content-type-options",
    "x-frame-options",
    "content-security-policy",
    "strict-transport-security",
    "referrer-policy",
)

# Strong stack-trace / debug-page signatures (checked only on 5xx to avoid FPs).
_STACKTRACE = (
    "traceback (most recent call last)",
    "sqlalchemy",
    "werkzeug",
    "<!doctype html>",
)

_VERSION_RE = re.compile(r"\d+\.\d+")


def _slug(*parts: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", "-".join(parts).lower()).strip("-")


class MisconfigScanner(Scanner):
    name = "misconfig"
    owasp_id = "API8:2023"  # Security Misconfiguration

    def __init__(self, context) -> None:
        super().__init__(context)
        self._checked_global = False

    async def _send(self, endpoint: Endpoint, extra_headers: dict | None = None):
        method, url, headers, query, body = build_request(
            endpoint, self.base_url, headers=extra_headers or {}
        )
        return await self.engine.send(method, url, headers=headers, params=query, body=body)

    async def run(self, endpoint: Endpoint) -> list[Finding]:
        findings: list[Finding] = []
        exchange = await self._send(endpoint)

        verbose = self._verbose_error(endpoint, exchange)
        if verbose is not None:
            findings.append(verbose)

        if not self._checked_global:
            self._checked_global = True
            headers_finding = self._missing_headers(endpoint, exchange)
            if headers_finding is not None:
                findings.append(headers_finding)
            version_finding = self._version_disclosure(endpoint, exchange)
            if version_finding is not None:
                findings.append(version_finding)
            cors_finding = await self._check_cors(endpoint)
            if cors_finding is not None:
                findings.append(cors_finding)

        return findings

    def _verbose_error(self, endpoint, exchange) -> Finding | None:
        if exchange.status < 500:
            return None
        low = exchange.evidence.response_body.lower()
        hit = next((s for s in _STACKTRACE if s in low), None)
        if hit is None:
            return None
        return Finding(
            id=_slug("misconfig", "verbose-error", endpoint.method, endpoint.path),
            title=f"Verbose error / stack trace on {endpoint.method} {endpoint.path}",
            scanner=self.name,
            endpoint=endpoint,
            severity=Severity.MEDIUM,
            owasp_id=self.owasp_id,
            confidence=0.85,
            description=(
                f"{endpoint.method} {endpoint.path} returned HTTP {exchange.status} with a debug/stack-trace "
                f"body (signature {hit!r}), leaking internal details."
            ),
            remediation="Disable debug mode in production; return generic error bodies.",
            evidence=exchange.evidence,
        )

    def _missing_headers(self, endpoint, exchange) -> Finding | None:
        present = {k.lower() for k in exchange.evidence.response_headers}
        missing = [h for h in _SECURITY_HEADERS if h not in present]
        if not missing:
            return None
        return Finding(
            id="misconfig-missing-security-headers",
            title="Missing security response headers",
            scanner=self.name,
            endpoint=endpoint,
            severity=Severity.LOW,
            owasp_id=self.owasp_id,
            confidence=0.9,
            description=f"Responses are missing security headers: {', '.join(missing)}.",
            remediation="Set X-Content-Type-Options, X-Frame-Options, a CSP, HSTS, and Referrer-Policy.",
            evidence=exchange.evidence,
        )

    def _version_disclosure(self, endpoint, exchange) -> Finding | None:
        server = exchange.evidence.response_headers.get("server", "")
        if not server or not _VERSION_RE.search(server):
            return None
        return Finding(
            id="misconfig-version-disclosure",
            title="Server version disclosure",
            scanner=self.name,
            endpoint=endpoint,
            severity=Severity.LOW,
            owasp_id=self.owasp_id,
            confidence=0.8,
            description=f"The Server header discloses software and version: {server!r}.",
            remediation="Suppress or genericize the Server header.",
            evidence=exchange.evidence,
        )

    async def _check_cors(self, endpoint) -> Finding | None:
        exchange = await self._send(endpoint, {"Origin": "https://evil.example"})
        acao = exchange.evidence.response_headers.get("access-control-allow-origin", "")
        acac = exchange.evidence.response_headers.get("access-control-allow-credentials", "").lower()
        if acao != "*" and acao != "https://evil.example":
            return None
        severity = Severity.HIGH if (acac == "true" and acao != "*") else Severity.MEDIUM
        return Finding(
            id="misconfig-permissive-cors",
            title="Permissive CORS policy",
            scanner=self.name,
            endpoint=endpoint,
            severity=severity,
            owasp_id=self.owasp_id,
            confidence=0.85,
            description=(
                f"An untrusted Origin was reflected in Access-Control-Allow-Origin "
                f"({acao!r}, allow-credentials={acac!r})."
            ),
            remediation="Allowlist trusted origins; never reflect arbitrary Origins with credentials.",
            evidence=exchange.evidence,
        )
