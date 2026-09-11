"""SSRF scanner (BRAIN.md D9).

Injects internal-range and cloud-metadata URLs into URL-shaped parameters and
flags a finding when the response reveals metadata (a strong SSRF signal).

VAmPI has no URL-fetching parameters, so this scanner is expected to report
nothing there — that absence is reported honestly, not padded with a finding.
"""

from __future__ import annotations

import re

from apiguard.core.http_engine import build_request
from apiguard.core.models import Endpoint, Finding, Parameter, Severity
from apiguard.scanners.base import Scanner

_URL_NAME_HINTS = (
    "url", "uri", "host", "hostname", "callback", "webhook", "redirect",
    "dest", "destination", "link", "img", "image", "src", "target", "feed", "proxy",
)

_PAYLOADS = [
    "http://169.254.169.254/latest/meta-data/",           # AWS IMDS
    "http://metadata.google.internal/computeMetadata/v1/",  # GCP
    "http://127.0.0.1:80/",
    "http://localhost/",
    "file:///etc/passwd",
]

# Signatures that indicate the internal/metadata target was actually fetched.
_SIGNATURES = (
    "ami-id",
    "instance-id",
    "iam/security-credentials",
    "computemetadata",
    "meta-data",
    "root:x:0:0",
)


def _looks_like_url_param(param: Parameter) -> bool:
    if (param.format_ or "").lower() == "uri":
        return True
    name = param.name.lower()
    return any(hint in name for hint in _URL_NAME_HINTS)


def _slug(*parts: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", "-".join(parts).lower()).strip("-")


class SsrfScanner(Scanner):
    name = "ssrf"
    owasp_id = "API7:2023"  # Server Side Request Forgery

    def _headers_for(self, endpoint: Endpoint) -> dict[str, str]:
        if endpoint.security and self.context.sessions:
            primary = self.context.sessions.get("userA") or next(
                iter(self.context.sessions.values()), None
            )
            if primary is not None:
                return dict(primary.headers)
        return {}

    async def run(self, endpoint: Endpoint) -> list[Finding]:
        targets = [
            p for p in endpoint.parameters
            if p.location in ("query", "path") and _looks_like_url_param(p)
        ]
        if not targets:
            return []

        headers = self._headers_for(endpoint)
        findings: list[Finding] = []
        for param in targets:
            for payload in _PAYLOADS:
                method, url, req_headers, query, body = build_request(
                    endpoint, self.base_url, values={param.name: payload}, headers=headers
                )
                exchange = await self.engine.send(
                    method, url, headers=req_headers, params=query, body=body
                )
                low = exchange.evidence.response_body.lower()
                hit = next((s for s in _SIGNATURES if s in low), None)
                if hit is not None:
                    findings.append(
                        Finding(
                            id=_slug("ssrf", endpoint.method, endpoint.path, param.name),
                            title=f"SSRF via {param.location} parameter '{param.name}'",
                            scanner=self.name,
                            endpoint=endpoint,
                            severity=Severity.HIGH,
                            owasp_id=self.owasp_id,
                            confidence=0.85,
                            description=(
                                f"Injecting {payload!r} into {param.name!r} of "
                                f"{endpoint.method} {endpoint.path} returned internal/metadata "
                                f"content (signature {hit!r})."
                            ),
                            remediation="Validate/allowlist outbound URLs; block link-local and internal ranges.",
                            evidence=exchange.evidence,
                        )
                    )
                    break  # one finding per parameter
        return findings
