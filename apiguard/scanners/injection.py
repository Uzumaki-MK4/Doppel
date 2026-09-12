"""Injection scanner: SQLi + reflected XSS in one loop (BRAIN.md D8).

SQLi is detected two ways: error-signature matching (a SQL error appears with the
payload but not in the benign baseline) and time-delay (a sleep payload makes the
response markedly slower than baseline). Reflected XSS is detected by injecting a
marker and checking it reflects unescaped in an HTML response.

Payloads are static wordlists under `wordlists/` (AI-generated payloads arrive in
Week 3); a built-in default list is used if the files are absent.
"""

from __future__ import annotations

import re
import time
from pathlib import Path

from apiguard.core.http_engine import build_request
from apiguard.core.models import Endpoint, Finding, Severity
from apiguard.scanners.base import Scanner

# SQL error signatures across common engines (matched case-insensitively).
_SQL_ERROR_SIGNATURES = (
    "sql syntax",
    "syntax error",
    "unrecognized token",
    "unterminated quoted",
    "quoted string not properly terminated",
    "sqlite3",
    "sqlalchemy",
    "operationalerror",
    "programmingerror",
    "psycopg2",
    "pg::",
    "ora-0",
    "you have an error in your sql",
    "sqlstate",
)

_DEFAULT_SQLI = [
    "'",
    "' OR '1'='1",
    "' OR 1=1--",
    "'; DROP TABLE users--",
    "1' ORDER BY 10--",
    "' OR SLEEP(5)--",
]
_DEFAULT_XSS = [
    "<script>apiguardXSS</script>",
    '"><svg onload=alert(1)>',
    "<apiguardXSSMARKER>",
    "<img src=x onerror=alert(1)>",
]

# Time-based SQLi: trust a delay only when it clearly exceeds a fast baseline.
_TIME_DELAY_THRESHOLD_S = 3.0
_TIME_BASELINE_MAX_S = 1.5


def _load_wordlist(filename: str, default: list[str]) -> list[str]:
    path = Path(__file__).resolve().parents[2] / "wordlists" / filename
    if path.is_file():
        payloads = [
            line.strip()
            for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        ]
        if payloads:
            return payloads
    return list(default)


def _first_sql_signature(body: str) -> str | None:
    low = body.lower()
    for sig in _SQL_ERROR_SIGNATURES:
        if sig in low:
            return sig
    return None


def _slug(*parts: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", "-".join(parts).lower()).strip("-")


def _dedupe(items: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for item in items:
        if item not in seen:
            seen.add(item)
            out.append(item)
    return out


class InjectionScanner(Scanner):
    name = "injection"
    # OWASP API Top 10 2023 folds injection into API8 (Security Misconfiguration);
    # revisited in D11 when OWASP mapping is finalized.
    owasp_id = "API8:2023"

    def __init__(self, context, *, sqli_payloads=None, xss_payloads=None) -> None:
        super().__init__(context)
        self._sqli = sqli_payloads if sqli_payloads is not None else _load_wordlist("sqli.txt", _DEFAULT_SQLI)
        self._xss = xss_payloads if xss_payloads is not None else _load_wordlist("xss.txt", _DEFAULT_XSS)

    def _headers_for(self, endpoint: Endpoint) -> dict[str, str]:
        if endpoint.security and self.context.sessions:
            primary = self.context.sessions.get("userA") or next(
                iter(self.context.sessions.values()), None
            )
            if primary is not None:
                return dict(primary.headers)
        return {}

    async def _probe(self, endpoint, injections, headers):
        method, url, req_headers, query, body = build_request(
            endpoint, self.base_url, values=injections, headers=headers
        )
        start = time.monotonic()
        exchange = await self.engine.send(method, url, headers=req_headers, params=query, body=body)
        return exchange, time.monotonic() - start

    async def run(self, endpoint: Endpoint) -> list[Finding]:
        targets = [p for p in endpoint.parameters if p.location in ("path", "query")]
        if not targets:
            return []

        headers = self._headers_for(endpoint)
        baseline_ex, baseline_t = await self._probe(endpoint, {}, headers)
        baseline_has_sql = _first_sql_signature(baseline_ex.evidence.response_body) is not None

        findings: list[Finding] = []
        for param in targets:
            sqli_payloads, xss_payloads = await self._payloads_for(endpoint, param)
            sqli = await self._scan_sqli(
                endpoint, param, headers, baseline_has_sql, baseline_t, sqli_payloads
            )
            if sqli is not None:
                findings.append(sqli)
            xss = await self._scan_xss(endpoint, param, headers, xss_payloads)
            if xss is not None:
                findings.append(xss)
        return findings

    async def _send_payload(self, endpoint: Endpoint, param, payload: str, headers):
        """Probe with one payload; if input validation rejects it (400/422) and a
        repair loop is available, repair the payload and re-probe (capped)."""
        exchange, elapsed = await self._probe(endpoint, {param.name: payload}, headers)
        repair = getattr(self.context, "repair_loop", None)
        if exchange.status in (400, 422) and repair is not None:
            async def send(corrected: str):
                again, _ = await self._probe(endpoint, {param.name: corrected}, headers)
                return again

            result = await repair.repair_value(
                send=send,
                initial_value=payload,
                context=(
                    f"{param.location} parameter {param.name!r} "
                    f"(type={param.type_}, format={param.format_}) of "
                    f"{endpoint.method} {endpoint.path}"
                ),
                error_body=exchange.evidence.response_body,
                attack_goal="an injection payload that passes input validation",
            )
            if result.final_exchange is not None:
                exchange, elapsed = result.final_exchange, 0.0  # timing moot after repair
        return exchange, elapsed

    async def _payloads_for(self, endpoint: Endpoint, param) -> tuple[list[str], list[str]]:
        """Pick payloads per parameter by the context's payload_mode."""
        mode = getattr(self.context, "payload_mode", "static")
        generator = getattr(self.context, "payload_generator", None)
        if mode == "static" or generator is None:
            return self._sqli, self._xss

        ai = await generator.for_parameter(
            name=param.name,
            type_=param.type_,
            format_=param.format_,
            example=param.example,
            path=endpoint.path,
            method=endpoint.method,
        )
        ai_sqli, ai_xss = ai.get("sqli", []), ai.get("xss", [])
        if mode == "ai":
            return ai_sqli, ai_xss
        return _dedupe(self._sqli + ai_sqli), _dedupe(self._xss + ai_xss)  # both

    async def _scan_sqli(self, endpoint, param, headers, baseline_has_sql, baseline_t, payloads):
        name, loc = param.name, param.location
        for payload in payloads:
            exchange, elapsed = await self._send_payload(endpoint, param, payload, headers)
            sig = _first_sql_signature(exchange.evidence.response_body)
            if sig and not baseline_has_sql:
                return self._sqli_finding(
                    endpoint, name, loc, payload, exchange, f"a SQL error signature ({sig!r})", 0.9
                )
            if (elapsed - baseline_t) >= _TIME_DELAY_THRESHOLD_S and baseline_t <= _TIME_BASELINE_MAX_S:
                return self._sqli_finding(
                    endpoint,
                    name,
                    loc,
                    payload,
                    exchange,
                    f"a {elapsed:.1f}s delay vs a {baseline_t:.1f}s baseline (time-based)",
                    0.7,
                )
        return None

    def _sqli_finding(self, endpoint, name, loc, payload, exchange, why, confidence):
        return Finding(
            id=_slug("injection", "sqli", endpoint.method, endpoint.path, name),
            title=f"SQL injection in {loc} parameter '{name}'",
            scanner=self.name,
            endpoint=endpoint,
            severity=Severity.HIGH,
            owasp_id=self.owasp_id,
            confidence=confidence,
            description=(
                f"Injecting {payload!r} into the {loc} parameter {name!r} of "
                f"{endpoint.method} {endpoint.path} triggered {why}. The input reaches a SQL "
                f"query without proper parameterization."
            ),
            remediation="Use parameterized queries or an ORM binding; never concatenate user input into SQL.",
            evidence=exchange.evidence,
        )

    async def _scan_xss(self, endpoint, param, headers, payloads):
        name, loc = param.name, param.location
        for payload in payloads:
            exchange, _ = await self._send_payload(endpoint, param, payload, headers)
            ctype = exchange.evidence.response_headers.get("content-type", "").lower()
            if "html" in ctype and payload in exchange.evidence.response_body:
                return Finding(
                    id=_slug("injection", "xss", endpoint.method, endpoint.path, name),
                    title=f"Reflected XSS in {loc} parameter '{name}'",
                    scanner=self.name,
                    endpoint=endpoint,
                    severity=Severity.MEDIUM,
                    owasp_id=self.owasp_id,
                    confidence=0.8,
                    description=(
                        f"The {loc} parameter {name!r} of {endpoint.method} {endpoint.path} reflected "
                        f"the payload {payload!r} unescaped in an HTML response."
                    ),
                    remediation="Contextually output-encode reflected input and set a restrictive Content-Type / CSP.",
                    evidence=exchange.evidence,
                )
        return None
