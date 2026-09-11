"""Findings post-processing: dedup, OWASP mapping, evidence validation (D11).

Scanners assign a deterministic, readable `Finding.id` per (scanner, weakness,
endpoint, parameter). `finalize()` collapses duplicates by that id, checks every
finding carries a curl repro and a valid OWASP id (invariant 6), and returns a
stably-sorted list so saved result files are reproducible.
"""

from __future__ import annotations

from apiguard.core.models import Finding, Severity

# OWASP API Security Top 10 2023 catalog (id -> name).
OWASP_API_2023: dict[str, str] = {
    "API1:2023": "Broken Object Level Authorization",
    "API2:2023": "Broken Authentication",
    "API3:2023": "Broken Object Property Level Authorization",
    "API4:2023": "Unrestricted Resource Consumption",
    "API5:2023": "Broken Function Level Authorization",
    "API6:2023": "Unrestricted Access to Sensitive Business Flows",
    "API7:2023": "Server Side Request Forgery",
    "API8:2023": "Security Misconfiguration",
    "API9:2023": "Improper Inventory Management",
    "API10:2023": "Unsafe Consumption of APIs",
}

# Note: the 2023 list has NO standalone Injection category (it was API8:2019
# Injection). SQLi/XSS are mapped to API8:2023 (Security Misconfiguration) as the
# nearest current bucket; the finding title keeps the specific attack name.

# Default severity per category — a reference/floor for the report. Scanners set
# their own severity per finding and may go higher or lower with justification.
DEFAULT_SEVERITY: dict[str, Severity] = {
    "API1:2023": Severity.HIGH,
    "API2:2023": Severity.HIGH,
    "API3:2023": Severity.MEDIUM,
    "API4:2023": Severity.LOW,
    "API5:2023": Severity.HIGH,
    "API6:2023": Severity.MEDIUM,
    "API7:2023": Severity.HIGH,
    "API8:2023": Severity.MEDIUM,
    "API9:2023": Severity.LOW,
    "API10:2023": Severity.MEDIUM,
}

_SEVERITY_RANK: dict[Severity, int] = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


def owasp_name(owasp_id: str) -> str:
    return OWASP_API_2023.get(owasp_id, "Unmapped")


def is_valid_owasp_id(owasp_id: str) -> bool:
    return owasp_id in OWASP_API_2023


def _rank(finding: Finding) -> tuple[int, float]:
    return (_SEVERITY_RANK[finding.severity], finding.confidence)


def dedupe(findings: list[Finding]) -> list[Finding]:
    """Collapse findings sharing an id, keeping the highest severity/confidence."""
    best: dict[str, Finding] = {}
    for finding in findings:
        current = best.get(finding.id)
        if current is None or _rank(finding) > _rank(current):
            best[finding.id] = finding
    return list(best.values())


def finalize(findings: list[Finding], *, strict: bool = True) -> list[Finding]:
    """Dedupe, validate evidence + OWASP ids, and sort deterministically."""
    deduped = dedupe(findings)

    if strict:
        no_curl = [f.id for f in deduped if not f.evidence.curl_repro.strip()]
        if no_curl:
            raise ValueError(f"Findings missing a curl repro (invariant 6): {no_curl}")
        bad_owasp = [f.id for f in deduped if not is_valid_owasp_id(f.owasp_id)]
        if bad_owasp:
            raise ValueError(f"Findings with an invalid OWASP id: {bad_owasp}")

    # Highest severity first, then id for a stable, reproducible order.
    return sorted(deduped, key=lambda f: (-_SEVERITY_RANK[f.severity], f.id))
