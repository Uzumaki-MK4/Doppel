"""Core data models for APIGuard.

Every structured value that crosses a module boundary is a pydantic v2 model
(BRAIN.md invariant 9 — no bare dicts between modules). These are the contracts
from BRAIN.md Section 5, transcribed. `ScanResult` is the one model Section 5
names but does not define; its shape is chosen here and documented inline.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

# Reject unexpected fields everywhere: a mistyped key is a loud error, not a
# silently dropped value. Shared because ConfigDict is just a plain mapping.
_STRICT = ConfigDict(extra="forbid")


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Parameter(BaseModel):
    """One input to an endpoint, as declared in the OpenAPI spec.

    `type_` / `format_` carry trailing underscores to avoid shadowing the
    Python builtins; the spec parser maps OpenAPI `type` / `format` onto them.
    """

    model_config = _STRICT

    name: str
    location: Literal["path", "query", "header", "cookie", "body"]
    type_: str
    format_: str | None = None
    required: bool = False
    example: Any | None = None


class Endpoint(BaseModel):
    """A single operation (method + path) parsed from the spec."""

    model_config = _STRICT

    path: str
    method: str
    parameters: list[Parameter] = Field(default_factory=list)
    request_body_schema: dict | None = None
    security: list[str] = Field(default_factory=list)
    operation_id: str | None = None


class Evidence(BaseModel):
    """Full request + response capture and a copy-pasteable curl (invariant 6).

    No finding exists without one of these. The `curl_repro` string is built by
    the HTTP engine (D4) / evidence capture (D11); this model only holds it.
    """

    model_config = _STRICT

    request_method: str
    request_url: str
    request_headers: dict[str, str] = Field(default_factory=dict)
    request_body: str | None = None
    response_status: int
    response_headers: dict[str, str] = Field(default_factory=dict)
    response_body: str
    curl_repro: str


class AITrace(BaseModel):
    """Explainability record for a finding the LLM actually touched (upgrade 6).

    `signals` holds the measurable confidence signals from Section 5 — never a
    self-reported confidence number (invariant 5). Absent on purely
    deterministic findings.
    """

    model_config = _STRICT

    model: str
    seed: int
    temperature: float
    prompt: str
    raw_response: str
    signals: dict[str, float] = Field(default_factory=dict)


class Finding(BaseModel):
    """One vulnerability finding with its evidence and optional AI trace."""

    model_config = _STRICT

    id: str
    title: str
    scanner: str
    endpoint: Endpoint
    severity: Severity
    owasp_id: str  # e.g. "API1:2023"
    # Confidence is COMPUTED from signals (invariant 5), so it must stay in range.
    confidence: float = Field(ge=0.0, le=1.0)
    description: str
    remediation: str
    evidence: Evidence
    ai_trace: AITrace | None = None


class ScanResult(BaseModel):
    """Top-level output of one scan run.

    Section 5 names this model but leaves its shape to us. It is deliberately
    self-describing: it records the `model`, `seed` and `payload_mode` of the
    run plus `requests_sent`, so a saved result file can be attributed to one
    ablation arm without external context (Week-5 table, BRAIN.md Section 1).
    """

    model_config = _STRICT

    target: str
    spec_url: str
    model: str
    seed: int
    payload_mode: Literal["static", "ai", "both"] = "static"
    endpoints: list[Endpoint] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    requests_sent: int = 0
    started_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    finished_at: datetime | None = None

    def severity_counts(self) -> dict[str, int]:
        """Count findings by severity. Pure aggregation for report/dashboard."""
        counts: dict[str, int] = {s.value: 0 for s in Severity}
        for finding in self.findings:
            counts[finding.severity.value] += 1
        return counts
