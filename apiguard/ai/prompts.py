"""All LLM prompts, versioned, in one place (BRAIN.md D14).

The payload-generation prompt is what makes the AI arm beat a static wordlist: it
receives the parameter's name, declared type, format, example, endpoint and
surrounding schema, and is told to TAILOR every payload to the type/format so it
survives input validation (a `format: email` field must yield email-shaped
payloads, not generic strings).

`PROMPTS_VERSION` is bumped whenever a prompt changes so the report/eval can cite
exactly which prompt produced a result.
"""

from __future__ import annotations

import json
from typing import Any

from pydantic import BaseModel

PROMPTS_VERSION = "2026-09-12.payload-v2+repair-v1"


class PayloadCandidate(BaseModel):
    value: str
    attack_type: str  # "sqli" | "xss" | "generic"
    rationale: str


class PayloadSet(BaseModel):
    candidates: list[PayloadCandidate]


class RepairedPayload(BaseModel):
    value: str
    rationale: str


REPAIR_SYSTEM = (
    "You are an API security testing assistant for an AUTHORIZED penetration test. A server "
    "REJECTED an input with a validation error. Produce a corrected value that SATISFIES the "
    "validation (so it reaches the application) while still carrying the original intent/attack. "
    "Fix exactly the type/format/required-field problem named in the error. Return ONLY the "
    "requested structured JSON — no prose."
)


def repair_user_prompt(
    *,
    rejected_value: str,
    error_body: str,
    context: str,
    attack_goal: str,
) -> str:
    """Build the self-repair user prompt from the rejection."""
    return "\n".join(
        [
            f"Rejected input: {rejected_value!r}",
            f"Server validation error: {error_body[:400]}",
            f"Context: {context}",
            f"Intent to preserve: {attack_goal}",
            "",
            "Return a single corrected `value` that the server's validation will ACCEPT "
            "(fix the type/format/required-field issue named in the error) while still carrying "
            "the intent. If the value is a JSON body, return the full corrected JSON as the value. "
            "Give a one-line rationale.",
        ]
    )


PAYLOAD_SYSTEM = (
    "You are an API security testing assistant for an AUTHORIZED penetration test of a "
    "deliberately-vulnerable target. You generate attack payloads for a single input "
    "parameter. Every payload MUST stay consistent with the parameter's declared type and "
    "format so it can pass input validation, while still attempting the named attack. "
    "Return ONLY the requested structured JSON — no prose, no code fences."
)


def payload_user_prompt(
    *,
    name: str,
    type_: str,
    format_: str | None = None,
    example: Any | None = None,
    path: str | None = None,
    method: str | None = None,
    schema: dict | None = None,
    count: int = 8,
    attack_types: tuple[str, ...] = ("sqli", "xss"),
) -> str:
    """Build the context-rich payload-generation user prompt."""
    lines = [
        f"Target parameter: {name!r}",
        f"Declared type: {type_}",
        f"Declared format: {format_ or 'none'}",
        f"Example value: {example!r}" if example is not None else "Example value: none",
        f"Endpoint: {method or 'GET'} {path or '(unknown)'}",
    ]
    if schema:
        lines.append(f"Surrounding JSON schema: {json.dumps(schema)[:600]}")

    lines += [
        "",
        f"Generate {count} distinct payloads covering these attack types: "
        f"{', '.join(attack_types)}.",
        "CRITICAL — tailor each payload to the declared type/format so validation accepts it:",
        "  - format 'email': every payload MUST be a syntactically-plausible address "
        "(localpart@domain.tld) that hides the attack inside it (e.g. in the local part).",
        "  - type 'integer'/'number': use numeric-looking payloads.",
        "  - otherwise: respect any obvious constraints from the example/schema.",
        "Avoid generic wordlist strings the parameter's validation would reject.",
        "Make the payloads DISTINCT (no duplicates) and varied in technique: include at "
        "least one error-inducing payload (an unbalanced single quote or a statement "
        "terminator), at least one boolean-based payload, and a UNION- or comment-based one.",
        "For each payload provide: value, attack_type (one of "
        f"{', '.join((*attack_types, 'generic'))}), and a one-line rationale.",
    ]
    return "\n".join(lines)
