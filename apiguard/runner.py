"""Scan orchestration (BRAIN.md D6).

The runner is where the pipeline is wired together, keeping the CLI logic-free
(invariant 1). `dry_run()` parses the spec, logs in both users, and touches every
endpoint with a baseline probe (as User A) — the Week-1 end-to-end plumbing check,
with no vulnerability scanners yet. Progress is reported through an optional
callback so `rich` stays in the CLI.

Note: a dry-run still sends baseline requests (it is not a no-network mode), so
run it only against a disposable target such as VAmPI.
"""

from __future__ import annotations

from collections.abc import Callable
from urllib.parse import urlparse

import re

from apiguard.ai.client import OllamaClient
from apiguard.ai.oracle import BolaOracle
from apiguard.ai.payload_gen import PayloadGenerator
from apiguard.ai.repair import RepairLoop
from apiguard.core.findings import finalize
from apiguard.core.http_engine import Cassette, HttpEngine
from apiguard.core.identity import IdentityManager, UserCredentials
from apiguard.core.models import AITrace, Endpoint, Finding, ScanResult, Severity
from apiguard.core.scope import ScopeGuard
from apiguard.core.spec_parser import load_spec, parse_spec
from apiguard.engines.bola import collect_triples
from apiguard.scanners.base import ScanContext, build_scanners
from apiguard.scoring.confidence import compute_signals, confidence
from apiguard.settings import Settings


def _bola_finding_id(endpoint: Endpoint, object_id: str) -> str:
    raw = f"bola-{endpoint.method}-{endpoint.path}-{object_id}".lower()
    return re.sub(r"[^a-z0-9]+", "-", raw).strip("-")


async def find_bola_findings(
    engine: HttpEngine,
    base_url: str,
    sessions,
    endpoints: list[Endpoint],
    oracle: BolaOracle,
    weights: dict[str, float],
    *,
    attacker: str = "userB",
) -> list[Finding]:
    """Full BOLA engine: triples -> gate/oracle -> 5 signals -> confidence -> Finding."""
    triples = await collect_triples(engine, base_url, sessions, endpoints, attacker=attacker)
    findings: list[Finding] = []
    for triple in triples:
        decision = await oracle.adjudicate(triple)
        if not decision.is_leak:
            continue
        signals = compute_signals(triple, decision.oracle_verdict)
        endpoint = triple.object_endpoint
        # Public endpoints (no security) leak by design -> lower severity, not suppressed.
        severity = Severity.HIGH if endpoint.security else Severity.MEDIUM
        ai_trace = None
        if decision.trace is not None:
            ai_trace = AITrace(
                model=decision.trace["model"],
                seed=decision.trace["seed"],
                temperature=decision.trace["temperature"],
                prompt=decision.trace["prompt"],
                raw_response=decision.trace["raw_response"],
                signals=signals,
            )
        public = " (public endpoint)" if not endpoint.security else ""
        findings.append(
            Finding(
                id=_bola_finding_id(endpoint, triple.a_object_id),
                title=f"BOLA: User B can read User A's object via {endpoint.method} {endpoint.path}{public}",
                scanner="bola",
                endpoint=endpoint,
                severity=severity,
                owasp_id="API1:2023",
                confidence=confidence(signals, weights),
                description=(
                    f"User B accessed User A's object (id={triple.a_object_id!r}) and received A's "
                    f"data. Leaked fields: {decision.leaked_fields or 'see response body'}. "
                    f"Oracle: {decision.reasoning}"
                ),
                remediation=(
                    "Enforce object-level authorization: verify the authenticated caller owns or "
                    "is permitted to access the requested object."
                ),
                evidence=triple.b_cross_access,
                ai_trace=ai_trace,
            )
        )
    return findings

# on_progress(current_index, total, description)
ProgressCb = Callable[[int, int, str], None]


def _base_url_of(spec_source: str) -> str:
    parsed = urlparse(spec_source)
    if parsed.scheme in ("http", "https") and parsed.netloc:
        return f"{parsed.scheme}://{parsed.netloc}"
    raise ValueError(
        f"Cannot derive a base URL from {spec_source!r}; pass base_url explicitly."
    )


async def dry_run(
    spec_source: str,
    settings: Settings,
    *,
    base_url: str | None = None,
    confirm_authorized: bool = False,
    on_progress: ProgressCb | None = None,
) -> ScanResult:
    """Parse, log in both users, and touch every endpoint. No scanners."""
    base_url = base_url or _base_url_of(spec_source)
    # Enforce scope on the scan-traffic host too (invariant 7), not just the fetch.
    ScopeGuard(settings.scope.allowlist).check(base_url, confirm_authorized=confirm_authorized)

    spec = await load_spec(
        spec_source, allowlist=settings.scope.allowlist, confirm_authorized=confirm_authorized
    )
    endpoints = parse_spec(spec)

    async with HttpEngine(
        max_concurrency=settings.http.max_concurrency,
        rate_limit_per_s=settings.http.rate_limit_per_s,
        timeout_s=settings.http.timeout_s,
        retries=settings.http.retries,
    ) as engine:
        identity = IdentityManager(engine, base_url)
        users = {
            name: UserCredentials(**cfg.model_dump()) for name, cfg in settings.users.items()
        }
        sessions = await identity.setup(users)
        primary = sessions.get("userA") or next(iter(sessions.values()), None)
        headers = dict(primary.headers) if primary is not None else None

        total = len(endpoints)
        for index, endpoint in enumerate(endpoints, start=1):
            if on_progress is not None:
                on_progress(index, total, f"{endpoint.method} {endpoint.path}")
            await engine.probe(endpoint, base_url, headers=headers)

        return ScanResult(
            target=base_url,
            spec_url=spec_source,
            model=settings.model,
            seed=settings.seed,
            payload_mode="static",
            endpoints=endpoints,
            findings=[],
            requests_sent=engine.requests_sent,
        )


async def scan(
    spec_source: str,
    settings: Settings,
    *,
    base_url: str | None = None,
    confirm_authorized: bool = False,
    payload_mode: str = "static",
    repair_enabled: bool = True,
    bola_enabled: bool = False,
    record_dir: str | None = None,
    replay_dir: str | None = None,
    on_progress: ProgressCb | None = None,
) -> ScanResult:
    """Full baseline scan: fan every endpoint across all registered scanners.

    Scanners run sequentially (they hold per-run guards, e.g. the JWT and
    rate-limit scanners probe once); parallelising is a later optimisation.
    With `record_dir` the whole scan (spec + auth + scanners) is recorded to a
    cassette; with `replay_dir` it re-runs entirely from that cassette, offline.
    """
    base_url = base_url or _base_url_of(spec_source)
    ScopeGuard(settings.scope.allowlist).check(base_url, confirm_authorized=confirm_authorized)

    if replay_dir is not None:
        cassette: Cassette | None = Cassette.load(replay_dir)
    elif record_dir is not None:
        cassette = Cassette(mode="record")
    else:
        cassette = None

    # AI payloads: build a generator for ai/both, degrading to static if Ollama
    # is unreachable (invariant 4 — a scan must still run with Ollama off).
    generator = None
    repair_loop = None
    effective_mode = payload_mode
    if payload_mode in ("ai", "both"):
        ai_client = OllamaClient.from_settings(settings)
        if await ai_client.available():
            generator = PayloadGenerator(ai_client, temperature=settings.temperature_payload)
            if repair_enabled:
                repair_loop = RepairLoop(ai_client, temperature=settings.temperature_payload)
        else:
            effective_mode = "static"

    async with HttpEngine(
        max_concurrency=settings.http.max_concurrency,
        rate_limit_per_s=settings.http.rate_limit_per_s,
        timeout_s=settings.http.timeout_s,
        retries=settings.http.retries,
        cassette=cassette,
    ) as engine:
        spec = await load_spec(
            spec_source,
            allowlist=settings.scope.allowlist,
            confirm_authorized=confirm_authorized,
            engine=engine,
        )
        endpoints = parse_spec(spec)

        identity = IdentityManager(engine, base_url)
        users = {
            name: UserCredentials(**cfg.model_dump()) for name, cfg in settings.users.items()
        }
        sessions = await identity.setup(users)
        context = ScanContext(
            engine=engine,
            base_url=base_url,
            settings=settings,
            sessions=sessions,
            payload_mode=effective_mode,
            payload_generator=generator,
            repair_loop=repair_loop,
        )
        scanners = build_scanners(context)  # discover + instantiate every registered scanner

        findings = []
        total = len(endpoints)
        for index, endpoint in enumerate(endpoints, start=1):
            if on_progress is not None:
                on_progress(index, total, f"{endpoint.method} {endpoint.path}")
            for scanner in scanners:
                findings.extend(await scanner.run(endpoint))

        # BOLA engine (the "Full" arm): needs two users + the oracle. Degrades
        # silently if Ollama is unavailable (invariant 4).
        if bola_enabled and len(sessions) >= 2:
            bola_client = OllamaClient.from_settings(settings)
            if await bola_client.available():
                # Re-authenticate: earlier scanners may have disturbed target state
                # (e.g. VAmPI's GET /createdb reset endpoint wipes registered users),
                # invalidating the sessions from the start of the scan.
                bola_sessions = await identity.setup(users)
                oracle = BolaOracle(bola_client, temperature=settings.temperature_oracle)
                findings.extend(
                    await find_bola_findings(
                        engine,
                        base_url,
                        bola_sessions,
                        endpoints,
                        oracle,
                        settings.confidence_weights.model_dump(),
                    )
                )

        result = ScanResult(
            target=base_url,
            spec_url=spec_source,
            model=settings.model,
            seed=settings.seed,
            payload_mode=effective_mode,  # what actually ran (static if Ollama was down)
            endpoints=endpoints,
            findings=finalize(findings),  # dedupe + validate + stable sort
            requests_sent=engine.requests_sent,
        )

    # Only a record-mode cassette holds interactions; guard against overwriting
    # a real cassette with an empty one if both dirs were somehow supplied.
    if record_dir is not None and cassette is not None and cassette.mode == "record":
        cassette.save(record_dir, meta={"spec_source": spec_source, "base_url": base_url})

    return result
