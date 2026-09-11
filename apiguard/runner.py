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

from apiguard.core.http_engine import HttpEngine
from apiguard.core.identity import IdentityManager, UserCredentials
from apiguard.core.models import ScanResult
from apiguard.core.scope import ScopeGuard
from apiguard.core.spec_parser import load_spec, parse_spec
from apiguard.settings import Settings

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
