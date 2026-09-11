"""Tests for apiguard.scanners.base — the ABC + registry (Day 7)."""

import asyncio

import pytest

from apiguard.core.models import Endpoint, Evidence, Finding, Severity
from apiguard.scanners.base import (
    ScanContext,
    Scanner,
    build_scanners,
    discover_scanners,
    registered_scanners,
)


def _endpoint() -> Endpoint:
    return Endpoint(path="/x", method="GET", parameters=[], request_body_schema=None, security=[])


def _evidence() -> Evidence:
    return Evidence(
        request_method="GET",
        request_url="http://localhost:5000/x",
        response_status=200,
        response_body="{}",
        curl_repro="curl http://localhost:5000/x",
    )


class DummyScanner(Scanner):
    name = "dummy"
    owasp_id = "API8:2023"

    async def run(self, endpoint: Endpoint) -> list[Finding]:
        return [
            Finding(
                id="dummy-1",
                title="dummy finding",
                scanner=self.name,
                endpoint=endpoint,
                severity=Severity.INFO,
                owasp_id=self.owasp_id,
                confidence=0.0,
                description="always one",
                remediation="n/a",
                evidence=_evidence(),
            )
        ]


def test_subclass_auto_registers():
    assert registered_scanners().get("dummy") is DummyScanner


def test_duplicate_name_raises():
    with pytest.raises(ValueError):

        class AnotherDummy(Scanner):  # noqa: F811 - intentional duplicate name
            name = "dummy"

            async def run(self, endpoint: Endpoint) -> list[Finding]:
                return []


def test_nameless_subclass_not_registered():
    class Nameless(Scanner):
        async def run(self, endpoint: Endpoint) -> list[Finding]:
            return []

    assert Nameless not in registered_scanners().values()


def test_build_and_run_dummy():
    ctx = ScanContext(engine=None, base_url="http://localhost:5000")  # dummy ignores engine
    scanners = build_scanners(ctx, discover=False)
    dummy = next(s for s in scanners if s.name == "dummy")
    findings = asyncio.run(dummy.run(_endpoint()))
    assert len(findings) == 1
    assert findings[0].scanner == "dummy"
    assert findings[0].endpoint.path == "/x"


def test_discover_runs_and_is_idempotent():
    discover_scanners()
    first = registered_scanners()
    discover_scanners()
    assert registered_scanners() == first  # re-discovery does not duplicate
