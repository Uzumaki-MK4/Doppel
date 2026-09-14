"""Tests for doppel.core.identity (Day 5). respx mocks the auth flow."""

import asyncio

import pytest
import respx
from httpx import Response

from doppel.core.http_engine import HttpEngine
from doppel.core.identity import (
    AuthFlow,
    IdentityError,
    IdentityManager,
    UserCredentials,
)

BASE = "http://localhost:5000"
TOKEN_A = "jwt-token-A"
TOKEN_B = "jwt-token-B"


def _mock_vampi_auth():
    """Wire register + login for two users the way VAmPI responds."""
    respx.post(f"{BASE}/users/v1/register").mock(
        return_value=Response(200, json={"message": "ok", "status": "success"})
    )

    def login(request):
        import json as _json

        body = _json.loads(request.content.decode())
        token = TOKEN_A if body["username"] == "userA" else TOKEN_B
        return Response(200, json={"auth_token": token, "status": "success"})

    respx.post(f"{BASE}/users/v1/login").mock(side_effect=login)


@respx.mock
def test_authenticate_returns_session_with_bearer_header():
    _mock_vampi_auth()

    async def run():
        async with HttpEngine(rate_limit_per_s=0) as engine:
            mgr = IdentityManager(engine, BASE)
            return await mgr.authenticate(UserCredentials(username="userA", password="pw"))

    session = asyncio.run(run())
    assert session.username == "userA"
    assert session.token == TOKEN_A
    assert session.headers == {"Authorization": f"Bearer {TOKEN_A}"}


@respx.mock
def test_setup_two_users_and_session_for():
    _mock_vampi_auth()

    async def run():
        async with HttpEngine(rate_limit_per_s=0) as engine:
            mgr = IdentityManager(engine, BASE)
            sessions = await mgr.setup(
                {
                    "userA": UserCredentials(username="userA", password="pw"),
                    "userB": UserCredentials(username="userB", password="pw"),
                }
            )
            return sessions, mgr.session_for("userA"), mgr.session_for("userB")

    sessions, a, b = asyncio.run(run())
    assert set(sessions) == {"userA", "userB"}
    assert a.token == TOKEN_A and b.token == TOKEN_B
    assert a.headers["Authorization"] != b.headers["Authorization"]


@respx.mock
def test_login_failure_raises():
    respx.post(f"{BASE}/users/v1/register").mock(return_value=Response(200, json={}))
    respx.post(f"{BASE}/users/v1/login").mock(
        return_value=Response(401, json={"message": "bad creds", "status": "fail"})
    )

    async def run():
        async with HttpEngine(rate_limit_per_s=0) as engine:
            mgr = IdentityManager(engine, BASE)
            await mgr.authenticate(UserCredentials(username="userA", password="wrong"))

    with pytest.raises(IdentityError):
        asyncio.run(run())


@respx.mock
def test_missing_token_key_raises():
    respx.post(f"{BASE}/users/v1/register").mock(return_value=Response(200, json={}))
    respx.post(f"{BASE}/users/v1/login").mock(
        return_value=Response(200, json={"status": "success"})  # no auth_token
    )

    async def run():
        async with HttpEngine(rate_limit_per_s=0) as engine:
            await IdentityManager(engine, BASE).authenticate(
                UserCredentials(username="userA", password="pw")
            )

    with pytest.raises(IdentityError):
        asyncio.run(run())


def test_session_for_unknown_raises():
    async def run():
        async with HttpEngine(rate_limit_per_s=0) as engine:
            IdentityManager(engine, BASE).session_for("nobody")

    with pytest.raises(IdentityError):
        asyncio.run(run())


def test_custom_authflow_fields():
    flow = AuthFlow(token_json_key="token", header_template="{token}", header_name="X-Auth")
    assert flow.token_json_key == "token"
    assert flow.header_template.format(token="abc") == "abc"
