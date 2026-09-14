"""Tests for doppel.scanners.jwt_attacks (Day 9)."""

import asyncio
import base64
import hashlib
import hmac
import json
import time

import respx
from httpx import Response

from doppel.core.http_engine import HttpEngine
from doppel.core.identity import Session
from doppel.core.models import Endpoint
from doppel.scanners.base import ScanContext
from doppel.scanners.jwt_attacks import JwtScanner, forge_hs256, forge_none, token_payload

BASE = "http://localhost:5000"
SERVER_SECRET = "topsecret"


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _b64url_decode(seg: str) -> bytes:
    return base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4))


def _valid_hs256(token: str, secret: str, check_exp: bool = True) -> bool:
    try:
        h, p, s = token.split(".")
        if json.loads(_b64url_decode(h)).get("alg") != "HS256":
            return False
        expected = _b64url(hmac.new(secret.encode(), f"{h}.{p}".encode(), hashlib.sha256).digest())
        if not hmac.compare_digest(s, expected):
            return False
        if check_exp and json.loads(_b64url_decode(p)).get("exp", 10**12) < time.time():
            return False
        return True
    except Exception:
        return False


def _token_of(request) -> str:
    auth = request.headers.get("authorization", "")
    return auth[7:] if auth.lower().startswith("bearer ") else ""


def _me_endpoint() -> Endpoint:
    return Endpoint(path="/me", method="GET", parameters=[], request_body_schema=None, security=["bearerAuth"])


def _valid_session() -> Session:
    payload = {"sub": "apiguard_a", "iat": int(time.time()), "exp": int(time.time()) + 300}
    token = forge_hs256(payload, SERVER_SECRET)
    return Session(username="apiguard_a", token=token, headers={"Authorization": f"Bearer {token}"})


def _run(scanner_wordlist, handler):
    respx.get(f"{BASE}/me").mock(side_effect=handler)
    session = _valid_session()

    async def go():
        async with HttpEngine(rate_limit_per_s=0) as engine:
            ctx = ScanContext(engine=engine, base_url=BASE, sessions={"userA": session})
            scanner = JwtScanner(ctx, secret_wordlist=scanner_wordlist)
            return await scanner.run(_me_endpoint())

    return asyncio.run(go())


def test_forge_helpers_roundtrip():
    payload = {"sub": "u", "exp": 1}
    assert token_payload(forge_hs256(payload, "s")) == payload
    assert forge_none(payload).endswith(".")  # empty signature segment


def _hs256_server(check_exp=True):
    def handler(request):
        if _valid_hs256(_token_of(request), SERVER_SECRET, check_exp):
            return Response(200, json={"data": {"username": "apiguard_a"}, "status": "success"})
        return Response(401, json={"status": "fail", "message": "Invalid token"})
    return handler


@respx.mock
def test_flags_weak_secret():
    findings = _run(["nope", "topsecret", "other"], _hs256_server())
    weak = [f for f in findings if "weak-secret" in f.id]
    assert len(weak) == 1
    assert weak[0].severity.value == "critical"
    assert weak[0].scanner == "jwt"
    # exp is enforced by this server, so no expired-replay finding
    assert not any("expired" in f.id for f in findings)


@respx.mock
def test_strong_server_no_findings():
    findings = _run(["nope", "other", "weak"], _hs256_server())  # real secret not in list
    assert findings == []


@respx.mock
def test_flags_alg_none():
    def handler(request):
        token = _token_of(request)
        try:
            header = json.loads(_b64url_decode(token.split(".")[0]))
        except Exception:
            return Response(401)
        if header.get("alg") == "none":  # insecurely trusts unsigned tokens
            return Response(200, json={"data": {}})
        if _valid_hs256(token, SERVER_SECRET):
            return Response(200, json={"data": {}})
        return Response(401, json={"status": "fail"})

    findings = _run(["nope", "other"], handler)  # real secret excluded -> only alg:none fires
    assert any("alg-none" in f.id for f in findings)
    assert not any("weak-secret" in f.id for f in findings)


@respx.mock
def test_flags_expired_replay_when_exp_ignored():
    findings = _run(["topsecret"], _hs256_server(check_exp=False))
    assert any("weak-secret" in f.id for f in findings)
    assert any("expired-replay" in f.id for f in findings)
