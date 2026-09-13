"""Tests for the BOLA cross-access phase (Day 20)."""

import asyncio
import json

import respx
from httpx import Response

from apiguard.core.http_engine import HttpEngine
from apiguard.core.identity import Session
from apiguard.core.models import Endpoint, Parameter
from apiguard.engines.bola import collect_triples

BASE = "http://localhost:5000"


def _endpoints() -> list[Endpoint]:
    return [
        Endpoint(path="/books/v1", method="GET", parameters=[], request_body_schema=None, security=["bearerAuth"]),
        Endpoint(
            path="/books/v1",
            method="POST",
            parameters=[],
            request_body_schema={"type": "object", "properties": {"book_title": {"type": "string"}, "secret": {"type": "string"}}},
            security=["bearerAuth"],
        ),
        Endpoint(
            path="/books/v1/{book_title}",
            method="GET",
            parameters=[Parameter(name="book_title", location="path", type_="string", required=True)],
            request_body_schema=None,
            security=["bearerAuth"],
        ),
    ]


def _sessions():
    return {
        "userA": Session(username="apiguard_a", token="A", headers={"Authorization": "Bearer A"}),
        "userB": Session(username="apiguard_b", token="B", headers={"Authorization": "Bearer B"}),
    }


@respx.mock
def test_collect_triples_shows_cross_access_leak():
    # A owns book "apiguard_userA_book_title" (seeded); B owns "apiguard_userB_book_title".
    owners = {"apiguard_userA_book_title": "apiguard_a", "apiguard_userB_book_title": "apiguard_b"}

    def post_books(request):
        body = json.loads(request.content.decode())
        who = "apiguard_a" if request.headers.get("authorization") == "Bearer A" else "apiguard_b"
        owners[body["book_title"]] = who
        return Response(200, json={"status": "success"})

    def list_books(request):
        return Response(200, json={"Books": [{"book_title": t, "user": u} for t, u in owners.items()]})

    def get_book(request):
        title = request.url.path.rsplit("/", 1)[-1]
        # VAmPI-style BOLA: returns the object with its secret REGARDLESS of caller.
        return Response(200, json={"book_title": title, "owner": owners.get(title, "?"), "secret": f"secret-of-{title}"})

    respx.post(f"{BASE}/books/v1").mock(side_effect=post_books)
    respx.get(f"{BASE}/books/v1").mock(side_effect=list_books)
    respx.get(url__regex=rf"{BASE}/books/v1/.+").mock(side_effect=get_book)

    async def go():
        async with HttpEngine(rate_limit_per_s=0) as engine:
            return await collect_triples(engine, BASE, _sessions(), _endpoints())

    triples = asyncio.run(go())
    # A's seeded book id
    t = next(x for x in triples if x.a_object_id == "apiguard_userA_book_title")
    # B cross-accessed A's book and got A's secret (the leak)
    assert "secret-of-apiguard_userA_book_title" in t.b_cross_access.response_body
    assert t.a_object_id in t.b_cross_access.response_body  # A's id echoed in B's cross-access
    # B's control (B's own book) is present and different
    assert t.b_control is not None
    assert "secret-of-apiguard_userB_book_title" in t.b_control.response_body
    # A's own access is the reference
    assert "secret-of-apiguard_userA_book_title" in t.a_access.response_body


@respx.mock
def test_control_absent_when_attacker_owns_nothing():
    # Collection lists only A's book; POST refuses for B so B owns nothing.
    def post_books(request):
        if request.headers.get("authorization") == "Bearer B":
            return Response(403, json={"status": "fail"})
        return Response(200, json={"status": "success"})

    def list_books(request):
        return Response(200, json={"Books": [{"book_title": "apiguard_userA_book_title", "user": "apiguard_a"}]})

    def get_book(request):
        title = request.url.path.rsplit("/", 1)[-1]
        return Response(200, json={"book_title": title, "owner": "apiguard_a", "secret": "s"})

    respx.post(f"{BASE}/books/v1").mock(side_effect=post_books)
    respx.get(f"{BASE}/books/v1").mock(side_effect=list_books)
    respx.get(url__regex=rf"{BASE}/books/v1/.+").mock(side_effect=get_book)

    async def go():
        async with HttpEngine(rate_limit_per_s=0) as engine:
            return await collect_triples(engine, BASE, _sessions(), _endpoints())

    triples = asyncio.run(go())
    assert triples  # A still has an object
    assert all(t.b_control is None for t in triples)  # B owns nothing -> no control
