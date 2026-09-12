"""Tests for apiguard.engines.bola resource discovery (Day 19)."""

import asyncio
import json

import respx
from httpx import Response

from apiguard.core.http_engine import HttpEngine
from apiguard.core.identity import Session
from apiguard.core.models import Endpoint, Parameter
from apiguard.engines.bola import ResourceDiscoverer

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
def test_discovers_seeded_and_harvested_ids():
    created = {"titles": set()}

    def post_books(request):
        body = json.loads(request.content.decode())
        created["titles"].add(body["book_title"])
        return Response(200, json={"message": "Book has been added.", "status": "success"})

    def list_books(request):
        items = [{"book_title": "bookTitle36", "user": "name1"}, {"book_title": "other", "user": "apiguard_a"}]
        items += [{"book_title": t, "user": "apiguard_a"} for t in created["titles"]]
        return Response(200, json={"Books": items})

    def get_book(request):
        title = request.url.path.rsplit("/", 1)[-1]
        return Response(200, json={"book_title": title, "owner": "apiguard_a", "secret": "s"})

    respx.post(f"{BASE}/books/v1").mock(side_effect=post_books)
    respx.get(f"{BASE}/books/v1").mock(side_effect=list_books)
    respx.get(url__regex=rf"{BASE}/books/v1/.+").mock(side_effect=get_book)

    async def go():
        async with HttpEngine(rate_limit_per_s=0) as engine:
            disc = ResourceDiscoverer(engine, BASE, _sessions(), owner="userA")
            return await disc.discover(_endpoints())

    owned = asyncio.run(go())
    ids = {o.object_id: o for o in owned}
    # seeded object A created, plus the harvested A-owned 'other'
    assert "apiguard_userA_book_title" in ids
    assert ids["apiguard_userA_book_title"].source == "seed"
    assert "other" in ids and ids["other"].source == "harvest"
    # 'bookTitle36' belongs to name1, so it must NOT be attributed to A
    assert "bookTitle36" not in ids
    # every owned object carries A's own access evidence
    for o in owned:
        assert o.owner == "userA"
        assert o.a_access.response_status == 200
        assert o.object_endpoint.path == "/books/v1/{book_title}"


@respx.mock
def test_no_collection_means_no_harvest_no_crash():
    # Only an object endpoint, no collection GET/POST -> nothing discovered, no error.
    eps = [
        Endpoint(
            path="/books/v1/{book_title}", method="GET",
            parameters=[Parameter(name="book_title", location="path", type_="string", required=True)],
            request_body_schema=None, security=[],
        )
    ]
    respx.get(url__regex=rf"{BASE}/books/v1/.+").mock(return_value=Response(404, json={}))

    async def go():
        async with HttpEngine(rate_limit_per_s=0) as engine:
            return await ResourceDiscoverer(engine, BASE, _sessions()).discover(eps)

    assert asyncio.run(go()) == []
