"""BOLA engine — discovery + cross-access (BRAIN.md D19-D20). THE CROWN JEWEL.

Phase 1 (D19) establishes object IDs that *provably belong to User A*, two ways:

* seed — POST to a collection as A to create an object A owns;
* harvest — GET the collection as A and keep items whose owner field equals A's
  username.

For each owned ID it captures A's own successful access (the `a_access`
evidence) — the baseline the Day-20 cross-access phase compares against.
"""

from __future__ import annotations

import json
from dataclasses import dataclass

from apiguard.core.http_engine import HttpEngine, _example_from_schema, build_request
from apiguard.core.identity import Session
from apiguard.core.models import Endpoint, Evidence


@dataclass
class OwnedObject:
    """An object provably owned by the owner session, with A's own access."""

    object_endpoint: Endpoint
    id_param: str
    object_id: str
    owner: str  # session name, e.g. "userA"
    source: str  # "seed" | "harvest"
    a_access: Evidence


def _path_params(endpoint: Endpoint) -> list[str]:
    return [p.name for p in endpoint.parameters if p.location == "path"]


def _collection_path(object_path: str) -> str:
    # "/books/v1/{book_title}" -> "/books/v1"
    return object_path.rsplit("/{", 1)[0]


def _find_list(payload: object) -> list:
    """Return the first list in a JSON payload (the collection items)."""
    if isinstance(payload, list):
        return payload
    if isinstance(payload, dict):
        for value in payload.values():
            if isinstance(value, list):
                return value
    return []


def _item_owned_by(item: object, username: str) -> bool:
    return isinstance(item, dict) and any(
        isinstance(v, str) and v == username for v in item.values()
    )


async def _object_access(
    engine: HttpEngine, base_url: str, obj_ep: Endpoint, id_param: str, object_id: str, headers: dict
):
    """GET a single object by id, with the given auth headers. Shared by discovery
    and cross-access so both build the identical request."""
    method, url, req_headers, query, body = build_request(
        obj_ep, base_url.rstrip("/"), values={id_param: object_id}, headers=headers
    )
    return await engine.send(method, url, headers=req_headers, params=query, body=body)


class ResourceDiscoverer:
    """Finds objects provably owned by a user, by seeding (POST) and harvesting (owner-field match)."""

    def __init__(
        self, engine: HttpEngine, base_url: str, sessions: dict[str, Session], *, owner: str = "userA"
    ) -> None:
        self._engine = engine
        self._base = base_url.rstrip("/")
        self._sessions = sessions
        self._owner_name = owner

    def _owner_session(self) -> Session | None:
        return self._sessions.get(self._owner_name) or next(iter(self._sessions.values()), None)

    async def discover(self, endpoints: list[Endpoint]) -> list[OwnedObject]:
        owner = self._owner_session()
        if owner is None:
            return []
        headers = dict(owner.headers)
        username = owner.username

        owned: list[OwnedObject] = []
        for obj_ep in self._object_endpoints(endpoints):
            id_param = _path_params(obj_ep)[-1]
            collection = _collection_path(obj_ep.path)

            ids: dict[str, str] = {}  # id -> source
            seeded = await self._seed(collection, id_param, endpoints, headers)
            if seeded is not None:
                ids[seeded] = "seed"
            for hid in await self._harvest(collection, id_param, endpoints, headers, username):
                ids.setdefault(hid, "harvest")

            for object_id, source in ids.items():
                access = await self._get_object(obj_ep, id_param, object_id, headers)
                if access.status < 400:
                    owned.append(
                        OwnedObject(
                            object_endpoint=obj_ep,
                            id_param=id_param,
                            object_id=object_id,
                            owner=self._owner_name,
                            source=source,
                            a_access=access.evidence,
                        )
                    )
        return owned

    @staticmethod
    def _object_endpoints(endpoints: list[Endpoint]) -> list[Endpoint]:
        # A GET whose path ends in a single {id} segment is an object endpoint.
        result = []
        for ep in endpoints:
            if ep.method.upper() != "GET":
                continue
            if _path_params(ep) and ep.path.rstrip("/").endswith("}"):
                result.append(ep)
        return result

    async def _seed(self, collection: str, id_param: str, endpoints, headers) -> str | None:
        post = next(
            (
                e
                for e in endpoints
                if e.method.upper() == "POST"
                and e.path == collection
                and e.request_body_schema is not None
            ),
            None,
        )
        if post is None:
            return None
        body = _example_from_schema(post.request_body_schema)
        if not isinstance(body, dict):
            return None
        # Fill unconstrained string fields with owner-distinctive values so the
        # seeded object carries data identifiable as THIS owner's — a cross-user
        # read then clearly leaks the other user's data (sharpens the BOLA signal).
        props = (post.request_body_schema or {}).get("properties", {})
        for field, spec in props.items():
            if isinstance(spec, dict) and spec.get("type") == "string" and not spec.get("format"):
                body[field] = f"apiguard-{self._owner_name}-{field}"
        object_id = f"apiguard_{self._owner_name}_{id_param}"
        body[id_param] = object_id
        exchange = await self._engine.send(
            "POST", f"{self._base}{collection}", headers=headers, json_body=body
        )
        return object_id if exchange.status < 400 else None

    async def _harvest(self, collection: str, id_param: str, endpoints, headers, username) -> list[str]:
        get = next(
            (e for e in endpoints if e.method.upper() == "GET" and e.path == collection), None
        )
        if get is None:
            return []
        exchange = await self._engine.send("GET", f"{self._base}{collection}", headers=headers)
        try:
            payload = json.loads(exchange.evidence.response_body)
        except ValueError:
            return []
        ids = []
        for item in _find_list(payload):
            if isinstance(item, dict) and id_param in item and _item_owned_by(item, username):
                ids.append(str(item[id_param]))
        return ids

    async def _get_object(self, obj_ep: Endpoint, id_param: str, object_id: str, headers):
        return await _object_access(self._engine, self._base, obj_ep, id_param, object_id, headers)


# --------------------------------------------------------------------------- #
# Cross-access phase (BRAIN.md D20)
# --------------------------------------------------------------------------- #
@dataclass
class AccessTriple:
    """The three responses the BOLA gate/oracle compares (Section 5).

    * a_access      — A accessing A's own object (the reference for what the data is).
    * b_cross_access — the attacker (B) accessing A's object (the potential leak).
    * b_control     — B accessing B's OWN object at the same endpoint (a legitimate
      access baseline; None if B owns nothing of that type).
    """

    object_endpoint: Endpoint
    a_object_id: str
    a_access: Evidence
    b_cross_access: Evidence
    b_control: Evidence | None


async def probe_cross_access(
    engine: HttpEngine,
    base_url: str,
    sessions: dict[str, Session],
    owned_a: list[OwnedObject],
    owned_b: list[OwnedObject],
    *,
    attacker: str = "userB",
) -> list[AccessTriple]:
    """For each A-owned object, have the attacker (B) access it, plus a B-owned
    control at the same endpoint. Produces (A, B-cross, B-control) triples."""
    attacker_session = sessions.get(attacker) or next(iter(sessions.values()), None)
    if attacker_session is None:
        return []
    attacker_headers = dict(attacker_session.headers)
    base = base_url.rstrip("/")

    # A B-owned object per endpoint path, for controls.
    b_by_path: dict[str, OwnedObject] = {}
    for owned in owned_b:
        b_by_path.setdefault(owned.object_endpoint.path, owned)

    triples: list[AccessTriple] = []
    for oa in owned_a:
        cross = await _object_access(
            engine, base, oa.object_endpoint, oa.id_param, oa.object_id, attacker_headers
        )
        control_ev: Evidence | None = None
        b_obj = b_by_path.get(oa.object_endpoint.path)
        if b_obj is not None:
            control = await _object_access(
                engine, base, b_obj.object_endpoint, b_obj.id_param, b_obj.object_id, attacker_headers
            )
            control_ev = control.evidence
        triples.append(
            AccessTriple(
                object_endpoint=oa.object_endpoint,
                a_object_id=oa.object_id,
                a_access=oa.a_access,
                b_cross_access=cross.evidence,
                b_control=control_ev,
            )
        )
    return triples


async def collect_triples(
    engine: HttpEngine,
    base_url: str,
    sessions: dict[str, Session],
    endpoints: list[Endpoint],
    *,
    owner: str = "userA",
    attacker: str = "userB",
) -> list[AccessTriple]:
    """Full D19+D20: discover owner's objects and attacker's controls, then probe."""
    owned_a = await ResourceDiscoverer(engine, base_url, sessions, owner=owner).discover(endpoints)
    owned_b = await ResourceDiscoverer(engine, base_url, sessions, owner=attacker).discover(endpoints)
    return await probe_cross_access(
        engine, base_url, sessions, owned_a, owned_b, attacker=attacker
    )
