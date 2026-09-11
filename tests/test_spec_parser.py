"""Tests for apiguard.core.spec_parser and apiguard.core.scope (Day 3)."""

import asyncio

import pytest
import respx
from httpx import Response

from apiguard.core.scope import ScopeError, ScopeGuard
from apiguard.core.spec_parser import _deref, load_spec, parse_spec

# A small, valid OpenAPI 3.0 document with a shared path param, a query param
# (with a format), an operation-level security requirement, and a request body.
INLINE_SPEC = {
    "openapi": "3.0.0",
    "info": {"title": "t", "version": "1.0.0"},
    "paths": {
        "/x/{id}": {
            "parameters": [
                {"name": "id", "in": "path", "required": True, "schema": {"type": "integer"}}
            ],
            "get": {
                "operationId": "get_x",
                "parameters": [
                    {"name": "q", "in": "query", "schema": {"type": "string", "format": "email"}}
                ],
                "security": [{"bearerAuth": []}],
                "responses": {"200": {"description": "ok"}},
            },
            "post": {
                "operationId": "make_x",
                "requestBody": {
                    "content": {
                        "application/json": {
                            "schema": {"type": "object", "properties": {"a": {"type": "string"}}}
                        }
                    }
                },
                "responses": {"200": {"description": "ok"}},
            },
        }
    },
    "components": {"securitySchemes": {"bearerAuth": {"type": "http", "scheme": "bearer"}}},
}

# Same operation but the parameter is behind an internal $ref.
REF_SPEC = {
    "openapi": "3.0.0",
    "info": {"title": "t", "version": "1.0.0"},
    "paths": {
        "/x/{id}": {
            "get": {
                "parameters": [{"$ref": "#/components/parameters/IdParam"}],
                "responses": {"200": {"description": "ok"}},
            }
        }
    },
    "components": {
        "parameters": {
            "IdParam": {"name": "id", "in": "path", "required": True, "schema": {"type": "integer"}}
        }
    },
}


def test_parse_spec_inline():
    endpoints = {(e.method, e.path): e for e in parse_spec(INLINE_SPEC)}
    assert set(endpoints) == {("GET", "/x/{id}"), ("POST", "/x/{id}")}

    get = endpoints[("GET", "/x/{id}")]
    params = {p.name: p for p in get.parameters}
    assert params["id"].location == "path" and params["id"].type_ == "integer" and params["id"].required
    assert params["q"].location == "query" and params["q"].format_ == "email"
    assert get.security == ["bearerAuth"]
    assert get.request_body_schema is None
    assert get.operation_id == "get_x"

    post = endpoints[("POST", "/x/{id}")]
    assert post.request_body_schema == {"type": "object", "properties": {"a": {"type": "string"}}}
    # POST inherits the (empty) global security -> no auth required.
    assert post.security == []


def test_deref_resolves_internal_ref():
    resolved = _deref(REF_SPEC, REF_SPEC)
    param = resolved["paths"]["/x/{id}"]["get"]["parameters"][0]
    assert param == {"name": "id", "in": "path", "required": True, "schema": {"type": "integer"}}

    endpoints = parse_spec(resolved)
    assert len(endpoints) == 1
    assert endpoints[0].parameters[0].name == "id"
    assert endpoints[0].parameters[0].location == "path"


def test_scope_localhost_allowed():
    assert ScopeGuard().check("http://localhost:5000/openapi.json") == "localhost"
    assert ScopeGuard().check("http://127.0.0.1:5000/x") == "127.0.0.1"


def test_scope_nonlocal_requires_allowlist_and_flag():
    guard = ScopeGuard(allowlist=["localhost", "127.0.0.1", "example.com"])
    # In allowlist but non-localhost: needs the flag.
    with pytest.raises(ScopeError):
        guard.check("http://example.com/x")
    assert guard.check("http://example.com/x", confirm_authorized=True) == "example.com"
    # Not in allowlist: refused even with the flag.
    with pytest.raises(ScopeError):
        guard.check("http://evil.example/x", confirm_authorized=True)


@respx.mock
def test_load_spec_over_http_then_parse():
    respx.get("http://localhost:5000/openapi.json").mock(
        return_value=Response(200, json=INLINE_SPEC)
    )
    loaded = asyncio.run(load_spec("http://localhost:5000/openapi.json"))
    methods = {(e.method, e.path) for e in parse_spec(loaded)}
    assert ("GET", "/x/{id}") in methods


def test_load_spec_blocks_out_of_scope_host():
    # Non-localhost host without authorization must never reach the network.
    with pytest.raises(ScopeError):
        asyncio.run(load_spec("http://evil.example/openapi.json"))
