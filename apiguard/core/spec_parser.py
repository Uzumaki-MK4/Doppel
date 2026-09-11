"""OpenAPI spec -> list[Endpoint] (BRAIN.md D3).

Two entry points, deliberately split:

* `load_spec(source)` is async — it scope-guards the host (invariant 7), fetches
  over `httpx` (invariant 8) or reads a file, validates the document with
  `openapi-spec-validator`, and resolves internal `$ref`s.
* `parse_spec(spec)` is a pure function turning the resolved dict into
  `Endpoint` models. It never touches the network, so it is unit-testable from a
  plain dict and `respx` only needs to mock the fetch.

Ref resolution is a small internal JSON-Pointer resolver (see BRAIN.md Section 9
for why we did not use the library resolver): OpenAPI refs are internal
`#/...` pointers, and this is simpler and fully testable.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import httpx
import yaml
from openapi_spec_validator import validate as _validate_openapi

from apiguard.core.models import Endpoint, Parameter
from apiguard.core.scope import ScopeGuard

# OpenAPI operation keys inside a path item (everything else is metadata).
_HTTP_METHODS: tuple[str, ...] = (
    "get", "put", "post", "delete", "patch", "head", "options", "trace",
)


# --------------------------------------------------------------------------- #
# Loading
# --------------------------------------------------------------------------- #
def _looks_like_url(source: str) -> bool:
    return source.startswith(("http://", "https://"))


def _loads(text: str) -> Any:
    """Parse spec text as JSON, falling back to YAML."""
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return yaml.safe_load(text)


async def load_spec(
    source: str,
    *,
    allowlist: list[str] | None = None,
    confirm_authorized: bool = False,
    engine: object | None = None,
) -> dict:
    """Fetch/read, validate, and dereference an OpenAPI spec into a dict.

    If `engine` (an HttpEngine) is given, the fetch goes through it so it is
    recorded/replayed with the rest of the scan (cassettes); otherwise a
    one-shot client is used.
    """
    if _looks_like_url(source):
        ScopeGuard(allowlist).check(source, confirm_authorized=confirm_authorized)
        if engine is not None:
            exchange = await engine.send("GET", source)
            if exchange.status >= 400:
                raise ValueError(f"Spec fetch returned HTTP {exchange.status} for {source!r}")
            text = exchange.response.text
        else:
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.get(source)
                resp.raise_for_status()
                text = resp.text
    else:
        text = Path(source).read_text(encoding="utf-8")

    spec = _loads(text)
    if not isinstance(spec, dict):
        raise ValueError("Spec did not parse to a JSON/YAML object.")
    _validate_openapi(spec)  # raises on an invalid OpenAPI document
    return _deref(spec, spec)


# --------------------------------------------------------------------------- #
# Internal $ref resolution
# --------------------------------------------------------------------------- #
def _resolve_pointer(root: dict, ref: str) -> Any:
    """Resolve a local JSON Pointer like '#/components/parameters/IdParam'."""
    if not ref.startswith("#/"):
        raise ValueError(f"Only internal '#/...' refs are supported, got: {ref!r}")
    node: Any = root
    for raw in ref[2:].split("/"):
        key = raw.replace("~1", "/").replace("~0", "~")  # JSON Pointer unescape
        node = node[int(key)] if isinstance(node, list) else node[key]
    return node


def _deref(node: Any, root: dict, _seen: frozenset[str] = frozenset()) -> Any:
    """Recursively resolve internal $refs. Cycle-guarded for recursive schemas."""
    if isinstance(node, dict):
        ref = node.get("$ref")
        if isinstance(ref, str):
            if ref in _seen:
                return {"$ref": ref}  # cycle: stop, leave a shallow marker
            return _deref(_resolve_pointer(root, ref), root, _seen | {ref})
        return {key: _deref(value, root, _seen) for key, value in node.items()}
    if isinstance(node, list):
        return [_deref(item, root, _seen) for item in node]
    return node


# --------------------------------------------------------------------------- #
# Parsing (pure)
# --------------------------------------------------------------------------- #
def _security_names(security: Any) -> list[str]:
    """OpenAPI security is a list of {schemeName: [scopes]}; return the names."""
    if not security:
        return []
    names: list[str] = []
    for requirement in security:
        if isinstance(requirement, dict):
            names.extend(requirement.keys())
    return list(dict.fromkeys(names))  # de-dupe, preserve order


def _request_body_schema(request_body: Any) -> dict | None:
    """Return the (already dereferenced) request-body schema, JSON preferred."""
    if not isinstance(request_body, dict):
        return None
    content = request_body.get("content") or {}
    for ctype in ("application/json", *content.keys()):
        media = content.get(ctype)
        if isinstance(media, dict) and isinstance(media.get("schema"), dict):
            return media["schema"]
    return None


def _to_parameter(raw: dict) -> Parameter:
    schema = raw.get("schema") or {}
    return Parameter(
        name=raw.get("name", ""),
        location=raw.get("in", "query"),
        type_=schema.get("type", "string"),
        format_=schema.get("format"),
        required=bool(raw.get("required", False)),
        example=raw.get("example", schema.get("example")),
    )


def parse_spec(spec: dict) -> list[Endpoint]:
    """Turn a resolved OpenAPI dict into a flat list of Endpoint models."""
    global_security = _security_names(spec.get("security"))
    endpoints: list[Endpoint] = []
    paths = spec.get("paths") or {}

    for path, path_item in paths.items():
        if not isinstance(path_item, dict):
            continue
        shared = [p for p in path_item.get("parameters", []) if isinstance(p, dict)]
        for method in _HTTP_METHODS:
            operation = path_item.get(method)
            if not isinstance(operation, dict):
                continue
            op_params = [p for p in operation.get("parameters", []) if isinstance(p, dict)]
            parameters = [_to_parameter(p) for p in (*shared, *op_params)]
            # A missing operation-level `security` inherits the global default;
            # an explicit empty list means "no auth", so distinguish None.
            if operation.get("security") is None:
                security = global_security
            else:
                security = _security_names(operation["security"])
            endpoints.append(
                Endpoint(
                    path=path,
                    method=method.upper(),
                    parameters=parameters,
                    request_body_schema=_request_body_schema(operation.get("requestBody")),
                    security=security,
                    operation_id=operation.get("operationId"),
                )
            )
    return endpoints
