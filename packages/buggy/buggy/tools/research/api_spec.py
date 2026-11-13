"""API spec-driven security testing — OpenAPI/Swagger parsing + test gen.

Parses OpenAPI v2 (Swagger) and v3 specs to enumerate endpoints,
parameters, and auth schemes, then generates test matrices for
BOLA/BFLA, mass assignment, and boundary violations. Pure Python —
uses ``json`` / ``yaml``-compatible parsing (no external binary).
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Annotated, Any
from urllib.parse import unquote

import httpx
from langchain_core.tools import tool
from pydantic import Field

from buggy_core.utils.logging import get_logger

log = get_logger("research.api_spec")

_TIMEOUT = 15.0


# ── Spec loading ─────────────────────────────────────────────────────────


def _load_spec(source: str) -> tuple[dict[str, Any] | None, str]:
    """Load an OpenAPI spec from a file path or URL. Returns (data, error)."""
    try:
        if source.startswith("http://") or source.startswith("https://"):
            with httpx.Client(
                timeout=_TIMEOUT,
                follow_redirects=True,
            ) as client:
                resp = client.get(source)
            if resp.status_code != 200:
                return None, f"HTTP {resp.status_code} fetching spec"
            text = resp.text
        else:
            path = Path(source)
            if not path.is_file():
                return None, f"File not found: {source}"
            text = path.read_text()

        # Try JSON first, then YAML-like
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            # Minimal YAML-like parsing for common OpenAPI specs
            # (avoids adding pyyaml dependency)
            try:
                import yaml  # type: ignore[import-untyped]  # noqa: PLC0415

            except ImportError:
                return None, "Spec is YAML but pyyaml is not installed — convert to JSON"
            try:
                data = yaml.safe_load(text)
            except yaml.YAMLError as exc:
                return None, f"Invalid YAML: {exc}"
        if not isinstance(data, dict):
            return None, "Spec root must be an object"
        return data, ""
    except (httpx.HTTPError, OSError, UnicodeError) as exc:
        return None, str(exc)


# ── Spec parsing ─────────────────────────────────────────────────────────


class APISpecError(ValueError):
    """An OpenAPI document has malformed inventory data."""


def _require_object(value: Any, location: str) -> dict[str, Any]:
    """Validate an object before inspecting its inventory fields."""
    if not isinstance(value, dict):
        raise APISpecError(f"{location} must be an object")
    return value


def parse_openapi_document(spec: dict[str, Any]) -> list[dict[str, Any]]:
    """Return every OpenAPI v2/v3 operation without IO or input mutation.

    Raises APISpecError for malformed document, path, or operation shapes.
    The returned list is complete and unpaginated, in document order, with
    the same endpoint fields exposed by api_parse_openapi. Only local JSON
    Pointer references are resolved; external metadata is not fetched.
    """
    spec = _require_object(spec, "Spec root")
    for field in ("info", "components", "webhooks"):
        _require_object(spec.get(field, {}), field)
    paths = spec.get("paths")
    version = spec.get("openapi", "")
    if (
        "paths" not in spec
        and isinstance(version, str)
        and re.match(r"3\.[1-9][0-9]*\.", version)
        and ("components" in spec or "webhooks" in spec)
    ):
        paths = {}
    paths = _require_object(paths, "paths")
    _extract_auth({}, spec)
    base_path = spec.get("basePath", "")  # v2
    if not isinstance(base_path, str):
        raise APISpecError("basePath must be a string")
    endpoints: list[dict[str, Any]] = []

    for path, methods in paths.items():
        if not isinstance(path, str):
            raise APISpecError("Path names must be strings")
        if path.startswith("x-"):
            continue
        if not path.startswith("/"):
            raise APISpecError(f"Path {path!r} must start with '/'")
        methods = _require_object(methods, f"Path {path!r}")
        resolved_methods = _resolve_object(methods, spec, f"Path {path!r}")
        methods = {
            **(resolved_methods or {}),
            **{key: value for key, value in methods.items() if key != "$ref"},
        }
        inherited = {"parameters": _merge_parameters(methods, {}, spec)}
        full_path = base_path + path if base_path else path
        for method, op in methods.items():
            if not isinstance(method, str):
                raise APISpecError(f"Path {path!r} field names must be strings")
            if method.lower() in (
                "get",
                "post",
                "put",
                "patch",
                "delete",
                "head",
                "options",
                "trace",
            ):
                op = _require_object(op, f"Operation {method.upper()} {path}")
                for field in ("operationId", "summary"):
                    if not isinstance(op.get(field, ""), str):
                        raise APISpecError(f"Operation {field} must be a string")
                tags = op.get("tags", [])
                if not isinstance(tags, list) or not all(isinstance(tag, str) for tag in tags):
                    raise APISpecError("Operation tags must be an array of strings")
                op = {**op, "parameters": _merge_parameters(inherited, op, spec)}
                params = _extract_params(op, spec)
                auth = _extract_auth(op, spec)
                endpoints.append(
                    {
                        "path": full_path,
                        "method": method.upper(),
                        "operation_id": op.get("operationId", ""),
                        "summary": str(op.get("summary", ""))[:200],
                        "tags": list(tags),
                        "parameters": params,
                        "auth_required": auth,
                        "request_body": _extract_request_body(op, spec),
                        "response_properties": _extract_response_properties(op, spec),
                    }
                )
    return endpoints


def _extract_endpoints(spec: dict[str, Any]) -> list[dict[str, Any]]:
    """Extract endpoints through the reusable, IO-free document parser."""
    return parse_openapi_document(spec)


def _merge_parameters(
    path_item: dict[str, Any], op: dict[str, Any], spec: dict[str, Any]
) -> list[dict[str, Any]]:
    """Merge inherited parameters, replacing operation-level (name, in) matches."""
    merged: dict[tuple[str, str], dict[str, Any]] = {}
    for owner in (path_item, op):
        parameters = owner.get("parameters", [])
        if not isinstance(parameters, list):
            raise APISpecError("parameters must be an array")
        seen: set[tuple[str, str]] = set()
        for parameter in parameters:
            parameter = _resolve_object(parameter, spec, "Parameter")
            if parameter is None:
                continue
            name, location = parameter.get("name"), parameter.get("in")
            if (
                not isinstance(name, str)
                or not name
                or not isinstance(location, str)
                or not location
            ):
                raise APISpecError("Parameters must have nonempty string name and in fields")
            if not isinstance(parameter.get("required", False), bool):
                raise APISpecError("Parameter required must be a boolean")
            key = (name, location)
            if key in seen:
                raise APISpecError(f"Duplicate parameter {name!r} in {location!r}")
            seen.add(key)
            merged[key] = parameter
    return list(merged.values())


def _extract_params(op: dict[str, Any], spec: dict[str, Any]) -> list[dict[str, Any]]:
    """Extract parameters from an operation."""
    params: list[dict[str, Any]] = []
    for p in op.get("parameters", []):
        if "$ref" in p:
            p = _resolve_ref(p["$ref"], spec) or p
        params.append(
            {
                "name": p.get("name", ""),
                "in": p.get("in", ""),
                "required": p.get("required", False),
                "type": _param_type(p),
            }
        )
    return params


def _param_type(p: dict[str, Any]) -> str:
    """Get parameter type string."""
    if "schema" in p:
        schema = _require_object(p["schema"], "Parameter schema")
        return str(schema.get("type", schema.get("$ref", "object")))
    return str(p.get("type", "string"))


def _extract_auth(op: dict[str, Any], spec: dict[str, Any]) -> list[str]:
    """Extract auth requirements, respecting explicit operation overrides."""
    security = op["security"] if "security" in op else spec.get("security", [])
    if not isinstance(security, list):
        raise APISpecError("security must be an array")
    schemes: list[str] = []
    for sec in security:
        sec = _require_object(sec, "security requirement")
        for name, scopes in sec.items():
            if not isinstance(name, str) or not isinstance(scopes, list):
                raise APISpecError("security requirements must map scheme names to scope arrays")
            if not all(isinstance(scope, str) for scope in scopes):
                raise APISpecError("security scopes must be strings")
            schemes.append(name)
    return schemes


def _extract_request_body(op: dict[str, Any], spec: dict[str, Any]) -> dict[str, Any] | None:
    """Extract request body schema (v3) or inherited body parameter (v2)."""
    if "requestBody" in op:
        rb = _resolve_object(op["requestBody"], spec, "requestBody")
        if rb is not None:
            if not isinstance(rb.get("required", False), bool):
                raise APISpecError("requestBody required must be a boolean")
            content = _require_object(rb.get("content", {}), "requestBody content")
            for ct, schema_info in content.items():
                schema_info = _require_object(schema_info, "requestBody media type")
                schema = (
                    _resolve_object(schema_info.get("schema", {}), spec, "requestBody schema") or {}
                )
                props = _require_object(schema.get("properties", {}), "requestBody properties")
                return {
                    "content_type": ct,
                    "required": rb.get("required", False),
                    "schema_type": schema.get("type", "object"),
                    "properties": list(props.keys())[:20],
                }
    # v2 body param
    for p in op.get("parameters", []):
        if p.get("in") == "body" and "schema" in p:
            schema = _resolve_object(p["schema"], spec, "Body parameter schema") or {}
            props = _require_object(schema.get("properties", {}), "Body parameter properties")
            return {
                "content_type": "application/json",
                "required": p.get("required", False),
                "schema_type": schema.get("type", "object"),
                "properties": list(props.keys())[:20],
            }
    return None


def _resolve_ref(ref: str, spec: dict[str, Any]) -> dict[str, Any] | None:
    """Resolve one local JSON Pointer without fetching external references."""
    if not isinstance(ref, str) or not ref.startswith("#"):
        return None
    if ref == "#":
        return spec
    fragment = ref[1:]
    if re.search(r"%(?![0-9a-fA-F]{2})", fragment):
        return None
    try:
        pointer = unquote(fragment, errors="strict")
    except UnicodeError:
        return None
    if not pointer.startswith("/"):
        return None
    obj: Any = spec
    for token in pointer[1:].split("/"):
        if re.search(r"~(?:[^01]|$)", token):
            return None
        part = token.replace("~1", "/").replace("~0", "~")
        if isinstance(obj, dict):
            obj = obj.get(part)
        elif isinstance(obj, list) and re.fullmatch(r"0|[1-9][0-9]*", part):
            try:
                index = int(part)
            except ValueError:
                return None
            obj = obj[index] if index < len(obj) else None
        else:
            return None
    return obj if isinstance(obj, dict) else None


def _resolve_object(value: Any, spec: dict[str, Any], location: str) -> dict[str, Any] | None:
    """Resolve local reference chains, rejecting broken or cyclic pointers.

    External references remain unresolved; callers omit unavailable metadata
    rather than fetching it or inventing parameters or operations.
    """
    obj = _require_object(value, location)
    seen: set[int] = set()
    overrides: dict[str, Any] = {}
    while "$ref" in obj:
        if id(obj) in seen:
            raise APISpecError(f"{location} has a cyclic $ref")
        seen.add(id(obj))
        ref = obj["$ref"]
        if not isinstance(ref, str) or not ref:
            raise APISpecError(f"{location} $ref must be a nonempty string")
        if not ref.startswith("#"):
            return None
        overrides = {**{key: value for key, value in obj.items() if key != "$ref"}, **overrides}
        resolved = _resolve_ref(ref, spec)
        if resolved is None:
            raise APISpecError(f"{location} has an invalid or unresolved local $ref: {ref}")
        obj = resolved
    return {**obj, **overrides}


def _extract_response_properties(op: dict[str, Any], spec: dict[str, Any]) -> list[str]:
    """Extract response schema property names for the 200 response."""
    responses = _require_object(op.get("responses", {}), "responses")
    for code, response in responses.items():
        if isinstance(code, str) and code.startswith("x-"):
            continue
        _require_object(response, "Response")
    ok_resp = (
        responses.get("200")
        or responses.get(200)
        or responses.get("201")
        or responses.get(201)
        or {}
    )
    ok_resp = _resolve_object(ok_resp, spec, "Response") or {}
    # OpenAPI v3: content -> application/json -> schema -> properties
    content = _require_object(ok_resp.get("content", {}), "Response content")
    for ct, media in content.items():
        if not isinstance(ct, str):
            raise APISpecError("Response content types must be strings")
        media = _require_object(media, "Response media type")
        if "json" in ct:
            schema = _resolve_object(media.get("schema", {}), spec, "Response schema") or {}
            props = _require_object(schema.get("properties", {}), "Response properties")
            if props:
                return list(props.keys())[:30]
    # OpenAPI v2: schema -> properties
    schema = _resolve_object(ok_resp.get("schema", {}), spec, "Response schema") or {}
    props = _require_object(schema.get("properties", {}), "Response properties")
    if props:
        return list(props.keys())[:30]
    return []


# ── Test matrix generation ───────────────────────────────────────────────


def _generate_bola_tests(endpoints: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Generate BOLA/IDOR test cases for endpoints with ID parameters."""
    id_pattern = re.compile(r"(?i)(id|uuid|user_?id|account_?id|org_?id|resource_?id)")
    tests: list[dict[str, Any]] = []
    for ep in endpoints:
        id_params = [
            p for p in ep["parameters"] if id_pattern.search(p["name"]) or p.get("in") == "path"
        ]
        if id_params and ep["method"] in ("GET", "PUT", "PATCH", "DELETE"):
            tests.append(
                {
                    "test_type": "BOLA",
                    "endpoint": f"{ep['method']} {ep['path']}",
                    "id_params": [p["name"] for p in id_params],
                    "description": "Replace ID param with another user's ID to test horizontal privilege escalation",
                    "severity": "high",
                }
            )
    return tests


def _generate_mass_assignment_tests(endpoints: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Generate mass assignment test cases for endpoints with request bodies."""
    sensitive_fields = re.compile(
        r"(?i)(role|admin|is_?admin|privilege|permission|balance|credit|status|verified|active)"
    )
    tests: list[dict[str, Any]] = []
    for ep in endpoints:
        if ep["method"] in ("POST", "PUT", "PATCH") and ep.get("request_body"):
            props = ep["request_body"].get("properties", [])
            sensitive = [p for p in props if sensitive_fields.search(p)]
            tests.append(
                {
                    "test_type": "mass_assignment",
                    "endpoint": f"{ep['method']} {ep['path']}",
                    "known_properties": props[:10],
                    "sensitive_properties_detected": sensitive,
                    "description": "Add extra fields (role, isAdmin, etc.) to request body",
                    "severity": "high" if sensitive else "medium",
                }
            )
    return tests


def _generate_auth_tests(endpoints: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Generate auth bypass test cases."""
    tests: list[dict[str, Any]] = []
    for ep in endpoints:
        if ep["auth_required"]:
            tests.append(
                {
                    "test_type": "auth_bypass",
                    "endpoint": f"{ep['method']} {ep['path']}",
                    "auth_schemes": ep["auth_required"],
                    "description": "Send request without auth token to test enforcement",
                    "severity": "critical",
                }
            )
        if ep["method"] in ("PUT", "PATCH", "DELETE") and not ep["auth_required"]:
            tests.append(
                {
                    "test_type": "missing_auth",
                    "endpoint": f"{ep['method']} {ep['path']}",
                    "description": "State-changing endpoint has no auth requirement in spec",
                    "severity": "critical",
                }
            )
    return tests


def _json(data: Any) -> str:
    return json.dumps(data, indent=2, default=str)


def _inventory_page(
    items: list[dict[str, Any]], key: str, offset: int, limit: int
) -> dict[str, Any]:
    """Return one bounded inventory page with continuation metadata."""
    page = items[offset : offset + limit]
    next_offset = offset + len(page)
    has_more = next_offset < len(items)
    return {
        key: page,
        "returned_count": len(page),
        "next_offset": next_offset if has_more else None,
        "has_more": has_more,
    }


# ── @tool wrappers ───────────────────────────────────────────────────────


@tool
def api_parse_openapi(
    spec_source: str,
    offset: Annotated[int, Field(strict=True, ge=0)] = 0,
    limit: Annotated[int, Field(strict=True, ge=1, le=1000)] = 100,
) -> str:
    """Parse an OpenAPI/Swagger spec and return a page of endpoints.

    Accepts a file path or URL to an OpenAPI v2 (Swagger) or v3 spec
    (JSON or YAML). Returns endpoints with methods, parameters,
    auth requirements, and request body schemas. Offset must be a
    nonnegative integer and limit an integer from 1 to 1000 (default 100).
    Totals cover the full inventory; use next_offset while has_more is true
    to retrieve subsequent pages and understand the complete API surface.
    """
    spec, error = _load_spec(spec_source)
    if spec is None:
        return _json({"error": "spec_load_failed", "detail": error})

    try:
        endpoints = parse_openapi_document(spec)
    except APISpecError as exc:
        return _json({"error": "spec_parse_failed", "detail": str(exc)})
    info = spec.get("info", {})

    return _json(
        {
            "title": info.get("title", ""),
            "version": info.get("version", ""),
            "openapi_version": spec.get("openapi", spec.get("swagger", "")),
            "total_endpoints": len(endpoints),
            **_inventory_page(endpoints, "endpoints", offset, limit),
        }
    )


@tool
def api_generate_test_matrix(
    spec_source: str,
    offset: Annotated[int, Field(strict=True, ge=0)] = 0,
    limit: Annotated[int, Field(strict=True, ge=1, le=1000)] = 100,
) -> str:
    """Generate a security test matrix from an OpenAPI spec.

    Analyses the spec and generates test cases for:
    - **BOLA/IDOR**: endpoints with ID parameters → horizontal priv-esc
    - **Mass assignment**: endpoints with request bodies → extra field injection
    - **Auth bypass**: endpoints with/without auth → enforcement testing
    - **Missing auth**: state-changing endpoints without auth requirements

    Returns a page of ranked test cases with descriptions and severity.
    Offset must be a nonnegative integer and limit an integer from 1 to 1000
    (default 100). Counts cover the full matrix; follow next_offset while
    has_more is true to retrieve the remaining tests.
    """
    spec, error = _load_spec(spec_source)
    if spec is None:
        return _json({"error": "spec_load_failed", "detail": error})

    try:
        endpoints = parse_openapi_document(spec)
    except APISpecError as exc:
        return _json({"error": "spec_parse_failed", "detail": str(exc)})
    bola = _generate_bola_tests(endpoints)
    mass_assign = _generate_mass_assignment_tests(endpoints)
    auth = _generate_auth_tests(endpoints)

    all_tests = bola + mass_assign + auth
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    all_tests.sort(key=lambda x: severity_order.get(x.get("severity", "low"), 4))

    return _json(
        {
            "total_endpoints": len(endpoints),
            "total_tests": len(all_tests),
            "by_type": {
                "bola_idor": len(bola),
                "mass_assignment": len(mass_assign),
                "auth_bypass": len(auth),
            },
            **_inventory_page(all_tests, "tests", offset, limit),
        }
    )


@tool
def api_detect_undocumented(base_url: str, spec_source: str) -> str:
    """Discover undocumented API fields by comparing live responses to spec.

    Fetches each GET endpoint in the spec and compares the response JSON
    keys against the documented schema properties. Extra fields may
    indicate mass-assignment vectors or information disclosure.
    """
    spec, error = _load_spec(spec_source)
    if spec is None:
        return _json({"error": "spec_load_failed", "detail": error})

    endpoints = _extract_endpoints(spec)
    get_endpoints = [ep for ep in endpoints if ep["method"] == "GET"][:20]

    findings: list[dict[str, Any]] = []
    try:
        with httpx.Client(
            timeout=_TIMEOUT,
            follow_redirects=True,
        ) as client:
            for ep in get_endpoints:
                path = ep["path"]
                # Skip paths with path params (we can't substitute)
                if "{" in path:
                    continue
                url = f"{base_url.rstrip('/')}{path}"
                try:
                    resp = client.get(url)
                    if resp.status_code == 200:
                        try:
                            body = resp.json()
                        except ValueError:
                            continue
                        if isinstance(body, dict):
                            live_keys = set(body.keys())
                            documented_keys = set(ep.get("response_properties", []))
                            extra = live_keys - documented_keys if documented_keys else live_keys
                            if extra:
                                findings.append(
                                    {
                                        "endpoint": f"GET {path}",
                                        "documented_fields": sorted(documented_keys),
                                        "undocumented_fields": sorted(extra),
                                        "severity": "medium",
                                    }
                                )
                except httpx.HTTPError:
                    continue
    except httpx.HTTPError as exc:
        return _json({"error": "request_failed", "detail": str(exc)})

    return _json(
        {
            "base_url": base_url,
            "endpoints_checked": len(get_endpoints),
            "endpoints_with_undocumented_fields": len(findings),
            "findings": findings,
        }
    )


API_SPEC_TOOLS = [api_parse_openapi, api_generate_test_matrix, api_detect_undocumented]
