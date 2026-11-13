"""Unit tests for API spec-driven security testing tools.

No live HTTP calls — httpx is monkeypatched.
"""

from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path
from typing import Any

import pytest

from buggy.tools.research import api_spec as asp

_SAMPLE_SPEC_V3 = {
    "openapi": "3.0.0",
    "info": {"title": "Test API", "version": "1.0.0"},
    "paths": {
        "/users/{userId}": {
            "get": {
                "operationId": "getUser",
                "summary": "Get a user by ID",
                "parameters": [
                    {
                        "name": "userId",
                        "in": "path",
                        "required": True,
                        "schema": {"type": "string"},
                    },
                ],
                "security": [{"bearerAuth": []}],
            },
            "put": {
                "operationId": "updateUser",
                "summary": "Update user profile",
                "parameters": [
                    {
                        "name": "userId",
                        "in": "path",
                        "required": True,
                        "schema": {"type": "string"},
                    },
                ],
                "requestBody": {
                    "required": True,
                    "content": {
                        "application/json": {
                            "schema": {
                                "type": "object",
                                "properties": {
                                    "name": {"type": "string"},
                                    "email": {"type": "string"},
                                    "role": {"type": "string"},
                                    "isAdmin": {"type": "boolean"},
                                },
                            }
                        }
                    },
                },
                "security": [{"bearerAuth": []}],
            },
            "delete": {
                "operationId": "deleteUser",
                "summary": "Delete user",
                "parameters": [
                    {
                        "name": "userId",
                        "in": "path",
                        "required": True,
                        "schema": {"type": "string"},
                    },
                ],
            },
        },
        "/public/health": {
            "get": {
                "operationId": "healthCheck",
                "summary": "Health check",
            },
        },
    },
    "components": {
        "securitySchemes": {
            "bearerAuth": {"type": "http", "scheme": "bearer"},
        }
    },
}


class TestSpecLoading:
    def test_load_json_file(self, tmp_path: Path) -> None:
        f = tmp_path / "spec.json"
        f.write_text(json.dumps(_SAMPLE_SPEC_V3))
        data, err = asp._load_spec(str(f))
        assert data is not None
        assert err == ""
        assert data["openapi"] == "3.0.0"

    def test_file_not_found(self) -> None:
        data, err = asp._load_spec("/nonexistent/spec.json")
        assert data is None
        assert "not found" in err.lower()


class TestParseOpenapiDocument:
    def test_returns_every_operation_without_io_or_mutation(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        spec = {
            "paths": {
                f"/resources/{index}": {
                    "get": {"operationId": f"getResource{index}", "tags": ["inventory"]}
                }
                for index in range(151)
            }
        }
        original = deepcopy(spec)

        def unexpected_io(*args: Any, **kwargs: Any) -> None:
            pytest.fail("parse_openapi_document must not perform file or network IO")

        monkeypatch.setattr(asp, "_load_spec", unexpected_io)
        monkeypatch.setattr(asp.httpx, "Client", unexpected_io)
        monkeypatch.setattr(Path, "read_text", unexpected_io)
        monkeypatch.setattr("builtins.open", unexpected_io)

        endpoints = asp.parse_openapi_document(spec)

        assert len(endpoints) == 151
        assert [ep["operation_id"] for ep in endpoints] == [
            f"getResource{index}" for index in range(151)
        ]
        assert set(endpoints[0]) == {
            "path",
            "method",
            "operation_id",
            "summary",
            "tags",
            "parameters",
            "auth_required",
            "request_body",
            "response_properties",
        }
        assert spec == original
        endpoints[0]["tags"].append("changed")
        assert spec == original

    @pytest.mark.parametrize(
        "spec",
        [
            None,
            [],
            "not a spec",
            42,
            {},
            {"paths": None},
            {"paths": []},
            {"paths": "not a paths object"},
            {"paths": {17: {"get": {}}}},
            {"paths": {"relative": {"get": {}}}},
            {"paths": {"/bad": []}},
            {"paths": {"/bad": None}},
            {"paths": {"/bad": {"get": []}}},
            {"paths": {"/bad": {"post": None}}},
            {"paths": {"/bad": {2: {}}}},
            {"paths": {}, "basePath": []},
            {"paths": {}, "info": []},
        ],
    )
    def test_rejects_malformed_root_and_paths(self, spec: Any) -> None:
        assert issubclass(asp.APISpecError, ValueError)
        with pytest.raises(asp.APISpecError) as exc:
            asp.parse_openapi_document(spec)
        assert str(exc.value)

    def test_empty_paths_are_a_valid_empty_inventory(self) -> None:
        assert asp.parse_openapi_document({"paths": {}}) == []

    def test_path_metadata_is_not_an_operation_and_trace_is_included(self) -> None:
        spec = {
            "paths": {
                "x-inventory": ["extension data"],
                "/health": {
                    "summary": "Health endpoint",
                    "description": "Path metadata",
                    "servers": [{"url": "https://example.invalid"}],
                    "parameters": [],
                    "x-extra": {"post": {}},
                    "get": {"operationId": "health"},
                    "trace": {"operationId": "traceHealth"},
                },
            }
        }
        endpoints = asp.parse_openapi_document(spec)
        assert [(ep["method"], ep["path"]) for ep in endpoints] == [
            ("GET", "/health"),
            ("TRACE", "/health"),
        ]

    @pytest.mark.parametrize(
        "operation",
        [
            {"operationId": []},
            {"summary": []},
            {"tags": None},
            {"tags": "inventory"},
            {"tags": [{}]},
            {"parameters": [{"name": "id", "in": "query", "schema": None}]},
            {"parameters": [{"name": "id", "in": "query", "required": "yes"}]},
            {"requestBody": None},
            {"requestBody": {"required": "yes"}},
            {"requestBody": {"content": []}},
            {"requestBody": {"content": {"application/json": None}}},
            {"requestBody": {"content": {"application/json": {"schema": None}}}},
            {"responses": None},
            {"responses": {"200": None}},
            {"responses": {"200": []}},
            {"responses": {"404": []}},
            {"responses": {"200": {"content": {0: {}}}}},
        ],
    )
    def test_malformed_inventory_fields_raise_named_errors(self, operation: Any) -> None:
        spec = {"paths": {"/resource": {"get": operation}}}
        with pytest.raises(asp.APISpecError):
            asp.parse_openapi_document(spec)

    @pytest.mark.parametrize(
        "spec",
        [
            {"paths": {}, "security": None},
            {"paths": {"/resource": {"parameters": None}}},
            {"paths": {}, "components": []},
        ],
    )
    def test_validates_shapes_even_without_operations(self, spec: dict[str, Any]) -> None:
        with pytest.raises(asp.APISpecError):
            asp.parse_openapi_document(spec)

    @pytest.mark.parametrize("field", ["components", "webhooks"])
    def test_accepts_openapi_31_documents_with_no_paths(self, field: str) -> None:
        spec = {
            "openapi": "3.1.0",
            "info": {"title": "Reusable API components", "version": "1.0"},
            field: {},
        }
        assert asp.parse_openapi_document(spec) == []


class TestOperationSecurity:
    def test_operation_security_overrides_root_including_empty_list(self, tmp_path: Path) -> None:
        spec = {
            "paths": {
                "/resource": {
                    "get": {},
                    "post": {"security": []},
                    "put": {"security": [{"operationAuth": []}]},
                    "delete": {"security": [{}]},
                }
            },
            "security": [{"rootAuth": ["read"]}],
        }
        original = deepcopy(spec)
        endpoints = asp.parse_openapi_document(spec)
        assert {ep["method"]: ep["auth_required"] for ep in endpoints} == {
            "GET": ["rootAuth"],
            "POST": [],
            "PUT": ["operationAuth"],
            "DELETE": [],
        }
        assert spec == original
        source = tmp_path / "security.json"
        source.write_text(json.dumps(spec))
        parsed = json.loads(asp.api_parse_openapi.invoke({"spec_source": str(source)}))
        assert parsed["endpoints"] == endpoints
        matrix = json.loads(asp.api_generate_test_matrix.invoke({"spec_source": str(source)}))
        assert [(test["endpoint"], test["test_type"]) for test in matrix["tests"]] == [
            ("GET /resource", "auth_bypass"),
            ("PUT /resource", "auth_bypass"),
            ("DELETE /resource", "missing_auth"),
        ]

    @pytest.mark.parametrize("level", ["root", "operation"])
    @pytest.mark.parametrize(
        "security", [None, {}, "bearerAuth", [None], [{"bearerAuth": "read"}], [{1: []}]]
    )
    def test_rejects_malformed_security(self, level: str, security: Any) -> None:
        spec = {"paths": {"/health": {"get": {}}}}
        container = spec if level == "root" else spec["paths"]["/health"]["get"]
        container["security"] = security
        with pytest.raises(asp.APISpecError, match="security"):
            asp.parse_openapi_document(spec)


class TestInheritedParameters:
    def test_inherits_and_overrides_parameters_by_name_and_location(self) -> None:
        spec = {
            "paths": {
                "/resources/{id}": {
                    "parameters": [
                        {"$ref": "#/components/parameters/resourceId"},
                        {"name": "id", "in": "query", "schema": {"type": "string"}},
                        {"name": "X-Tenant", "in": "header", "schema": {"type": "string"}},
                    ],
                    "get": {
                        "parameters": [
                            {"$ref": "#/components/parameters/resourceIdOverride"},
                            {
                                "name": "id",
                                "in": "query",
                                "required": True,
                                "schema": {"type": "integer"},
                            },
                            {"name": "filter", "in": "query", "schema": {"type": "string"}},
                        ]
                    },
                    "post": {"parameters": []},
                }
            },
            "components": {
                "parameters": {
                    "resourceId": {"name": "id", "in": "path", "required": True, "type": "string"},
                    "resourceIdOverride": {
                        "name": "id",
                        "in": "path",
                        "required": True,
                        "type": "integer",
                    },
                }
            },
        }
        original = deepcopy(spec)
        get_endpoint, post_endpoint = asp.parse_openapi_document(spec)
        assert get_endpoint["parameters"] == [
            {"name": "id", "in": "path", "required": True, "type": "integer"},
            {"name": "id", "in": "query", "required": True, "type": "integer"},
            {"name": "X-Tenant", "in": "header", "required": False, "type": "string"},
            {"name": "filter", "in": "query", "required": False, "type": "string"},
        ]
        assert post_endpoint["parameters"] == [
            {"name": "id", "in": "path", "required": True, "type": "string"},
            {"name": "id", "in": "query", "required": False, "type": "string"},
            {"name": "X-Tenant", "in": "header", "required": False, "type": "string"},
        ]
        assert spec == original

    def test_inherits_and_overrides_swagger_body_parameters(self) -> None:
        spec = {
            "swagger": "2.0",
            "basePath": "/v2",
            "paths": {
                "/resources": {
                    "parameters": [
                        {
                            "name": "payload",
                            "in": "body",
                            "schema": {
                                "type": "object",
                                "properties": {"name": {"type": "string"}},
                            },
                        }
                    ],
                    "post": {},
                    "put": {
                        "parameters": [
                            {
                                "name": "payload",
                                "in": "body",
                                "required": True,
                                "schema": {
                                    "type": "object",
                                    "properties": {"label": {"type": "string"}},
                                },
                            }
                        ]
                    },
                }
            },
        }
        post, put = asp.parse_openapi_document(spec)
        assert post["path"] == "/v2/resources"
        assert post["request_body"] == {
            "content_type": "application/json",
            "required": False,
            "schema_type": "object",
            "properties": ["name"],
        }
        assert put["request_body"] == {
            "content_type": "application/json",
            "required": True,
            "schema_type": "object",
            "properties": ["label"],
        }

    @pytest.mark.parametrize("level", ["path", "operation"])
    @pytest.mark.parametrize(
        "parameters",
        [
            None,
            {},
            "not parameters",
            [None],
            [{}],
            [{"name": [], "in": "query"}],
            [{"name": "id", "in": []}],
            [{"name": "id", "in": "query"}, {"name": "id", "in": "query"}],
        ],
    )
    def test_rejects_malformed_parameters(self, level: str, parameters: Any) -> None:
        spec = {"paths": {"/health": {"get": {}}}}
        path_item = spec["paths"]["/health"]
        container = path_item if level == "path" else path_item["get"]
        container["parameters"] = parameters
        with pytest.raises(asp.APISpecError, match="[Pp]arameter"):
            asp.parse_openapi_document(spec)


class TestLocalReferences:
    @pytest.mark.parametrize(
        ("ref", "expected"),
        [
            ("#/objects/a~1b", "slash"),
            ("#/objects/a~0b", "tilde"),
            ("#/objects/~01", "literal escape"),
            ("#/objects/space%20name", "space"),
            ("#/objects/a%7E1b", "slash"),
            ("#//name", "empty token"),
            ("#/items/0", "array item"),
        ],
    )
    def test_decodes_local_json_pointers_once(self, ref: str, expected: str) -> None:
        spec = {
            "objects": {
                "a/b": {"value": "slash"},
                "a~b": {"value": "tilde"},
                "~1": {"value": "literal escape"},
                "space name": {"value": "space"},
            },
            "": {"name": {"value": "empty token"}},
            "items": [{"value": "array item"}],
        }
        assert asp._resolve_ref(ref, spec) == {"value": expected}
        assert asp._resolve_ref("#", spec) == spec

    @pytest.mark.parametrize(
        "ref",
        [
            None,
            1,
            "",
            "objects/value",
            "/objects/value",
            "##/objects/value",
            "https://example.invalid/spec.json#/objects/value",
            "file:///private/spec.json#/objects/value",
            "#/objects/bad~2escape",
            "#/objects/bad%escape",
            "#/objects/%FF",
            "#/objects/missing",
            "#/objects/scalar",
            "#/items/-1",
            "#/items/01",
            "#/items/9",
        ],
    )
    def test_does_not_resolve_nonlocal_or_invalid_pointers(self, ref: Any) -> None:
        spec = {
            "objects": {
                "value": {},
                "bad~2escape": {},
                "bad%escape": {},
                "%FF": {},
                "scalar": 7,
            },
            "items": [{}],
        }
        assert asp._resolve_ref(ref, spec) is None

    def test_resolves_path_parameter_body_and_response_references(self) -> None:
        spec = {
            "paths": {"/items/{id}": {"$ref": "#/components/pathItems/Item~1Path"}},
            "components": {
                "pathItems": {
                    "Item/Path": {
                        "parameters": [{"$ref": "#/components/parameters/Item~0Id"}],
                        "get": {
                            "responses": {"200": {"$ref": "#/components/responses/OK%20Reply"}}
                        },
                        "post": {"requestBody": {"$ref": "#/components/requestBodies/Body"}},
                    }
                },
                "parameters": {
                    "Item~Id": {"name": "id", "in": "path", "required": True, "type": "string"}
                },
                "responses": {
                    "OK Reply": {
                        "content": {
                            "application/json": {"schema": {"$ref": "#/components/schemas/~01"}}
                        }
                    }
                },
                "requestBodies": {
                    "Body": {
                        "required": True,
                        "content": {
                            "application/json": {"schema": {"$ref": "#/components/schemas/~01"}}
                        },
                    }
                },
                "schemas": {"~1": {"type": "object", "properties": {"name": {"type": "string"}}}},
            },
        }
        original = deepcopy(spec)
        get_endpoint, post_endpoint = asp.parse_openapi_document(spec)
        assert get_endpoint["path"] == "/items/{id}"
        assert get_endpoint["parameters"] == [
            {"name": "id", "in": "path", "required": True, "type": "string"}
        ]
        assert get_endpoint["response_properties"] == ["name"]
        assert post_endpoint["request_body"] == {
            "content_type": "application/json",
            "required": True,
            "schema_type": "object",
            "properties": ["name"],
        }
        assert spec == original

    @pytest.mark.parametrize("target", ["missing", "cycle", "scalar"])
    def test_invalid_local_path_references_raise_named_errors(self, target: str) -> None:
        spec = {
            "paths": {"/items": {"$ref": f"#/components/pathItems/{target}"}},
            "components": {
                "pathItems": {
                    "cycle": {"$ref": "#/components/pathItems/cycle"},
                    "scalar": 3,
                }
            },
        }
        with pytest.raises(asp.APISpecError, match=r"\$ref"):
            asp.parse_openapi_document(spec)

    def test_keeps_declared_operations_without_fetching_external_references(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def unexpected_io(*args: Any, **kwargs: Any) -> None:
            pytest.fail("External references must not be fetched")

        monkeypatch.setattr(asp.httpx, "Client", unexpected_io)
        monkeypatch.setattr(Path, "read_text", unexpected_io)
        spec = {
            "paths": {
                "/items": {
                    "get": {
                        "parameters": [{"$ref": "https://example.invalid/parameters.json#/id"}],
                        "responses": {"200": {"$ref": "responses.json#/OK"}},
                    },
                    "post": {"requestBody": {"$ref": "file:///private/body.json"}},
                }
            }
        }
        get_endpoint, post_endpoint = asp.parse_openapi_document(spec)
        assert get_endpoint["parameters"] == []
        assert get_endpoint["response_properties"] == []
        assert post_endpoint["request_body"] is None


class TestExtractEndpoints:
    def test_extracts_all_endpoints(self) -> None:
        endpoints = asp._extract_endpoints(_SAMPLE_SPEC_V3)
        assert len(endpoints) == 4  # GET, PUT, DELETE /users/{userId} + GET /public/health
        methods = {ep["method"] for ep in endpoints}
        assert "GET" in methods
        assert "PUT" in methods
        assert "DELETE" in methods

    def test_extracts_params(self) -> None:
        endpoints = asp._extract_endpoints(_SAMPLE_SPEC_V3)
        get_user = next(ep for ep in endpoints if ep["operation_id"] == "getUser")
        assert len(get_user["parameters"]) == 1
        assert get_user["parameters"][0]["name"] == "userId"

    def test_extracts_auth(self) -> None:
        endpoints = asp._extract_endpoints(_SAMPLE_SPEC_V3)
        get_user = next(ep for ep in endpoints if ep["operation_id"] == "getUser")
        assert "bearerAuth" in get_user["auth_required"]

    def test_extracts_request_body(self) -> None:
        endpoints = asp._extract_endpoints(_SAMPLE_SPEC_V3)
        update_user = next(ep for ep in endpoints if ep["operation_id"] == "updateUser")
        assert update_user["request_body"] is not None
        assert "role" in update_user["request_body"]["properties"]
        assert "isAdmin" in update_user["request_body"]["properties"]


class TestBolaTests:
    def test_generates_bola_for_id_params(self) -> None:
        endpoints = asp._extract_endpoints(_SAMPLE_SPEC_V3)
        bola = asp._generate_bola_tests(endpoints)
        assert len(bola) >= 1
        assert all(t["test_type"] == "BOLA" for t in bola)


class TestMassAssignmentTests:
    def test_detects_sensitive_fields(self) -> None:
        endpoints = asp._extract_endpoints(_SAMPLE_SPEC_V3)
        mass = asp._generate_mass_assignment_tests(endpoints)
        assert len(mass) >= 1
        update_test = next(t for t in mass if "PUT /users" in str(t.get("endpoint", "")))
        assert "role" in update_test["sensitive_properties_detected"]
        assert "isAdmin" in update_test["sensitive_properties_detected"]


class TestAuthTests:
    def test_detects_missing_auth(self) -> None:
        endpoints = asp._extract_endpoints(_SAMPLE_SPEC_V3)
        auth = asp._generate_auth_tests(endpoints)
        # DELETE /users/{userId} has no security spec
        missing_auth = [t for t in auth if t["test_type"] == "missing_auth"]
        assert len(missing_auth) >= 1


class TestInventoryPagination:
    @pytest.mark.parametrize(
        ("tool_name", "items_key", "total_key"),
        [
            ("api_parse_openapi", "endpoints", "total_endpoints"),
            ("api_generate_test_matrix", "tests", "total_tests"),
        ],
    )
    def test_public_tools_page_all_operations(
        self, tmp_path: Path, tool_name: str, items_key: str, total_key: str
    ) -> None:
        spec = {
            "openapi": "3.0.0",
            "info": {"title": "Large API", "version": "1.0"},
            "security": [{"bearerAuth": []}],
            "paths": {
                f"/resources/{index}": {"get": {"operationId": f"getResource{index}"}}
                for index in range(237)
            },
        }
        source = tmp_path / "large.json"
        source.write_text(json.dumps(spec))
        public_tool = getattr(asp, tool_name)
        first_page = json.loads(public_tool.invoke({"spec_source": str(source)}))

        assert first_page[total_key] == 237
        assert len(first_page[items_key]) == 100
        assert first_page["returned_count"] == 100
        assert first_page["next_offset"] == 100
        assert first_page["has_more"] is True
        inventory = list(first_page[items_key])

        for offset, expected_count, next_offset in [(100, 100, 200), (200, 37, None)]:
            page = json.loads(
                public_tool.invoke({"spec_source": str(source), "offset": offset, "limit": 100})
            )
            assert page["total_endpoints"] == 237
            assert page[total_key] == 237
            assert len(page[items_key]) == expected_count
            assert page["returned_count"] == expected_count
            assert page["next_offset"] == next_offset
            assert page["has_more"] is (next_offset is not None)
            inventory.extend(page[items_key])

        identifiers = [item.get("path", item.get("endpoint")) for item in inventory]
        prefix = "GET " if items_key == "tests" else ""
        assert identifiers == [f"{prefix}/resources/{index}" for index in range(237)]
        if items_key == "tests":
            assert first_page["by_type"] == {
                "bola_idor": 0,
                "mass_assignment": 0,
                "auth_bypass": 237,
            }

    @pytest.mark.parametrize("tool_name", ["api_parse_openapi", "api_generate_test_matrix"])
    @pytest.mark.parametrize(
        ("argument", "value"),
        [
            ("offset", -1),
            ("offset", True),
            ("offset", 1.5),
            ("offset", "1"),
            ("offset", None),
            ("limit", 0),
            ("limit", -1),
            ("limit", 1001),
            ("limit", True),
            ("limit", 1.5),
            ("limit", "100"),
            ("limit", None),
        ],
    )
    def test_rejects_invalid_page_arguments_before_loading(
        self, monkeypatch: pytest.MonkeyPatch, tool_name: str, argument: str, value: Any
    ) -> None:
        def unexpected_load(*args: Any, **kwargs: Any) -> None:
            pytest.fail("Invalid pagination must be rejected before loading a spec")

        monkeypatch.setattr(asp, "_load_spec", unexpected_load)
        with pytest.raises(ValueError):
            getattr(asp, tool_name).invoke({"spec_source": "unused.json", argument: value})

    @pytest.mark.parametrize(
        ("tool_name", "items_key", "total_key"),
        [
            ("api_parse_openapi", "endpoints", "total_endpoints"),
            ("api_generate_test_matrix", "tests", "total_tests"),
        ],
    )
    def test_page_boundaries_and_full_counts(
        self, tmp_path: Path, tool_name: str, items_key: str, total_key: str
    ) -> None:
        spec = {
            "security": [{"token": []}],
            "paths": {f"/items/{index}": {"get": {}} for index in range(1003)},
        }
        source = tmp_path / "boundaries.json"
        source.write_text(json.dumps(spec))
        public_tool = getattr(asp, tool_name)
        for offset, limit, expected_count, next_offset in [
            (0, 1, 1, 1),
            (0, 1000, 1000, 1000),
            (3, 1000, 1000, None),
            (1000, 1000, 3, None),
            (1003, 100, 0, None),
            (1004, 100, 0, None),
        ]:
            page = json.loads(
                public_tool.invoke({"spec_source": str(source), "offset": offset, "limit": limit})
            )
            assert page[total_key] == 1003
            assert page["total_endpoints"] == 1003
            assert len(page[items_key]) == page["returned_count"] == expected_count
            assert page["next_offset"] == next_offset
            assert page["has_more"] is (next_offset is not None)
            if items_key == "tests":
                assert page["by_type"]["auth_bypass"] == 1003

        source.write_text(json.dumps({"paths": {}}))
        page = json.loads(public_tool.invoke({"spec_source": str(source)}))
        assert page[total_key] == page["returned_count"] == 0
        assert page[items_key] == []
        assert page["next_offset"] is None
        assert page["has_more"] is False

    def test_matrix_paginates_after_global_ranking(self, tmp_path: Path) -> None:
        source = tmp_path / "ranked.json"
        source.write_text(json.dumps(_SAMPLE_SPEC_V3))
        public_tool = asp.api_generate_test_matrix
        full = json.loads(public_tool.invoke({"spec_source": str(source), "limit": 1000}))
        collected = []
        offset = 0
        while offset is not None:
            page = json.loads(
                public_tool.invoke({"spec_source": str(source), "offset": offset, "limit": 2})
            )
            assert page["total_endpoints"] == full["total_endpoints"]
            assert page["total_tests"] == full["total_tests"]
            assert page["by_type"] == full["by_type"]
            collected.extend(page["tests"])
            offset = page["next_offset"]
        assert collected == full["tests"]


class TestPublicSpecValidation:
    @pytest.mark.parametrize("tool_name", ["api_parse_openapi", "api_generate_test_matrix"])
    @pytest.mark.parametrize(
        "text",
        [
            "",
            "null",
            "[]",
            "17",
            "{}",
            '{"paths": []}',
            '{"paths": {"/ok": {"get": {}}, "/bad": {"get": []}}}',
            "paths: [unterminated",
        ],
    )
    def test_invalid_documents_return_errors_not_partial_inventory(
        self, tmp_path: Path, tool_name: str, text: str
    ) -> None:
        source = tmp_path / "invalid-spec"
        source.write_text(text)
        result = json.loads(getattr(asp, tool_name).invoke({"spec_source": str(source)}))
        assert result["error"] in {"spec_load_failed", "spec_parse_failed"}
        assert result["detail"]
        assert "endpoints" not in result
        assert "tests" not in result

    @pytest.mark.parametrize("format_name", ["json", "yaml"])
    @pytest.mark.parametrize("version", ["2.0", "3.0.0"])
    def test_preserves_valid_json_and_yaml_specs(
        self, tmp_path: Path, format_name: str, version: str
    ) -> None:
        spec = deepcopy(_SAMPLE_SPEC_V3)
        if version == "2.0":
            spec = {
                "swagger": "2.0",
                "info": {"title": "Swagger API", "version": "1.0"},
                "basePath": "/v2",
                "paths": {
                    "/items/{id}": {
                        "get": {
                            "parameters": [{"name": "id", "in": "path", "type": "string"}],
                            "responses": {
                                200: {
                                    "schema": {
                                        "type": "object",
                                        "properties": {"name": {"type": "string"}},
                                    }
                                }
                            },
                        }
                    }
                },
            }
        if format_name == "yaml":
            yaml = pytest.importorskip("yaml")
            text = yaml.safe_dump(spec, sort_keys=False)
        else:
            text = json.dumps(spec)
        source = tmp_path / f"spec.{format_name}"
        source.write_text(text)
        result = json.loads(asp.api_parse_openapi.invoke({"spec_source": str(source)}))
        assert result["title"] == spec["info"]["title"]
        assert result["version"] == spec["info"]["version"]
        assert result["openapi_version"] == version
        assert result["endpoints"] == asp.parse_openapi_document(spec)
        assert result["total_endpoints"] == result["returned_count"]
        if version == "2.0":
            assert result["endpoints"][0]["path"] == "/v2/items/{id}"
            assert result["endpoints"][0]["response_properties"] == ["name"]


class TestApiParseOpenapi:
    def test_parses_spec(self, tmp_path: Path) -> None:
        f = tmp_path / "spec.json"
        f.write_text(json.dumps(_SAMPLE_SPEC_V3))
        result = json.loads(asp.api_parse_openapi.invoke({"spec_source": str(f)}))
        assert result["title"] == "Test API"
        assert result["total_endpoints"] == 4

    def test_bad_file(self) -> None:
        result = json.loads(asp.api_parse_openapi.invoke({"spec_source": "/nonexistent"}))
        assert result["error"] == "spec_load_failed"


class TestApiGenerateTestMatrix:
    def test_generates_tests(self, tmp_path: Path) -> None:
        f = tmp_path / "spec.json"
        f.write_text(json.dumps(_SAMPLE_SPEC_V3))
        result = json.loads(asp.api_generate_test_matrix.invoke({"spec_source": str(f)}))
        assert result["total_tests"] > 0
        assert result["by_type"]["bola_idor"] >= 1
        assert result["by_type"]["mass_assignment"] >= 1
        # Tests should be sorted by severity
        severities = [t["severity"] for t in result["tests"]]
        sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        assert all(
            sev_order.get(a, 5) <= sev_order.get(b, 5) for a, b in zip(severities, severities[1:])
        )
