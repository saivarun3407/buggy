"""Exercise metadata-only context sources through an offline, read-only driver seam."""

from __future__ import annotations

import builtins
import hashlib
import importlib
import importlib.util
import inspect
import io
import json
import os
import socket
import subprocess
import sys
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any, NoReturn, Self, get_type_hints

import pytest

from buggy.context_export import ContextExportError, graph_source, skill_source

DISPLAY = "local-review_1"
SCOPE = "tenant-17.graph"
OTHER = "tenant-elsewhere"
SENTINEL = "SYNTHETIC-PRIVATE-SENTINEL-74e1"
KINDS = "Host Service Endpoint Finding Vulnerability CVE Misconfiguration Weakness".split()
SENSITIVE = "Credential Secret Session User Account".split()
FIELDS = "engagement id kind cve_id cwe_id severity status host port protocol".split()


def node(**changes: Any) -> dict[str, Any]:
    return {
        "labels": ["Host"],
        "engagement": SCOPE,
        "key": "node-1",
        "cve": "CVE-2025-12345",
        "cwe": "CWE-79",
        "severity": "high",
        "status": "open",
        "hostname": "api.example.test",
        "port": 443,
        "protocol": "https",
    } | changes


def row(**changes: Any) -> dict[str, Any]:
    return {
        "engagement": SCOPE,
        "id": "node-1",
        "kind": "Host",
        "cve_id": "CVE-2025-12345",
        "cwe_id": "CWE-79",
        "severity": "high",
        "status": "open",
        "host": "api.example.test",
        "port": 443,
        "protocol": "https",
    } | changes


def coalesce(record: dict[str, Any], *keys: str) -> Any:
    return next((record[key] for key in keys if record.get(key) is not None), None)


class ReadOnlyDriver:
    def __init__(
        self,
        nodes: list[dict[str, Any]] | None = None,
        *,
        responses: list[Any] | None = None,
    ) -> None:
        self.nodes = nodes or []
        self.responses = responses
        self.requests: list[tuple[str, dict[str, Any]]] = []
        self.writes = 0

    def session(self, *, database: str) -> Self:
        assert database == "offline"
        return self

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *args: Any) -> None:
        pass

    def execute_read(self, operation: Callable[[ReadOnlyDriver], Any]) -> Any:
        return operation(self)

    def execute_write(self, *args: Any, **kwargs: Any) -> NoReturn:
        self.writes += 1
        raise AssertionError("The metadata collector must never execute writes")

    def run(self, cypher: str, **params: Any) -> Any:
        self.requests.append((cypher, params))
        query = " ".join(cypher.split())
        assert "MATCH (n {engagement: $engagement})" in query
        assert "any(kind IN $safe_kinds WHERE kind IN labels(n))" in query
        assert "none(kind IN $excluded_kinds WHERE kind IN labels(n))" in query
        assert params["safe_kinds"] == KINDS
        assert params["excluded_kinds"] == SENSITIVE
        assert type(params["max_rows"]) is int and 1 <= params["max_rows"] <= 1000
        if self.responses is not None:
            response = self.responses[len(self.requests) - 1]
            if isinstance(response, Exception):
                raise response
            return response
        selected = [
            record
            for record in self.nodes
            if record["engagement"] == params["engagement"]
            and any(kind in record["labels"] for kind in KINDS)
            and not any(kind in record["labels"] for kind in SENSITIVE)
        ]
        if "RETURN count(n) AS total" in query:
            return [{"total": len(selected)}]
        assert "ORDER BY kind, id, elementId(n) LIMIT $max_rows" in query
        projected = [
            {
                "engagement": record["engagement"],
                "id": record.get("key"),
                "kind": next(kind for kind in KINDS if kind in record["labels"]),
                "cve_id": coalesce(record, "cve_id", "cve"),
                "cwe_id": coalesce(record, "cwe_id", "cwe"),
                "severity": record.get("severity"),
                "status": record.get("status"),
                "host": coalesce(record, "hostname", "ip", "host"),
                "port": record.get("port"),
                "protocol": record.get("protocol"),
            }
            for record in selected
        ]
        return sorted(projected, key=lambda item: (item["kind"], item["id"]))[: params["max_rows"]]


class MetadataMessage:
    def __init__(self, tool_calls: Any) -> None:
        self.tool_calls = tool_calls

    @property
    def content(self) -> NoReturn:
        raise AssertionError("Message content must not be inspected")

    @property
    def additional_kwargs(self) -> NoReturn:
        raise AssertionError("Arbitrary message kwargs must not be inspected")

    @property
    def reasoning(self) -> NoReturn:
        raise AssertionError("Message reasoning must not be inspected")

    @property
    def response_metadata(self) -> NoReturn:
        raise AssertionError("Only public tool_calls may be inspected")


def request(value: Any) -> dict[str, Any]:
    return {"name": "load_skill", "args": {"name_or_path": value}, "id": "synthetic-call"}


@pytest.fixture(autouse=True)
def forbid_network_and_processes(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    attempts: list[str] = []

    def forbidden(*args: Any, **kwargs: Any) -> NoReturn:
        attempts.append(" -> ".join(frame.function for frame in inspect.stack(context=0)[:12]))
        raise AssertionError("Sources must not start processes or use the network")

    for owner, attribute in (
        (socket, "socket"),
        (socket, "create_connection"),
        (socket, "getaddrinfo"),
        (subprocess, "Popen"),
        (subprocess, "run"),
        (os, "system"),
        (os, "popen"),
    ):
        monkeypatch.setattr(owner, attribute, forbidden)
    yield
    assert attempts == []


@pytest.fixture
def make_store(monkeypatch: pytest.MonkeyPatch) -> Callable[[ReadOnlyDriver], Any]:
    source = Path(inspect.getfile(graph_source)).parent / "middleware/kg_internal/store.py"
    spec = importlib.util.spec_from_file_location("_context_export_test_kgstore", source)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, spec.name, module)
    spec.loader.exec_module(module)

    def factory(driver: ReadOnlyDriver) -> Any:
        config = module.KGStoreConfig(
            uri="bolt://offline.invalid:7687",
            user="synthetic",
            password="synthetic-not-a-credential",
            database="offline",
        )
        return module.KGStore(config, driver=driver)

    return factory


def graph_row(make_store: Callable[[ReadOnlyDriver], Any], record: dict[str, Any]) -> dict:
    driver = ReadOnlyDriver(responses=[[{"total": 1}], [record]])
    result = graph_source(make_store(driver), engagement=DISPLAY, graph_scope=SCOPE)
    assert result["status"] == "ok"
    assert result["total"] == 1
    assert driver.writes == 0
    return result["data"][0]


def test_public_api_requires_explicit_scope_and_annotations() -> None:
    assert issubclass(ContextExportError, ValueError)
    for function in (graph_source, skill_source):
        signature = inspect.signature(function)
        assert set(get_type_hints(function)) == set(signature.parameters) | {"return"}
        assert signature.parameters["max_rows"].default == 1000
        assert signature.parameters["max_rows"].kind is inspect.Parameter.KEYWORD_ONLY
    signature = inspect.signature(graph_source)
    assert list(signature.parameters) == ["store", "engagement", "graph_scope", "max_rows"]
    for parameter in ("engagement", "graph_scope"):
        assert signature.parameters[parameter].default is inspect.Parameter.empty
        assert signature.parameters[parameter].kind is inspect.Parameter.KEYWORD_ONLY
    assert list(inspect.signature(skill_source).parameters) == [
        "engagement",
        "messages",
        "max_rows",
    ]
    with pytest.raises(TypeError):
        signature.bind(object(), engagement=DISPLAY)
    with pytest.raises(TypeError):
        signature.bind(object(), graph_scope=SCOPE)


def test_composite_graph_scope_renders_under_the_selected_display_engagement(make_store):
    from buggy.sandbox_kernel.context_snapshot import render_snapshot

    source = graph_source(
        make_store(ReadOnlyDriver([node()])), engagement=DISPLAY, graph_scope=SCOPE
    )
    snapshot = render_snapshot(DISPLAY, {"findings": source})
    assert snapshot["engagement"] == DISPLAY
    assert snapshot["source_status"]["findings"] == "ok"
    assert SCOPE not in snapshot["markdown"]


def test_fixed_queries_bind_partition_and_exclude_unrelated_and_sensitive_nodes(
    make_store: Callable[[ReadOnlyDriver], Any],
) -> None:
    nodes = [
        node(key="record-b"),
        node(key="record-a", labels=["CVE", "Host", "CustomTag"]),
        node(engagement=OTHER, key=SENTINEL + "-other"),
        node(labels=["Credential"], key=SENTINEL + "-credential"),
        node(labels=["CustomTag"], key=SENTINEL + "-unknown"),
    ] + [node(labels=["Host", label], key=SENTINEL + label) for label in SENSITIVE]
    driver = ReadOnlyDriver(nodes)
    store = make_store(driver)
    result = graph_source(store, engagement=OTHER, graph_scope=SCOPE, max_rows=1)
    assert result["engagement"] == OTHER
    assert result["status"] == "ok"
    assert result["total"] == 2
    assert len(result["data"]) == 1
    assert result["data"][0]["engagement"] == OTHER
    assert result["data"][0]["id"] == "sha256:" + hashlib.sha256(b"record-a").hexdigest()
    assert SENTINEL not in json.dumps(result)
    assert len(driver.requests) == 2
    count_query, count_params = driver.requests[0]
    row_query, row_params = driver.requests[1]
    assert count_query.split("RETURN")[0] == row_query.split("RETURN")[0]
    assert count_params == row_params
    assert count_params["engagement"] == SCOPE
    assert count_params["max_rows"] == 1
    for query in (count_query, row_query):
        assert SCOPE not in query and OTHER not in query
        for forbidden in ("properties(n)", "n.title", "n.description", "n.password", "n.command"):
            assert forbidden not in query
    for projection in (
        "n.engagement AS engagement",
        "n.key AS id",
        "head([kind IN $safe_kinds WHERE kind IN labels(n)]) AS kind",
        "coalesce(n.cve_id, n.cve) AS cve_id",
        "coalesce(n.cwe_id, n.cwe) AS cwe_id",
        "coalesce(n.hostname, n.ip, n.host) AS host",
        "n.severity AS severity",
        "n.status AS status",
        "n.port AS port",
        "n.protocol AS protocol",
    ):
        assert projection in row_query
    store.execute_read(count_query, count_params | {"engagement": OTHER}, engagement=SCOPE)
    assert driver.requests[-1][1]["engagement"] == SCOPE
    assert driver.writes == 0


@pytest.mark.parametrize("kind", KINDS)
def test_each_safe_kind_is_projected_without_raw_labels(
    make_store: Callable[[ReadOnlyDriver], Any], kind: str
) -> None:
    driver = ReadOnlyDriver([node(labels=[kind])])
    result = graph_source(make_store(driver), engagement=DISPLAY, graph_scope=SCOPE)
    assert result["status"] == "ok"
    assert set(result["data"][0]) == set(FIELDS)
    assert result["data"][0]["kind"] == kind
    assert driver.writes == 0


def test_default_limit_retains_total_and_uses_stable_order(
    make_store: Callable[[ReadOnlyDriver], Any],
) -> None:
    driver = ReadOnlyDriver([node(key=f"node-{index:04}") for index in reversed(range(1002))])
    result = graph_source(make_store(driver), engagement=DISPLAY, graph_scope=SCOPE)
    assert result["status"] == "ok"
    assert result["total"] == 1002
    assert len(result["data"]) == 1000
    assert result["data"][0]["id"] == "sha256:" + hashlib.sha256(b"node-0000").hexdigest()
    assert result["data"][-1]["id"] == "sha256:" + hashlib.sha256(b"node-0999").hexdigest()
    assert driver.requests[-1][1]["max_rows"] == 1000
    assert driver.writes == 0


def test_successful_zero_count_is_distinct_from_failed_or_missing_queries(
    make_store: Callable[[ReadOnlyDriver], Any],
) -> None:
    driver = ReadOnlyDriver()
    result = graph_source(make_store(driver), engagement=DISPLAY, graph_scope=SCOPE)
    assert result == {"engagement": DISPLAY, "status": "ok", "total": 0, "data": []}
    assert len(driver.requests) == 2
    assert driver.writes == 0


@pytest.mark.parametrize(
    "count_response",
    [
        [],
        [{}],
        [{"count": 0}],
        [{"total": True}],
        [{"total": -1}],
        [{"total": 1.0}],
        [{"total": "1"}],
        [{"total": 0}, {"total": 1}],
        None,
    ],
)
def test_missing_or_malformed_counts_fail_closed(
    make_store: Callable[[ReadOnlyDriver], Any], count_response: Any
) -> None:
    driver = ReadOnlyDriver(responses=[count_response])
    result = graph_source(make_store(driver), engagement=DISPLAY, graph_scope=SCOPE)
    assert result == {
        "engagement": DISPLAY,
        "status": "error",
        "total": 0,
        "data": [],
        "error_code": "graph_read_failed",
    }
    assert len(driver.requests) == 1
    assert driver.writes == 0


@pytest.mark.parametrize("rows", [[], None, [{}], [SENTINEL]])
def test_positive_count_with_empty_or_malformed_rows_is_an_error(
    make_store: Callable[[ReadOnlyDriver], Any], rows: Any
) -> None:
    driver = ReadOnlyDriver(responses=[[{"total": 3}], rows])
    result = graph_source(make_store(driver), engagement=DISPLAY, graph_scope=SCOPE)
    assert result == {
        "engagement": DISPLAY,
        "status": "error",
        "total": 3,
        "data": [],
        "error_code": "graph_read_failed",
    }
    assert driver.writes == 0


@pytest.mark.parametrize(("total", "max_rows"), [(0, 2), (1, 2), (2, 1)])
def test_rows_exceeding_count_or_limit_are_not_trusted(
    make_store: Callable[[ReadOnlyDriver], Any], total: int, max_rows: int
) -> None:
    driver = ReadOnlyDriver(responses=[[{"total": total}], [row(), row(id="node-2")]])
    result = graph_source(
        make_store(driver), engagement=DISPLAY, graph_scope=SCOPE, max_rows=max_rows
    )
    assert result["status"] == "error" and result["data"] == []
    assert result["total"] == total
    assert result["error_code"] == "graph_read_failed"
    assert driver.writes == 0


def test_best_effort_rows_can_be_fewer_than_count_without_claiming_atomicity(
    make_store: Callable[[ReadOnlyDriver], Any],
) -> None:
    driver = ReadOnlyDriver(responses=[[{"total": 3}], [row()]])
    result = graph_source(make_store(driver), engagement=DISPLAY, graph_scope=SCOPE)
    assert result["status"] == "ok" and result["total"] == 3
    assert len(result["data"]) == 1
    assert set(result) == {"engagement", "status", "total", "data"}
    assert driver.writes == 0


@pytest.mark.parametrize(
    "changes",
    [
        {"engagement": OTHER},
        {"engagement": None},
        {"kind": "Credential"},
        {"kind": "Unknown"},
        {"kind": None},
        {"kind": ["Host", "Secret"]},
        {"labels": ["Host", "Secret"]},
        {"labels": ["Host"]},
    ],
)
def test_wrong_scope_or_label_metadata_discards_the_entire_result(
    make_store: Callable[[ReadOnlyDriver], Any], changes: dict[str, Any]
) -> None:
    driver = ReadOnlyDriver(responses=[[{"total": 2}], [row(), row(id=SENTINEL, **changes)]])
    result = graph_source(make_store(driver), engagement=DISPLAY, graph_scope=SCOPE)
    assert result["status"] == "error" and result["data"] == []
    assert result["error_code"] == "graph_read_failed"
    assert SENTINEL not in json.dumps(result)
    assert driver.writes == 0


@pytest.mark.parametrize("failure_after_count", [False, True])
def test_backend_errors_never_expose_exception_strings_or_partial_data(
    make_store: Callable[[ReadOnlyDriver], Any],
    failure_after_count: bool,
    caplog: pytest.LogCaptureFixture,
    capsys: pytest.CaptureFixture[str],
) -> None:
    string_attempts: list[str] = []

    class BackendError(RuntimeError):
        def __str__(self) -> str:
            string_attempts.append("stringified")
            return SENTINEL

    responses = ([[{"total": 7}]] if failure_after_count else []) + [BackendError(SENTINEL)]
    driver = ReadOnlyDriver(responses=responses)
    result = graph_source(make_store(driver), engagement=DISPLAY, graph_scope=SCOPE)
    assert result == {
        "engagement": DISPLAY,
        "status": "error",
        "total": 7 if failure_after_count else 0,
        "data": [],
        "error_code": "graph_read_failed",
    }
    assert string_attempts == []
    captured = capsys.readouterr()
    assert SENTINEL not in json.dumps(result) + caplog.text + captured.out + captured.err
    assert driver.writes == 0


def test_backend_projection_extras_cannot_escape(
    make_store: Callable[[ReadOnlyDriver], Any],
) -> None:
    extras = dict.fromkeys(
        "password secret title description command body evidence reasoning user account session".split(),
        SENTINEL,
    ) | {"properties": {"password": SENTINEL}}
    record = row(id=SENTINEL) | extras
    result = graph_row(make_store, record)
    assert set(result) == set(FIELDS)
    assert result["id"] == "sha256:" + hashlib.sha256(SENTINEL.encode()).hexdigest()
    assert SENTINEL not in json.dumps(result)
    assert record == row(id=SENTINEL) | extras


@pytest.mark.parametrize(
    ("field", "value", "expected"),
    [
        ("cve_id", "CVE-2025-12345", "CVE-2025-12345"),
        ("cwe_id", "CWE-79", "CWE-79"),
        ("cve_id", "cve-2025-12345", None),
        ("cve_id", "CVE-2025-123", None),
        ("cve_id", "CVE-2025-12345\n", None),
        ("cve_id", "CVE-２０２５-12345", None),
        ("cve_id", "CVE-2025-" + "1" * 20, None),
        ("cwe_id", "CWE-0", None),
        ("cwe_id", "CWE-079", None),
        ("cwe_id", "CWE-79/" + SENTINEL, None),
        ("cwe_id", {"value": SENTINEL}, None),
    ],
)
def test_cve_and_cwe_fields_have_strict_bounded_patterns(
    make_store: Callable[[ReadOnlyDriver], Any], field: str, value: Any, expected: Any
) -> None:
    assert graph_row(make_store, row(**{field: value}))[field] == expected


@pytest.mark.parametrize(
    ("field", "value"),
    [("severity", value) for value in "critical high medium low informational".split()]
    + [
        ("status", value)
        for value in "open confirmed suspected validated resolved mitigated accepted closed false_positive unconfirmed".split()
    ]
    + [("protocol", value) for value in "tcp udp http https tls ssh dns icmp icmpv6 sctp".split()],
)
def test_enum_metadata_is_allowlisted(
    make_store: Callable[[ReadOnlyDriver], Any], field: str, value: str
) -> None:
    assert graph_row(make_store, row(**{field: value}))[field] == value


@pytest.mark.parametrize(
    "field", ["severity", "status", "protocol", "id", "cve_id", "cwe_id", "host", "port"]
)
def test_arbitrary_objects_are_not_stringified(
    make_store: Callable[[ReadOnlyDriver], Any], field: str
) -> None:
    attempts: list[str] = []

    class PrivateValue:
        def __str__(self) -> str:
            attempts.append("stringified")
            return SENTINEL

    result = graph_row(make_store, row(**{field: PrivateValue()}))
    assert result[field] is None
    assert attempts == []
    assert SENTINEL not in json.dumps(result)


@pytest.mark.parametrize("field", ["severity", "status", "protocol"])
def test_unknown_enum_strings_become_null(
    make_store: Callable[[ReadOnlyDriver], Any], field: str
) -> None:
    assert graph_row(make_store, row(**{field: SENTINEL}))[field] is None


@pytest.mark.parametrize(
    ("host", "expected"),
    [
        ("API.Example.Test.", "api.example.test"),
        ("localhost", "localhost"),
        ("192.0.2.10", "192.0.2.10"),
        ("2001:0DB8::1", "2001:db8::1"),
        ("::1", "::1"),
    ],
)
def test_dns_and_ip_hosts_are_validated_without_resolution(
    make_store: Callable[[ReadOnlyDriver], Any], host: str, expected: str
) -> None:
    assert graph_row(make_store, row(host=host))["host"] == expected


@pytest.mark.parametrize(
    "host",
    [
        "https://api.example.test/" + SENTINEL,
        "api.example.test/path",
        "api.example.test?secret=" + SENTINEL,
        "api.example.test#fragment",
        SENTINEL + "@api.example.test",
        "api.example.test:443",
        "fe80::1%interface",
        "[::1]",
        "999.1.1.1",
        "192.000.2.1",
        "api..example.test",
        "-api.example.test",
        "api-.example.test",
        "api_example.test",
        "*.example.test",
        "api.example.test\n",
        "api\x00.example.test",
        "éxample.test",
        "K.example.test",
        "a" * 64 + ".test",
        "a." * 127 + "a",
    ],
)
def test_hosts_never_return_urls_paths_userinfo_or_invalid_names(
    make_store: Callable[[ReadOnlyDriver], Any], host: str
) -> None:
    assert graph_row(make_store, row(host=host))["host"] is None


@pytest.mark.parametrize("port", [None, False, True, "443", 443.0, -1, 0, 65536, 1, 443, 65535])
def test_ports_are_strictly_bounded_integers(
    make_store: Callable[[ReadOnlyDriver], Any], port: Any
) -> None:
    expected = port if type(port) is int and 1 <= port <= 65535 else None
    assert graph_row(make_store, row(port=port))["port"] == expected


@pytest.mark.parametrize("value", [None, False, "", [], {}, "x" * 4097])
def test_invalid_opaque_identifiers_become_null(
    make_store: Callable[[ReadOnlyDriver], Any], value: Any
) -> None:
    assert graph_row(make_store, row(id=value))["id"] is None


@pytest.mark.parametrize("value", [42, "opaque-key", "\ud800"])
def test_valid_opaque_identifiers_are_hashed(
    make_store: Callable[[ReadOnlyDriver], Any], value: Any
) -> None:
    expected = "sha256:" + hashlib.sha256(str(value).encode(errors="surrogatepass")).hexdigest()
    assert graph_row(make_store, row(id=value))["id"] == expected


@pytest.mark.parametrize("maximum", [None, False, True, -1, 0, 1001, "1", 1.0, [], {}])
def test_max_rows_validation_precedes_all_source_access(
    make_store: Callable[[ReadOnlyDriver], Any], maximum: Any
) -> None:
    driver = ReadOnlyDriver()
    with pytest.raises(ContextExportError):
        graph_source(make_store(driver), engagement=DISPLAY, graph_scope=SCOPE, max_rows=maximum)
    with pytest.raises(ContextExportError):
        skill_source(DISPLAY, [MetadataMessage([request("review")])], max_rows=maximum)
    assert driver.requests == [] and driver.writes == 0


@pytest.mark.parametrize(
    "label",
    [None, 1, False, "", " ", "a" * 129, "a/b", "a;MATCH", "x\n", "x\r", "é", SENTINEL + " bad"],
)
@pytest.mark.parametrize("field", ["engagement", "graph_scope"])
def test_both_labels_are_validated_without_reflecting_input(
    make_store: Callable[[ReadOnlyDriver], Any], label: Any, field: str
) -> None:
    driver = ReadOnlyDriver()
    arguments: dict[str, Any] = {"engagement": DISPLAY, "graph_scope": SCOPE, field: label}
    with pytest.raises(ContextExportError) as exc:
        graph_source(make_store(driver), **arguments)
    assert SENTINEL not in str(exc.value)
    if field == "engagement":
        with pytest.raises(ContextExportError):
            skill_source(label, [])
    assert driver.requests == [] and driver.writes == 0


@pytest.mark.parametrize("label", ["unknown", "A" * 128, "review.v1_-2"])
def test_safe_display_and_partition_labels_are_accepted(
    make_store: Callable[[ReadOnlyDriver], Any], label: str
) -> None:
    result = graph_source(make_store(ReadOnlyDriver()), engagement=label, graph_scope=label)
    assert result["engagement"] == label and result["status"] == "ok"
    assert skill_source(label, [])["engagement"] == label


@pytest.mark.parametrize(("messages", "status"), [(None, "not_requested"), ([], "ok")])
def test_absent_messages_differ_from_an_observed_empty_history(messages: Any, status: str) -> None:
    assert skill_source(DISPLAY, messages) == {
        "engagement": DISPLAY,
        "status": status,
        "total": 0,
        "data": [],
    }


def test_skill_requests_are_deduplicated_in_first_seen_order_with_omission_totals() -> None:
    messages = [
        MetadataMessage(
            [
                request("z-review"),
                request("/skills/web-review/SKILL.md"),
                request("z-review"),
                request("https://invalid.example/" + SENTINEL),
                {"name": "load_skill", "args": {}},
                {"name": "unrelated_tool", "args": {"name_or_path": SENTINEL}},
                request("a-review"),
            ]
        )
    ]
    result = skill_source(DISPLAY, messages, max_rows=2)
    assert result == {
        "engagement": DISPLAY,
        "status": "ok",
        "total": 6,
        "data": [
            {"name_or_path": "z-review", "status": "requested"},
            {"name_or_path": "/skills/web-review/SKILL.md", "status": "requested"},
        ],
    }
    assert SENTINEL not in json.dumps(result)
    assert len(skill_source(DISPLAY, messages)["data"]) == 3


@pytest.mark.parametrize(
    "identifier",
    [
        "review",
        "Review_v1-2",
        "a" * 80,
        "/skills/web-review/SKILL.md",
        "/skills/standard/review.v2/SKILL.md",
    ],
)
def test_safe_skill_identifiers_are_preserved_without_loading_bodies(identifier: str) -> None:
    assert skill_source(DISPLAY, [MetadataMessage([request(identifier)])])["data"] == [
        {"name_or_path": identifier, "status": "requested"}
    ]


@pytest.mark.parametrize(
    "identifier",
    [
        None,
        1,
        {},
        "",
        "a" * 81,
        "/skills/" + "a/" * 100 + "SKILL.md",
        "https://example.test/" + SENTINEL,
        "file:///skills/review/SKILL.md",
        "../review",
        "/skills/../review",
        "/skills/review/../../private",
        "/skills/%2e%2e/private",
        "/skills//review",
        "/skills/review\\SKILL.md",
        "/skills/.hidden/SKILL.md",
        "/other/review/SKILL.md",
        "skills/review/SKILL.md",
        "review\n" + SENTINEL,
        "review\n",
        "review\x00",
        "review?secret=" + SENTINEL,
        "review#fragment",
        "user@review",
        "review space",
        "[review](url)",
    ],
)
def test_unsafe_skill_arguments_are_dropped_but_counted(identifier: Any) -> None:
    assert skill_source(DISPLAY, [MetadataMessage([request(identifier)])]) == {
        "engagement": DISPLAY,
        "status": "ok",
        "total": 1,
        "data": [],
    }


def test_only_public_parsed_tool_calls_and_name_or_path_are_used() -> None:
    messages = [
        MetadataMessage(
            [
                {"name": "load_skill", "args": None},
                {"name": "load_skill", "args": SENTINEL},
                {"name": "load_skill"},
                {"name": "load_skill", "args": {"skill_path": "web-review"}},
                {"name": "other", "args": {"name_or_path": SENTINEL}},
                None,
                SENTINEL,
            ]
        ),
        MetadataMessage({"name": "load_skill", "args": {"name_or_path": SENTINEL}}),
        object(),
    ]
    assert skill_source(DISPLAY, messages) == {
        "engagement": DISPLAY,
        "status": "ok",
        "total": 4,
        "data": [],
    }
    assert skill_source(DISPLAY, [{"tool_calls": [request("review")], "content": SENTINEL}])[
        "data"
    ] == [{"name_or_path": "review", "status": "requested"}]


def test_native_langchain_messages_do_not_prove_a_skill_was_loaded(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(socket, "has_ipv6", False)
    messages = importlib.import_module("langchain_core.messages")
    supplied = [
        messages.AIMessage(content=SENTINEL, tool_calls=[request("web-review")]),
        messages.ToolMessage(
            content=json.dumps({"error": SENTINEL}),
            name="load_skill",
            tool_call_id="synthetic-call",
            status="success",
        ),
        messages.SystemMessage(content=SENTINEL),
    ]
    assert skill_source(DISPLAY, supplied) == {
        "engagement": DISPLAY,
        "status": "ok",
        "total": 1,
        "data": [{"name_or_path": "web-review", "status": "requested"}],
    }


def test_skill_metadata_access_errors_have_a_fixed_safe_envelope() -> None:
    class UnavailableMetadata:
        @property
        def tool_calls(self) -> NoReturn:
            raise RuntimeError(SENTINEL)

    assert skill_source(DISPLAY, [UnavailableMetadata()]) == {
        "engagement": DISPLAY,
        "status": "error",
        "total": 0,
        "data": [],
        "error_code": "skill_metadata_failed",
    }


@pytest.mark.parametrize("messages", ["private", {}, (), 1])
def test_invalid_message_containers_are_domain_errors(messages: Any) -> None:
    with pytest.raises(ContextExportError):
        skill_source(DISPLAY, messages)


def test_sources_perform_no_file_reads(
    make_store: Callable[[ReadOnlyDriver], Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    driver = ReadOnlyDriver([node()])
    store = make_store(driver)
    messages = [MetadataMessage([request("/skills/review/SKILL.md")])]
    attempts: list[str] = []

    def forbidden(*args: Any, **kwargs: Any) -> NoReturn:
        attempts.append("file access")
        raise AssertionError("Metadata sources must not read files")

    with monkeypatch.context() as guard:
        for owner, attribute in (
            (builtins, "open"),
            (io, "open"),
            (Path, "read_text"),
            (Path, "read_bytes"),
        ):
            guard.setattr(owner, attribute, forbidden)
        graph = graph_source(store, engagement=DISPLAY, graph_scope=SCOPE)
        skills = skill_source(DISPLAY, messages)
    assert graph["status"] == skills["status"] == "ok"
    assert attempts == [] and driver.writes == 0
