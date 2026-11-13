from __future__ import annotations

import hashlib
import json
import os
import socket
import ssl
import time
from collections.abc import Iterator
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest

from buggy.sandbox_kernel import defensive_workflows as workflows
from buggy.sandbox_kernel._workflow_storage import WorkflowStorage, WorkflowStorageError
from buggy.sandbox_kernel.assessment import AssessmentStore
from buggy.sandbox_kernel.bounded_process import CommandResult
from buggy.sandbox_kernel.defensive_workflows import (
    DefensiveWorkflowError,
    DefensiveWorkflowRunner,
    WorkflowInputError,
    workflow_catalog,
)

ASSET = "https://api.example.test/"
STAMP = "2025-01-02T03:04:05Z"


@pytest.fixture(autouse=True)
def no_real_targets(monkeypatch: pytest.MonkeyPatch) -> None:
    def refuse(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError("A test attempted a real command or network transport")

    monkeypatch.setattr(workflows, "run_bounded", refuse, raising=False)
    monkeypatch.setattr(socket, "socket", refuse)
    monkeypatch.setattr(socket, "getaddrinfo", refuse)


def artifact(workspace: Path, value: dict[str, Any], name: str = "input.json") -> str:
    (workspace / name).write_text(json.dumps(value), encoding="utf-8")
    return name


def capture(**overrides: Any) -> dict[str, Any]:
    return {
        "source": "capture",
        "url": ASSET,
        "method": "GET",
        "captured_at": STAMP,
        "status_code": 200,
        "headers": {
            "X-Content-Type-Options": "nosniff",
            "Strict-Transport-Security": "max-age=31536000",
            "Set-Cookie": "session=synthetic-secret",
        },
        "body": "synthetic-private-body",
    } | overrides


def test_artifact_descriptor_closes_when_stream_initialization_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import os

    from buggy.sandbox_kernel._workflow_storage import WorkflowStorage, WorkflowStorageError

    path = artifact(tmp_path, capture())
    storage = WorkflowStorage(tmp_path)
    descriptors: list[int] = []
    closed: set[int] = set()
    original_close = os.close

    def fail_open(descriptor: int, *args: Any, **kwargs: Any) -> Any:
        descriptors.append(descriptor)
        raise OSError("fixture stream initialization failure")

    def close(descriptor: int) -> None:
        closed.add(descriptor)
        original_close(descriptor)

    monkeypatch.setattr(os, "fdopen", fail_open)
    monkeypatch.setattr(os, "close", close)
    try:
        with pytest.raises(WorkflowStorageError):
            storage.read(path)
        assert len(descriptors) == 1
        with pytest.raises(OSError):
            os.fstat(descriptors[0])
    finally:
        for descriptor in descriptors:
            if descriptor not in closed:
                original_close(descriptor)


@pytest.fixture
def tracked_descriptors(
    monkeypatch: pytest.MonkeyPatch,
) -> Iterator[tuple[set[int], list[int]]]:
    live: set[int] = set()
    counts: list[int] = []
    original_open, original_close = os.open, os.close

    def open_descriptor(*args: Any, **kwargs: Any) -> int:
        descriptor = original_open(*args, **kwargs)
        live.add(descriptor)
        counts.append(len(live))
        return descriptor

    def close_descriptor(descriptor: int) -> None:
        original_close(descriptor)
        live.remove(descriptor)

    monkeypatch.setattr(os, "open", open_descriptor)
    monkeypatch.setattr(os, "close", close_descriptor)
    try:
        yield live, counts
    finally:
        for descriptor in live:
            original_close(descriptor)


def test_evidence_descriptor_closes_when_stream_initialization_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    tracked_descriptors: tuple[set[int], list[int]],
) -> None:
    storage = WorkflowStorage(tmp_path)
    nonce = storage.new_run()

    def fail_open(*args: Any, **kwargs: Any) -> Any:
        raise OSError("fixture stream initialization failure")

    monkeypatch.setattr(os, "fdopen", fail_open)
    with pytest.raises(WorkflowStorageError):
        storage.write(nonce, "fixture.json", b"{}")
    assert not tracked_descriptors[0]


def test_directory_walk_bounds_handles_for_deep_paths_and_unicode_workspaces(
    tmp_path: Path, tracked_descriptors: tuple[set[int], list[int]]
) -> None:
    workspace = tmp_path / "workspace with spaces" / "資料"
    workspace.mkdir(parents=True)
    storage = WorkflowStorage(workspace)
    parts = tuple(f"p{index}" for index in range(64))
    with storage.directory(parts, create=True) as parent:
        assert os.path.samestat(os.fstat(parent), workspace.joinpath(*parts).stat())
        assert not os.get_inheritable(parent)
    path = artifact(workspace, capture(), "/".join((*parts, "input.json")))
    reference, raw = storage.read(path)
    assert reference["path"] == path
    assert json.loads(raw) == capture()
    live, counts = tracked_descriptors
    assert not live
    assert max(counts) == 2


@pytest.mark.parametrize(
    ("operation", "fail_after"),
    [("open", 2), ("dup2", 1), ("mkdir", 2), ("fsync", 2), ("fstat", 1)],
)
def test_directory_walk_closes_descriptors_when_a_filesystem_operation_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    tracked_descriptors: tuple[set[int], list[int]],
    operation: str,
    fail_after: int,
) -> None:
    storage = WorkflowStorage(tmp_path)
    original = getattr(os, operation)
    calls = 0

    def fail(*args: Any, **kwargs: Any) -> Any:
        nonlocal calls
        calls += 1
        if calls == fail_after:
            raise OSError("fixture directory operation failure")
        return original(*args, **kwargs)

    with monkeypatch.context() as patch:
        patch.setattr(os, operation, fail)
        with pytest.raises(WorkflowStorageError):
            with storage.directory(("assessment", "workflows"), create=True):
                pytest.fail("Directory acquisition did not fail")
    assert not tracked_descriptors[0]


def test_directory_walk_closes_descriptors_when_the_consumer_raises(
    tmp_path: Path, tracked_descriptors: tuple[set[int], list[int]]
) -> None:
    storage = WorkflowStorage(tmp_path)
    with pytest.raises(RuntimeError, match="fixture consumer failure"):
        try:
            with storage.directory(("assessment", "workflows"), create=True):
                raise RuntimeError("fixture consumer failure")
        finally:
            assert not tracked_descriptors[0]


@pytest.mark.parametrize("replacement", ["directory", "workspace_symlink", "ancestor_symlink"])
def test_directory_walk_rejects_replaced_workspaces_and_symlinked_ancestors(
    tmp_path: Path, tracked_descriptors: tuple[set[int], list[int]], replacement: str
) -> None:
    ancestor = tmp_path / "ancestor"
    workspace = ancestor / "workspace"
    workspace.mkdir(parents=True)
    storage = WorkflowStorage(workspace)
    if replacement == "ancestor_symlink":
        moved = tmp_path / "moved"
        ancestor.rename(moved)
        ancestor.symlink_to(moved, target_is_directory=True)
    else:
        moved = ancestor / "moved"
        workspace.rename(moved)
        if replacement == "workspace_symlink":
            workspace.symlink_to(moved, target_is_directory=True)
        else:
            workspace.mkdir()
    with pytest.raises(WorkflowStorageError):
        with storage.directory(()):
            pytest.fail("Replaced workspace was accepted")
    assert not tracked_descriptors[0]


def test_capture_review_is_durable_redacted_and_separate_from_coverage(tmp_path: Path) -> None:
    path = artifact(tmp_path, capture())
    original = (tmp_path / path).read_bytes()
    result = DefensiveWorkflowRunner(tmp_path).run(
        "http-capture-review", {"url": ASSET, "artifact_path": path}
    )
    assert result["status"] == "observed"
    assert result["baseline_coverage_updated"] is False
    assert result["independent_verification"] is False
    assert result["assurance"] == "none"
    assert result["observations"][0]["result"] == "present"
    assert result["process"] == {"status": "not_run", "exit_code": None}
    assert result["evidence_integrity"] == "verified"
    assert result["source_artifact"]["sha256"] == hashlib.sha256(original).hexdigest()
    assert result["artifact"] in result["evidence"]
    assert result["artifact"]["sha256"] == result["source_artifact"]["sha256"]
    assert (tmp_path / path).read_bytes() == original
    assert not (tmp_path / "assessment" / "coverage.sqlite3").exists()
    assert "synthetic-secret" not in json.dumps(result)
    assert "synthetic-private-body" not in json.dumps(result)
    assert DefensiveWorkflowRunner(tmp_path).report(result["run_id"]) == result


@pytest.mark.parametrize(
    "changes",
    [
        {"source": "mock"},
        {"url": "https://different.example.test/"},
        {"method": "POST"},
        {"captured_at": "not-a-timestamp"},
        {"status_code": True},
        {"headers": {"X-Content-Type-Options": "nosniff\r\nInjected: value"}},
    ],
)
def test_malformed_capture_is_rejected_with_durable_non_assurance(
    tmp_path: Path, changes: dict[str, Any]
) -> None:
    path = artifact(tmp_path, capture(**changes))
    runner = DefensiveWorkflowRunner(tmp_path)
    result = runner.run("http-capture-review", {"url": ASSET, "artifact_path": path})
    assert result["status"] == "rejected"
    assert result["error"]["code"] == "INVALID_ARTIFACT"
    assert result["observations"] == []
    assert runner.report(result["run_id"])["status"] == "rejected"


@pytest.mark.parametrize(
    ("changes", "expected"),
    [
        ({"status_code": 302}, "inconclusive"),
        ({"status_code": 403}, "inconclusive"),
        ({"is_challenge": True}, "inconclusive"),
        ({"headers": {"CF-Mitigated": "challenge"}}, "inconclusive"),
        ({"headers": {}}, "missing_or_ambiguous"),
        ({"headers": {"X-Content-Type-Options": ["nosniff", "nosniff"]}}, "missing_or_ambiguous"),
    ],
)
def test_http_uses_existing_challenge_redirect_and_duplicate_header_semantics(
    tmp_path: Path, changes: dict[str, Any], expected: str
) -> None:
    path = artifact(tmp_path, capture(**changes))
    result = DefensiveWorkflowRunner(tmp_path).run(
        "http-capture-review", {"url": ASSET, "artifact_path": path}
    )
    assert result["observations"][0]["result"] == expected
    assert result["status"] not in {"pass", "fail"}


@pytest.mark.parametrize("which", ["source", "evidence", "manifest"])
def test_report_detects_tampered_source_evidence_and_manifest(tmp_path: Path, which: str) -> None:
    path = artifact(tmp_path, capture())
    runner = DefensiveWorkflowRunner(tmp_path)
    result = runner.run("http-capture-review", {"url": ASSET, "artifact_path": path})
    target = tmp_path / (
        path
        if which == "source"
        else result["evidence"][0]["path"]
        if which == "evidence"
        else result["manifest"]["path"]
    )
    target.chmod(0o600)
    target.write_text("{}", encoding="utf-8")
    report = DefensiveWorkflowRunner(tmp_path).report(result["run_id"])
    assert report["evidence_integrity"] == "untrusted"
    assert report["status"] == "inconclusive"
    assert report["integrity_errors"]
    assert report["independent_verification"] is False


@pytest.mark.parametrize(
    "path",
    [
        "-",
        "/etc/passwd",
        "../input.json",
        "./input.json",
        "a/../input.json",
        "https://api.example.test/capture",
        "file:///tmp/a",
        "C:\\input.json",
    ],
)
def test_artifact_paths_must_be_local_canonical_and_workspace_relative(
    tmp_path: Path, path: str
) -> None:
    with pytest.raises(WorkflowInputError):
        DefensiveWorkflowRunner(tmp_path).run(
            "http-capture-review", {"url": ASSET, "artifact_path": path}
        )


@pytest.mark.parametrize("which", ["source", "parent", "storage"])
def test_symlinked_artifacts_and_storage_are_refused(tmp_path: Path, which: str) -> None:
    path = artifact(tmp_path, capture())
    if which == "source":
        (tmp_path / "link.json").symlink_to(tmp_path / path)
        path = "link.json"
    elif which == "parent":
        (tmp_path / "link").symlink_to(tmp_path, target_is_directory=True)
        path = "link/input.json"
    else:
        (tmp_path / "assessment").symlink_to(tmp_path, target_is_directory=True)
    with pytest.raises(DefensiveWorkflowError):
        DefensiveWorkflowRunner(tmp_path).run(
            "http-capture-review", {"url": ASSET, "artifact_path": path}
        )


def nmap_xml(
    ip: str = "192.0.2.10", hostname: str = "api.example.test", ports: str | None = None
) -> bytes:
    port_xml = (
        ports
        if ports is not None
        else '<port protocol="tcp" portid="443"><state state="open"/><service name="https"/></port>'
    )
    return (
        '<?xml version="1.0"?><!DOCTYPE nmaprun><nmaprun scanner="nmap" version="7.95">'
        '<host><status state="up"/>'
        f'<address addr="{ip}" addrtype="ipv4"/>'
        f'<hostnames><hostname name="{hostname}" type="user"/></hostnames>'
        f"<ports>{port_xml}</ports></host>"
        '<runstats><finished exit="success"/><hosts up="1" down="0" total="1"/></runstats></nmaprun>'
    ).encode()


def test_network_inventory_parses_real_nmap_structure_without_claiming_verification(
    tmp_path: Path,
) -> None:
    (tmp_path / "scan.xml").write_bytes(nmap_xml())
    result = DefensiveWorkflowRunner(tmp_path).run(
        "network-inventory", {"url": ASSET, "artifact_path": "scan.xml"}
    )
    assert result["status"] == "observed"
    assert result["tool"] == {"name": "nmap", "version": "7.95"}
    assert result["observations"] == [
        {"ip": "192.0.2.10", "port": 443, "protocol": "tcp", "state": "open", "service": "https"}
    ]
    assert result["baseline_coverage_updated"] is False
    assert result["assurance"] == "none"


def dns_artifact(**overrides: Any) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "kind": "dns-observation",
        "asset": ASSET,
        "observed_at": STAMP,
        "queries": [
            {
                "name": "api.example.test",
                "type": "A",
                "status": "NOERROR",
                "answers": [
                    {"name": "api.example.test", "type": "A", "value": "192.0.2.10", "ttl": 60}
                ],
            },
            {"name": "api.example.test", "type": "AAAA", "status": "NOERROR", "answers": []},
        ],
    } | overrides


def test_dns_inventory_validates_normalized_versioned_observations(tmp_path: Path) -> None:
    path = artifact(tmp_path, dns_artifact())
    result = DefensiveWorkflowRunner(tmp_path).run(
        "dns-inventory", {"url": ASSET, "artifact_path": path}
    )
    assert result["status"] == "observed"
    assert result["observations"] == [
        {
            "name": "api.example.test",
            "type": "A",
            "value": "192.0.2.10",
            "ttl": 60,
        }
    ]
    assert result["query_statuses"] == {"A": "NOERROR", "AAAA": "NOERROR"}
    assert result["tool"]["version"] == "unknown"


def tls_artifact(**overrides: Any) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "kind": "tls-observation",
        "asset": ASSET,
        "observed_at": STAMP,
        "peer_ip": "192.0.2.10",
        "port": 443,
        "server_name": "api.example.test",
        "handshake": "completed",
        "certificate_validation": "valid",
        "protocol": "TLSv1.3",
        "cipher": "TLS_AES_256_GCM_SHA384",
        "certificate_sha256": "a" * 64,
        "not_before": "2024-01-01T00:00:00Z",
        "not_after": "2026-01-01T00:00:00Z",
    } | overrides


@pytest.mark.parametrize("validation", ["valid", "invalid", "unknown"])
def test_tls_observations_never_turn_attested_validation_into_assurance(
    tmp_path: Path, validation: str
) -> None:
    path = artifact(tmp_path, tls_artifact(certificate_validation=validation))
    result = DefensiveWorkflowRunner(tmp_path).run(
        "tls-inspection", {"url": ASSET, "artifact_path": path}
    )
    assert result["status"] == ("observed" if validation == "valid" else "inconclusive")
    assert result["observations"][0]["certificate_validation"] == validation
    assert result["independent_verification"] is False
    assert result["tool"]["version"] == "unknown"


def sarif_artifact(results: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "properties": {"asset": ASSET},
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "synthetic-scanner",
                        "version": "1.2",
                        "rules": [{"id": "TEST001"}],
                    }
                },
                "invocations": [{"executionSuccessful": True, "exitCode": 0}],
                "results": results
                if results is not None
                else [
                    {
                        "ruleId": "TEST001",
                        "ruleIndex": 0,
                        "level": "warning",
                        "message": {"text": "Synthetic finding; not independently reproduced"},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "src/app.py"},
                                    "region": {"startLine": 7},
                                }
                            }
                        ],
                    }
                ],
            }
        ],
    }


def test_sarif_review_validates_and_summarizes_without_executing_source(tmp_path: Path) -> None:
    path = artifact(tmp_path, sarif_artifact())
    result = DefensiveWorkflowRunner(tmp_path).run(
        "sarif-review", {"url": ASSET, "artifact_path": path}
    )
    assert result["status"] == "observed"
    assert result["observations"] == [
        {
            "run_index": 0,
            "rule_id": "TEST001",
            "level": "warning",
            "locations_count": 1,
        }
    ]
    assert result["tool"] == {"name": "synthetic-scanner", "version": "1.2"}
    assert result["source_executed"] is False
    assert result["independent_verification"] is False


@pytest.mark.parametrize(
    "workflow",
    ["network-inventory", "dns-inventory", "tls-inspection", "http-capture-review", "sarif-review"],
)
@pytest.mark.parametrize(
    "raw", [b"", b"{", b'{"version":"2.1.0","version":"2.1.0"}', b'{"runs":NaN}', b"\xff"]
)
def test_empty_malformed_truncated_or_duplicate_artifacts_are_never_successful(
    tmp_path: Path, workflow: str, raw: bytes
) -> None:
    (tmp_path / "bad.dat").write_bytes(raw)
    result = DefensiveWorkflowRunner(tmp_path).run(
        workflow, {"url": ASSET, "artifact_path": "bad.dat"}
    )
    assert result["status"] == "rejected"
    assert result["observations"] == []
    assert result["assurance"] == "none"


@pytest.mark.parametrize(
    "raw",
    [
        nmap_xml(hostname="other.example.test"),
        nmap_xml().replace(b'<finished exit="success"/>', b""),
        nmap_xml().replace(b"</nmaprun>", b""),
        nmap_xml().replace(
            b"<!DOCTYPE nmaprun>", b'<!DOCTYPE nmaprun SYSTEM "file:///etc/passwd">'
        ),
        nmap_xml().replace(
            b"<!DOCTYPE nmaprun>", b'<!DOCTYPE nmaprun [<!ENTITY x SYSTEM "file:///etc/passwd">]>'
        ),
        nmap_xml().replace(
            b"<ports>",
            b'<ports xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include href="file:///etc/passwd"/>',
        ),
        nmap_xml().replace(
            b'<port protocol="tcp" portid="443">', b'<port protocol="tcp" portid="0">'
        ),
        nmap_xml().replace(b"</host>", b"</host><host/>"),
        nmap_xml().replace(b"<runstats>", b"<a>" * 25 + b"</a>" * 25 + b"<runstats>"),
        nmap_xml().replace(
            b"<!DOCTYPE nmaprun>", b'<?xml-stylesheet href="https://other.example.test/style"?>'
        ),
        nmap_xml().replace(b'total="1"', b'total="9"'),
        nmap_xml().replace(b'addrtype="ipv4"', b'addrtype="ipv6"'),
        nmap_xml().replace(b'<status state="up"/>', b'<status state="down"/>'),
        nmap_xml().replace(
            b'<state state="open"/>', b'<state state="open"/><state state="closed"/>'
        ),
        nmap_xml().replace(b"<ports>", b'<ports xml:base="https://other.example.test/">'),
    ],
)
def test_nmap_rejects_mismatches_entities_external_references_and_unbounded_trees(
    tmp_path: Path, raw: bytes
) -> None:
    (tmp_path / "scan.xml").write_bytes(raw)
    result = DefensiveWorkflowRunner(tmp_path).run(
        "network-inventory", {"url": ASSET, "artifact_path": "scan.xml"}
    )
    assert result["status"] == "rejected"
    assert result["observations"] == []


@pytest.mark.parametrize(
    ("workflow", "value"),
    [
        ("dns-inventory", dns_artifact(queries=[])),
        (
            "dns-inventory",
            dns_artifact(
                queries=[
                    {"name": "api.example.test", "type": "A", "status": "NXDOMAIN", "answers": []}
                ]
            ),
        ),
        ("sarif-review", sarif_artifact(results=[])),
        ("sarif-review", {"version": "2.1.0", "runs": []}),
    ],
)
def test_valid_empty_inventory_is_inconclusive_even_with_exit_zero(
    tmp_path: Path, workflow: str, value: dict[str, Any]
) -> None:
    path = artifact(tmp_path, value)
    result = DefensiveWorkflowRunner(tmp_path).run(workflow, {"url": ASSET, "artifact_path": path})
    assert result["status"] == "inconclusive"
    assert result["observations"] == []


@pytest.mark.parametrize(
    ("workflow", "value"),
    [
        ("dns-inventory", dns_artifact(schema_version=True)),
        ("dns-inventory", dns_artifact(schema_version=2)),
        ("dns-inventory", dns_artifact(asset="https://other.example.test/")),
        (
            "dns-inventory",
            dns_artifact(
                queries=[
                    {"name": "other.example.test", "type": "A", "status": "NOERROR", "answers": []}
                ]
            ),
        ),
        (
            "dns-inventory",
            dns_artifact(
                queries=[
                    {"name": "api.example.test", "type": "TXT", "status": "NOERROR", "answers": []}
                ]
            ),
        ),
        (
            "dns-inventory",
            dns_artifact(
                queries=[
                    {
                        "name": "api.example.test",
                        "type": "A",
                        "status": "NOERROR",
                        "answers": [
                            {"name": "api.example.test", "type": "A", "value": "::1", "ttl": 1}
                        ],
                    }
                ]
            ),
        ),
        ("tls-inspection", tls_artifact(asset="https://other.example.test/")),
        ("tls-inspection", tls_artifact(port=444)),
        ("tls-inspection", tls_artifact(server_name="other.example.test")),
        ("tls-inspection", tls_artifact(certificate_sha256="not-a-hash")),
        ("tls-inspection", tls_artifact(handshake="failed")),
        ("sarif-review", {"version": "2.0.0", "runs": []}),
        ("sarif-review", {"version": "2.1.0", "runs": [None]}),
        ("sarif-review", sarif_artifact(results=[{"message": "not an object"}])),
        (
            "sarif-review",
            sarif_artifact(results=[{"message": {"text": "finding"}, "ruleIndex": True}]),
        ),
        (
            "sarif-review",
            sarif_artifact(results=[{"message": {"text": "finding"}, "ruleIndex": 9}]),
        ),
        (
            "sarif-review",
            sarif_artifact(results=[{"message": {"text": "finding"}, "level": "pass"}]),
        ),
    ],
)
def test_versioned_parsers_reject_invalid_types_bindings_and_statuses(
    tmp_path: Path, workflow: str, value: dict[str, Any]
) -> None:
    path = artifact(tmp_path, value)
    result = DefensiveWorkflowRunner(tmp_path).run(workflow, {"url": ASSET, "artifact_path": path})
    assert result["status"] == "rejected"
    assert result["error"]["code"] == "INVALID_ARTIFACT"


@pytest.mark.parametrize("workflow", ["network-inventory", "dns-inventory", "tls-inspection"])
def test_observation_requires_existing_assessment_and_returns_durable_block(
    tmp_path: Path, workflow: str
) -> None:
    payload: dict[str, Any] = {"url": ASSET, "observe": True}
    if workflow == "network-inventory":
        payload["ports"] = [443]
    runner = DefensiveWorkflowRunner(tmp_path)
    result = runner.run(workflow, payload)
    assert result["status"] == "blocked"
    assert result["error"]["code"] == "ASSESSMENT_REQUIRED"
    assert result["process"]["status"] == "not_run"
    assert result["observations"] == []
    assert runner.report(result["run_id"]) == result
    assert not (tmp_path / "assessment" / "coverage.sqlite3").exists()


def initialize(
    workspace: Path,
    *,
    allowed: list[str] | None = None,
    denied: list[str] | None = None,
    **machine: Any,
) -> AssessmentStore:
    store = AssessmentStore(workspace)
    store.dispatch(
        "initialize",
        {
            "engagement_name": "defensive-synthetic",
            "profile": "external",
            "allowed_hosts": allowed or ["api.example.test"],
            "denied_hosts": denied or [],
        },
    )
    (workspace / "plan").mkdir(exist_ok=True)
    artifact(
        workspace,
        {"machine_enforcement": {"mode": "enforce", "in_scope": ["api.example.test"]} | machine},
        "plan/roe.json",
    )
    return store


def dig_output(
    kind: str = "A",
    address: str | None = "192.0.2.10",
    *,
    status: str = "NOERROR",
    flags: str = "qr rd ra",
) -> bytes:
    answer = f"api.example.test. 60 IN {kind} {address}\n" if address else ""
    return (
        f";; ->>HEADER<<- opcode: QUERY, status: {status}, id: 7\n"
        f";; flags: {flags}; QUERY: 1, ANSWER: {int(bool(address))}, AUTHORITY: 0, ADDITIONAL: 0\n"
        f";; QUESTION SECTION:\n;api.example.test. IN {kind}\n"
        f";; ANSWER SECTION:\n{answer};; SERVER: 192.0.2.53#53(192.0.2.53)\n;; MSG SIZE rcvd: 64\n"
    ).encode()


def test_dns_observation_executes_only_fixed_bounded_questions_and_persists_results(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = initialize(tmp_path)
    before = store.dispatch("report", {})
    calls: list[list[str]] = []

    def command(
        argv: list[str], *, cwd: str | Path, timeout: float, max_output_bytes: int
    ) -> CommandResult:
        assert argv[0] == "dig"
        assert Path(cwd) == tmp_path
        assert 0 < timeout <= 4
        assert max_output_bytes <= 2 * 1024 * 1024
        calls.append(argv)
        kind = argv[argv.index("-t") + 1]
        return CommandResult(
            "completed", 0, dig_output(kind, "192.0.2.10" if kind == "A" else None), b""
        )

    monkeypatch.setattr(workflows, "run_bounded", command)
    result = DefensiveWorkflowRunner(tmp_path).run("dns-inventory", {"url": ASSET, "observe": True})
    assert result["status"] == "observed"
    assert result["observations"] == [
        {"name": "api.example.test", "type": "A", "value": "192.0.2.10", "ttl": 60}
    ]
    assert result["resolved_ips"] == ["192.0.2.10"]
    assert len(calls) == 2
    assert all("-r" in argv and "+nosearch" in argv and "+ignore" in argv for argv in calls)
    assert result["process"] == {"status": "completed", "exit_code": 0}
    assert result["artifact"] == result["resolution_artifact"]
    assert result["artifact"] in result["evidence"]
    assert result["processes"][0]["stdout"] in result["evidence"]
    assert result["authorization"]["assessment_revision"] == before["revision"]
    assert store.dispatch("report", {}) == before
    assert DefensiveWorkflowRunner(tmp_path).report(result["run_id"]) == result


@pytest.mark.parametrize(
    "machine",
    [
        {"mode": "audit"},
        {"mode": "warn"},
        {"mode": True},
        {"in_scope": []},
        {"in_scope": ["other.example.test"]},
        {"in_scope": ["https://api.example.test/restricted"]},
        {"out_of_scope": ["*.example.test"]},
        {"forbidden_destinations": ["api.example.test"]},
        {"forbidden_command_patterns": [r"\bdig\b"]},
        {"forbidden_command_patterns": ["("]},
        {"allow_cloud_metadata": "false"},
        {"authorized_windows": [["1999-01-01T00:00:00Z", "2000-01-01T00:00:00Z"]]},
        {"authorized_windows": [{"start": "bad", "end": "bad"}]},
        {"blackout_windows": [["2000-01-01T00:00:00Z", "2100-01-01T00:00:00Z"]]},
        {"max_concurrent_connections": False},
        {"min_inter_request_delay_ms": 2000},
        {"out_of_scope": [42]},
        {"unrecognized_enforcement": True},
    ],
)
def test_roe_blocks_before_any_command_and_never_falls_back(
    tmp_path: Path, machine: dict[str, Any]
) -> None:
    initialize(tmp_path, **machine)
    result = DefensiveWorkflowRunner(tmp_path).run("dns-inventory", {"url": ASSET, "observe": True})
    assert result["status"] == "blocked"
    assert result["process"]["status"] == "not_run"
    assert result["observations"] == []


@pytest.mark.parametrize("marker", ["file", "dangling_symlink"])
def test_abort_marker_blocks_including_dangling_symlinks(tmp_path: Path, marker: str) -> None:
    initialize(tmp_path)
    if marker == "file":
        (tmp_path / ".abort").touch()
    else:
        (tmp_path / ".abort").symlink_to(tmp_path / "missing")
    result = DefensiveWorkflowRunner(tmp_path).run("dns-inventory", {"url": ASSET, "observe": True})
    assert result["status"] == "blocked"
    assert result["error"]["code"] == "EMERGENCY_ABORT"


@pytest.mark.parametrize(
    "address", ["169.254.169.254", "100.100.100.200", "192.0.2.99", "127.0.0.1"]
)
def test_resolved_ip_exclusions_have_precedence_over_domain_permission(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, address: str
) -> None:
    initialize(tmp_path, denied=["127.0.0.0/8"], out_of_scope=["192.0.2.99"])

    def command(argv: list[str], **kwargs: Any) -> CommandResult:
        kind = argv[argv.index("-t") + 1]
        return CommandResult(
            "completed", 0, dig_output(kind, address if kind == "A" else None), b""
        )

    monkeypatch.setattr(workflows, "run_bounded", command)
    result = DefensiveWorkflowRunner(tmp_path).run("dns-inventory", {"url": ASSET, "observe": True})
    assert result["status"] == "blocked"
    assert result["error"]["code"] == "RESOLVED_IP_DENIED"
    assert result["observations"] == []


@pytest.mark.parametrize(
    "output",
    [
        CommandResult("unavailable", None, b"", b""),
        CommandResult("timeout", None, dig_output(), b""),
        CommandResult("output_limit", None, dig_output(), b""),
        CommandResult("error", None, b"", b""),
        CommandResult("completed", 3, dig_output(), b"failure"),
        CommandResult("completed", 0, dig_output(flags="qr tc"), b""),
        CommandResult(
            "completed", 0, dig_output().replace(b"api.example.test", b"other.example.test"), b""
        ),
        CommandResult(
            "completed",
            0,
            dig_output().replace(b" IN A 192.0.2.10", b" IN CNAME other.example.test."),
            b"",
        ),
        CommandResult("completed", 0, dig_output().replace(b";; MSG SIZE rcvd: 64", b""), b""),
    ],
)
def test_dns_failures_are_durable_inconclusive_or_unavailable_without_retry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, output: CommandResult
) -> None:
    initialize(tmp_path)
    calls = []

    def command(argv: list[str], **kwargs: Any) -> CommandResult:
        calls.append(argv)
        return output

    monkeypatch.setattr(workflows, "run_bounded", command)
    result = DefensiveWorkflowRunner(tmp_path).run("dns-inventory", {"url": ASSET, "observe": True})
    assert result["status"] == ("unavailable" if output.status == "unavailable" else "inconclusive")
    assert len(calls) == 1
    assert result["observations"] == []
    assert result["evidence_integrity"] == "verified"


@pytest.mark.parametrize(
    "payload",
    [
        {"url": ASSET, "observe": "false"},
        {"url": ASSET, "observe": 1},
        {"url": ASSET, "observe": True, "ports": []},
        {"url": ASSET, "observe": True, "ports": [True]},
        {"url": ASSET, "observe": True, "ports": [443, 443]},
        {"url": ASSET, "observe": True, "ports": list(range(1, 18))},
        {"url": ASSET, "observe": True, "ports": "443"},
        {"url": ASSET, "observe": True, "ports": [0]},
        {"url": ASSET, "observe": True, "ports": [65536]},
        {"url": ASSET, "observe": True, "ports": [443], "artifact_path": "input.json"},
        {"url": ASSET, "observe": True, "ports": [443], "flags": ["-sV"]},
        {"url": ASSET + "private", "observe": True, "ports": [443]},
        {"url": ASSET + "?token=synthetic", "observe": True, "ports": [443]},
        {"url": "https://user:synthetic@api.example.test/", "observe": True, "ports": [443]},
        {"url": "https://*.example.test/", "observe": True, "ports": [443]},
    ],
)
def test_observation_payload_is_strict_and_has_no_arbitrary_execution_surface(
    tmp_path: Path, payload: dict[str, Any]
) -> None:
    with pytest.raises(WorkflowInputError):
        DefensiveWorkflowRunner(tmp_path).run("network-inventory", payload)


def test_network_observation_pins_one_address_and_uses_connect_only_fixed_argv(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    initialize(tmp_path)
    calls: list[list[str]] = []

    def command(
        argv: list[str], *, cwd: str | Path, timeout: float, max_output_bytes: int
    ) -> CommandResult:
        calls.append(argv)
        if argv[0] == "dig":
            kind = argv[argv.index("-t") + 1]
            return CommandResult(
                "completed", 0, dig_output(kind, "192.0.2.10" if kind == "A" else None), b""
            )
        assert argv[0] == "nmap"
        assert argv[-1] == "192.0.2.10"
        assert {
            "-sT",
            "-Pn",
            "-n",
            "--unprivileged",
            "--disable-arp-ping",
            "--no-stylesheet",
        } <= set(argv)
        assert not {"-sS", "-sV", "-sC", "--script", "-A", "-O"} & set(argv)
        assert argv[argv.index("-p") + 1] == "443"
        assert "--max-parallelism" not in argv
        assert "--scan-delay" not in argv
        assert argv[argv.index("--max-rate") + 1] == "1"
        assert timeout <= 20
        return CommandResult(
            "completed",
            0,
            nmap_xml().replace(
                b'<hostnames><hostname name="api.example.test" type="user"/></hostnames>', b""
            ),
            b"",
        )

    monkeypatch.setattr(workflows, "run_bounded", command)
    result = DefensiveWorkflowRunner(tmp_path).run(
        "network-inventory", {"url": ASSET, "observe": True, "ports": [443]}
    )
    assert result["status"] == "observed"
    assert result["selected_asset"] == ASSET
    assert result["pinned_ip"] == "192.0.2.10"
    assert result["observations"][0]["port"] == 443
    assert result["unobserved_ports"] == []
    assert [argv[0] for argv in calls] == ["dig", "dig", "nmap"]


@pytest.mark.parametrize(
    "outcome", ["valid", "invalid", "timeout", "abort", "peer_mismatch", "metadata"]
)
def test_tls_observation_pins_socket_preserves_sni_and_never_disables_validation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, outcome: str
) -> None:
    initialize(tmp_path)
    connected: list[tuple[str, int]] = []
    authorities: list[str] = []
    contexts = []
    closed = []

    def command(argv: list[str], **kwargs: Any) -> CommandResult:
        assert argv[0] == "dig"
        kind = argv[argv.index("-t") + 1]
        return CommandResult(
            "completed", 0, dig_output(kind, "192.0.2.10" if kind == "A" else None), b""
        )

    class Transport:
        def __enter__(self) -> Transport:
            return self

        def __exit__(self, *args: Any) -> None:
            self.close()

        def close(self) -> None:
            closed.append(True)

        def settimeout(self, timeout: float) -> None:
            assert 0 < timeout <= 4

        def connect(self, target: tuple[str, int]) -> None:
            connected.append(target)
            assert target == ("192.0.2.10", 443)
            if outcome == "abort":
                (tmp_path / ".abort").touch()

        def do_handshake(self) -> None:
            if outcome == "invalid":
                raise ssl.SSLCertVerificationError(1, "synthetic validation failure")
            if outcome == "timeout":
                raise TimeoutError("synthetic timeout")

        def getpeername(self) -> tuple[str, int]:
            return ("192.0.2.99" if outcome == "peer_mismatch" else "192.0.2.10"), 443

        def getpeercert(self, binary_form: bool = False) -> Any:
            return (
                b"synthetic-der-certificate"
                if binary_form
                else {
                    "notBefore": "invalid-date"
                    if outcome == "metadata"
                    else "Jan  1 00:00:00 2025 GMT",
                    "notAfter": "Jan  1 00:00:00 2027 GMT",
                }
            )

        def version(self) -> str:
            return "TLSv1.3"

        def cipher(self) -> tuple[str, str, int]:
            return "TLS_AES_256_GCM_SHA384", "TLSv1.3", 256

    class Context:
        check_hostname = True
        verify_mode = ssl.CERT_REQUIRED
        minimum_version = ssl.TLSVersion.MINIMUM_SUPPORTED

        def wrap_socket(
            self, sock: Transport, *, server_hostname: str, do_handshake_on_connect: bool
        ) -> Transport:
            assert self.check_hostname is True
            assert self.verify_mode == ssl.CERT_REQUIRED
            assert self.minimum_version == ssl.TLSVersion.TLSv1_2
            assert do_handshake_on_connect is False
            authorities.append(server_hostname)
            return sock

    def context(*args: Any, **kwargs: Any) -> Context:
        contexts.append(True)
        return Context()

    monkeypatch.setattr(workflows, "run_bounded", command)
    monkeypatch.setattr(socket, "socket", lambda *args, **kwargs: Transport())
    monkeypatch.setattr(ssl, "create_default_context", context)
    result = DefensiveWorkflowRunner(tmp_path).run(
        "tls-inspection", {"url": ASSET, "observe": True}
    )
    blocked = outcome in {"abort", "peer_mismatch"}
    assert result["status"] == (
        "blocked" if blocked else "observed" if outcome == "valid" else "inconclusive"
    )
    assert connected == [("192.0.2.10", 443)]
    assert len(contexts) == 1
    assert closed
    if blocked:
        assert result["observations"] == []
        assert result["process"]["status"] == "error"
    else:
        assert authorities == ["api.example.test"]
        observation = result["observations"][0]
        assert observation["certificate_validation"] == (
            outcome if outcome in {"valid", "invalid"} else "unknown"
        )
        assert result["tool"]["name"] == "python-ssl"
    assert result["independent_verification"] is False


@pytest.mark.parametrize(
    ("workflow", "pattern"), [("network-inventory", r"\bnmap\b"), ("tls-inspection", r"\bssl\b")]
)
def test_forbidden_observation_mode_is_checked_before_even_dns_resolution(
    tmp_path: Path, workflow: str, pattern: str
) -> None:
    initialize(tmp_path, forbidden_command_patterns=[pattern])
    payload: dict[str, Any] = {"url": ASSET, "observe": True}
    if workflow == "network-inventory":
        payload["ports"] = [443]
    result = DefensiveWorkflowRunner(tmp_path).run(workflow, payload)
    assert result["status"] == "blocked"
    assert result["error"]["code"] == "FORBIDDEN_COMMAND"
    assert result["process"]["status"] == "not_run"


@pytest.mark.parametrize("change", ["abort", "roe", "assessment"])
def test_authorization_is_rechecked_between_bounded_actions(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, change: str
) -> None:
    initialize(tmp_path)
    calls = []

    def command(argv: list[str], **kwargs: Any) -> CommandResult:
        calls.append(argv)
        if change == "abort":
            (tmp_path / ".abort").touch()
        elif change == "roe":
            artifact(tmp_path, {"machine_enforcement": {"mode": "audit"}}, "plan/roe.json")
        else:
            (tmp_path / "assessment" / "coverage.sqlite3").unlink()
        return CommandResult("completed", 0, dig_output(), b"")

    monkeypatch.setattr(workflows, "run_bounded", command)
    result = DefensiveWorkflowRunner(tmp_path).run(
        "network-inventory", {"url": ASSET, "observe": True, "ports": [443]}
    )
    assert result["status"] == "blocked"
    assert len(calls) == 1
    assert result["observations"] == []


@pytest.mark.parametrize(
    ("ip", "scope"), [("192.0.2.10", "192.0.2.0/24"), ("2001:db8::10", "2001:db8::/32")]
)
def test_literal_ip_observation_uses_no_dns_and_honors_cidr_permission(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, ip: str, scope: str
) -> None:
    initialize(tmp_path, allowed=[ip], in_scope=[scope])
    calls = []

    def command(argv: list[str], **kwargs: Any) -> CommandResult:
        assert argv[0] == "nmap"
        assert argv[-1] == ip
        assert ("-6" in argv) == (":" in ip)
        calls.append(argv)
        return CommandResult(
            "completed",
            0,
            nmap_xml(ip=ip).replace(b'addrtype="ipv4"', b'addrtype="ipv6"')
            if ":" in ip
            else nmap_xml(ip=ip),
            b"",
        )

    monkeypatch.setattr(workflows, "run_bounded", command)
    authority = f"[{ip}]" if ":" in ip else ip
    result = DefensiveWorkflowRunner(tmp_path).run(
        "network-inventory", {"url": f"https://{authority}/", "observe": True, "ports": [443]}
    )
    assert result["status"] == "observed"
    assert result["resolved_ips"] == [ip]
    assert len(calls) == 1


@pytest.mark.parametrize("address", ["::ffff:169.254.169.254", "fd00:ec2::254", "2001:db8::99"])
def test_a_single_denied_aaaa_answer_blocks_all_target_transport(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, address: str
) -> None:
    initialize(tmp_path, out_of_scope=["2001:db8::99"])
    calls = []

    def command(argv: list[str], **kwargs: Any) -> CommandResult:
        assert argv[0] == "dig"
        calls.append(argv)
        kind = argv[argv.index("-t") + 1]
        return CommandResult(
            "completed", 0, dig_output(kind, "192.0.2.10" if kind == "A" else address), b""
        )

    monkeypatch.setattr(workflows, "run_bounded", command)
    result = DefensiveWorkflowRunner(tmp_path).run(
        "network-inventory", {"url": ASSET, "observe": True, "ports": [443]}
    )
    assert result["status"] == "blocked"
    assert result["error"]["code"] == "RESOLVED_IP_DENIED"
    assert len(calls) == 2


@pytest.mark.parametrize("field", ["authorized_windows", "blackout_windows"])
def test_entire_action_must_fit_roe_windows_not_just_its_start(tmp_path: Path, field: str) -> None:
    now = datetime.now(timezone.utc)
    start, end = (
        (now - timedelta(hours=1), now + timedelta(seconds=2))
        if field == "authorized_windows"
        else (now + timedelta(seconds=2), now + timedelta(hours=1))
    )
    machine: dict[str, Any] = {field: [[start.isoformat(), end.isoformat()]]}
    initialize(tmp_path, **machine)
    result = DefensiveWorkflowRunner(tmp_path).run("dns-inventory", {"url": ASSET, "observe": True})
    assert result["status"] == "blocked"
    assert result["error"]["code"] == "TIME_WINDOW"


def test_url_scoped_authorization_does_not_grant_other_ports(tmp_path: Path) -> None:
    initialize(tmp_path, in_scope=[ASSET])
    result = DefensiveWorkflowRunner(tmp_path).run(
        "network-inventory", {"url": ASSET, "observe": True, "ports": [80, 443]}
    )
    assert result["status"] == "blocked"
    assert result["process"]["status"] == "not_run"


def test_exclusive_workspace_observation_lock_prevents_concurrent_runs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    initialize(tmp_path)
    nested = []

    def command(argv: list[str], **kwargs: Any) -> CommandResult:
        if not nested:
            blocked = DefensiveWorkflowRunner(tmp_path).run(
                "dns-inventory", {"url": ASSET, "observe": True}
            )
            assert blocked["status"] == "blocked"
            assert blocked["error"]["code"] == "OBSERVATION_STORAGE"
            nested.append(blocked)
        kind = argv[argv.index("-t") + 1]
        return CommandResult(
            "completed", 0, dig_output(kind, "192.0.2.10" if kind == "A" else None), b""
        )

    monkeypatch.setattr(workflows, "run_bounded", command)
    result = DefensiveWorkflowRunner(tmp_path).run("dns-inventory", {"url": ASSET, "observe": True})
    assert result["status"] == "observed"
    assert len(nested) == 1


def test_dns_observation_accepts_valid_long_ttl_without_truncation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    initialize(tmp_path)

    def command(argv: list[str], **kwargs: Any) -> CommandResult:
        kind = argv[argv.index("-t") + 1]
        return CommandResult(
            "completed",
            0,
            dig_output(kind, "192.0.2.10" if kind == "A" else None).replace(
                b"60 IN", b"2147483647 IN"
            ),
            b"",
        )

    monkeypatch.setattr(workflows, "run_bounded", command)
    result = DefensiveWorkflowRunner(tmp_path).run("dns-inventory", {"url": ASSET, "observe": True})
    assert result["status"] == "observed"
    assert result["observations"][0]["ttl"] == 2147483647


def test_command_budget_is_recomputed_after_slow_authorization_checks(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    initialize(tmp_path)
    clock = [100.0]
    original = AssessmentStore.dispatch
    timeouts = []

    def delayed_report(
        store: AssessmentStore, action: str, payload: dict[str, Any]
    ) -> dict[str, Any]:
        result = original(store, action, payload)
        if action == "report":
            clock[0] += 14
        return result

    def command(argv: list[str], *, timeout: float, **kwargs: Any) -> CommandResult:
        assert 0 < timeout <= 130 - clock[0]
        timeouts.append(timeout)
        return CommandResult("completed", 0, dig_output(), b"")

    monkeypatch.setattr(AssessmentStore, "dispatch", delayed_report)
    monkeypatch.setattr(time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(workflows, "run_bounded", command)
    result = DefensiveWorkflowRunner(tmp_path).run("dns-inventory", {"url": ASSET, "observe": True})
    assert result["status"] == "inconclusive"
    assert result["error"]["code"] == "DEADLINE"
    assert len(timeouts) == 1


def test_catalog_is_fixed_and_runs_never_overwrite(tmp_path: Path) -> None:
    catalog = workflow_catalog()
    assert all(item["capability_id"] == item["workflow_id"] for item in catalog["workflows"])
    dns = next(item for item in catalog["workflows"] if item["workflow_id"] == "dns-inventory")
    assert dns["artifact_contract"]["schema_version"] == 1
    assert dns["observation_parameters"]["observe"] is True
    assert {item["workflow_id"] for item in catalog["workflows"]} == {
        "network-inventory",
        "dns-inventory",
        "tls-inspection",
        "http-capture-review",
        "sarif-review",
    }
    path = artifact(tmp_path, capture())
    runner = DefensiveWorkflowRunner(tmp_path)
    first = runner.run("http-capture-review", {"url": ASSET, "artifact_path": path})
    second = runner.run("http-capture-review", {"url": ASSET, "artifact_path": path})
    assert first["run_id"] != second["run_id"]
    assert runner.report(first["run_id"]) == first
    assert runner.report(second["run_id"]) == second


def test_network_ports_are_serial_rate_limited_and_preserved_as_separate_artifacts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    initialize(
        tmp_path,
        allowed=["192.0.2.10"],
        in_scope=["192.0.2.10"],
        max_concurrent_connections=1,
        min_inter_request_delay_ms=250,
    )
    clock = [100.0]
    calls: list[tuple[list[str], float]] = []

    def sleep(seconds: float) -> None:
        clock[0] += seconds

    def command(argv: list[str], *, timeout: float, **kwargs: Any) -> CommandResult:
        calls.append((argv, clock[0]))
        assert 0 < timeout <= min(20, 130 - clock[0])
        ports = argv[argv.index("-p") + 1].split(",")
        clock[0] += 0.25
        return CommandResult(
            "completed",
            0,
            nmap_xml(
                ports="".join(
                    f'<port protocol="tcp" portid="{port}"><state state="open"/></port>'
                    for port in ports
                )
            ),
            b"",
        )

    monkeypatch.setattr(time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(time, "sleep", sleep)
    monkeypatch.setattr(workflows, "run_bounded", command)
    result = DefensiveWorkflowRunner(tmp_path).run(
        "network-inventory", {"url": "https://192.0.2.10/", "observe": True, "ports": [443, 80]}
    )
    assert result["status"] == "observed"
    assert [argv[argv.index("-p") + 1] for argv, _ in calls] == ["80", "443"]
    assert calls[1][1] - calls[0][1] >= 1.25
    assert all("--max-parallelism" not in argv for argv, _ in calls)
    assert all(argv[argv.index("--max-rate") + 1] == "1" for argv, _ in calls)
    assert [item["port"] for item in result["observations"]] == [80, 443]
    assert result["unobserved_ports"] == []
    assert len(result["processes"]) == len(result["artifacts"]) == 2
    assert result["artifact"] == result["artifacts"][0]
    for reference in result["artifacts"]:
        assert reference in result["evidence"]
        assert (
            hashlib.sha256((tmp_path / reference["path"]).read_bytes()).hexdigest()
            == reference["sha256"]
        )
    assert DefensiveWorkflowRunner(tmp_path).report(result["run_id"]) == result


def test_serial_network_ports_share_the_original_deadline(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    initialize(tmp_path, allowed=["192.0.2.10"], in_scope=["192.0.2.10"])
    clock = [100.0]
    timeouts = []

    def sleep(seconds: float) -> None:
        clock[0] += seconds

    def command(argv: list[str], *, timeout: float, **kwargs: Any) -> CommandResult:
        timeouts.append(timeout)
        if len(timeouts) == 1:
            clock[0] += 19.5
            return CommandResult(
                "completed",
                0,
                nmap_xml(ports='<port protocol="tcp" portid="80"><state state="open"/></port>'),
                b"",
            )
        clock[0] += timeout
        return CommandResult("timeout", None, b"", b"")

    monkeypatch.setattr(time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(time, "sleep", sleep)
    monkeypatch.setattr(workflows, "run_bounded", command)
    result = DefensiveWorkflowRunner(tmp_path).run(
        "network-inventory",
        {"url": "https://192.0.2.10/", "observe": True, "ports": [80, 443, 8443]},
    )
    assert timeouts == [20, 9.5]
    assert result["status"] == "inconclusive"
    assert result["error"]["code"] == "DEADLINE"
    assert result["observations"] == []
    assert len(result["processes"]) == 2
    assert result["evidence_integrity"] == "verified"


def test_forbidden_later_network_port_blocks_before_dns(tmp_path: Path) -> None:
    initialize(tmp_path, forbidden_command_patterns=[r"-p 443(?:\s|$)"])
    result = DefensiveWorkflowRunner(tmp_path).run(
        "network-inventory", {"url": ASSET, "observe": True, "ports": [80, 443]}
    )
    assert result["status"] == "blocked"
    assert result["error"]["code"] == "FORBIDDEN_COMMAND"
    assert result["process"]["status"] == "not_run"
