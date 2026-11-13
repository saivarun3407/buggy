from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from buggy.cli.__main__ import main


def test_cli_lists_sourced_scenarios_without_creating_an_assessment(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(["assessment", "--workspace", str(tmp_path), "scenarios"]) == 0
    catalog = json.loads(capsys.readouterr().out)
    assert catalog["catalog_version"]
    assert catalog["scenarios"]
    assert not (tmp_path / "assessment").exists()


def _initialize(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> list[str]:
    args = ["assessment", "--workspace", str(tmp_path)]
    assert main([*args, "init", "--name", "threat-fixture", "--scope", "app.example.test"]) == 0
    capsys.readouterr()
    return args


def _enrollment_artifact(enabled: bool = True) -> dict:
    return {
        "schema_version": 1,
        "asset": "https://app.example.test/",
        "observed_at": datetime.now(timezone.utc).isoformat(),
        "evidence_kind": "policy_export",
        "data": {
            "inventory_complete": True,
            "enrollment_policy": {
                "phishing_resistant_reauthentication_required": enabled,
                "managed_device_required": True,
                "change_notifications_enabled": True,
            },
        },
    }


@pytest.mark.parametrize(
    ("case", "status", "exit_code"),
    [("protected", "pass", 0), ("weak", "fail", 1), ("missing", "inconclusive", 3)],
)
def test_cli_evaluates_supplied_policy_without_granting_baseline_coverage(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], case: str, status: str, exit_code: int
) -> None:
    args = _initialize(tmp_path, capsys)
    artifact = _enrollment_artifact(case != "weak")
    if case == "missing":
        artifact["data"] = {}
    (tmp_path / "policy.json").write_text(json.dumps(artifact))
    assert (
        main([*args, "evaluate-scenario", "identity.mfa-enrollment", "--evidence", "policy.json"])
        == exit_code
    )
    result = json.loads(capsys.readouterr().out)
    assert result["status"] == status
    assert result["evaluation_mode"] == "supplied_artifact"
    assert result["evidence"][0]["path"] == "policy.json"
    assert len(result["evidence"][0]["sha256"]) == 64
    assert result["baseline_coverage_updated"] is False
    assert main([*args, "report"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["revision"] == 1
    assert report["complete"] is False


def test_scenario_workflow_refuses_out_of_scope_artifacts(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    args = _initialize(tmp_path, capsys)
    artifact = _enrollment_artifact()
    artifact["asset"] = "https://outside.example.test/"
    (tmp_path / "policy.json").write_text(json.dumps(artifact))
    assert (
        main([*args, "evaluate-scenario", "identity.mfa-enrollment", "--evidence", "policy.json"])
        == 2
    )
    assert "allowed_hosts" in capsys.readouterr().err


def _kev_artifacts(tmp_path: Path, applicability: str = "affected", stale: bool = False) -> None:
    now = datetime.now(timezone.utc)
    catalog = {
        "catalogVersion": now.strftime("%Y.%m.%d"),
        "dateReleased": (now - timedelta(days=30 if stale else 0)).isoformat(),
        "count": 1,
        "vulnerabilities": [
            {
                "cveID": "CVE-2026-10000",
                "vendorProject": "Example",
                "product": "Fixture",
                "vulnerabilityName": "Synthetic vulnerability",
                "shortDescription": "Synthetic fixture only",
                "dateAdded": (now - timedelta(days=60)).date().isoformat(),
                "dueDate": now.date().isoformat(),
                "requiredAction": "Review supplied vendor guidance",
            }
        ],
    }
    observation = {
        "schema_version": 1,
        "asset": "https://app.example.test/",
        "observed_at": now.isoformat(),
        "evidence_kind": "scanner_export",
        "vulnerabilities": [
            {
                "cve_id": "CVE-2026-10000",
                "applicability": applicability,
                "basis": "scanner_result",
            }
        ],
    }
    (tmp_path / "kev.json").write_text(json.dumps(catalog))
    (tmp_path / "observations.json").write_text(json.dumps(observation))


@pytest.mark.parametrize(
    ("applicability", "stale", "exit_code", "priority"),
    [
        ("affected", False, 1, "urgent"),
        ("unknown", False, 3, "investigate"),
        ("not_affected", False, 0, "not_applicable"),
        ("affected", True, 3, "investigate"),
    ],
)
def test_kev_cli_keeps_unknown_and_stale_data_out_of_clean_ci_results(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    applicability: str,
    stale: bool,
    exit_code: int,
    priority: str,
) -> None:
    args = _initialize(tmp_path, capsys)
    _kev_artifacts(tmp_path, applicability, stale)
    assert (
        main(
            [
                *args,
                "prioritize-kev",
                "--catalog",
                "kev.json",
                "--observations",
                "observations.json",
                "--fail-on-urgent",
            ]
        )
        == exit_code
    )
    result = json.loads(capsys.readouterr().out)
    assert result["records"][0]["priority"] == priority
    assert {item["path"] for item in result["evidence"]} == {"kev.json", "observations.json"}
    assert result["revision"] == 1
    assert result["baseline_coverage_updated"] is False


@pytest.mark.parametrize("offset", [0, 2, 1000])
def test_kev_ci_gate_uses_all_priorities_even_on_empty_or_nonurgent_pages(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], offset: int
) -> None:
    args = _initialize(tmp_path, capsys)
    _kev_artifacts(tmp_path)
    observation_path = tmp_path / "observations.json"
    observation = json.loads(observation_path.read_text())
    observation["vulnerabilities"].insert(
        0,
        {
            "cve_id": "CVE-2026-99999",
            "applicability": "not_affected",
            "basis": "scanner_result",
        },
    )
    observation_path.write_text(json.dumps(observation))
    assert (
        main(
            [
                *args,
                "prioritize-kev",
                "--catalog",
                "kev.json",
                "--observations",
                "observations.json",
                "--offset",
                str(offset),
                "--limit",
                "1",
                "--fail-on-urgent",
            ]
        )
        == 1
    )
    result = json.loads(capsys.readouterr().out)
    assert result["total"] == 2
    assert result["priority_counts"]["urgent"] == 1
    assert len(result["records"]) == (1 if offset == 0 else 0)
    if offset == 0:
        assert result["records"][0]["priority"] == "not_applicable"
        assert result["next_offset"] == 1


@pytest.fixture
def threat_daemon(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    import importlib

    import httpx
    from fastapi.testclient import TestClient

    from buggy.backends.http_sandbox import HTTPSandbox

    app_module = importlib.import_module("buggy.sandbox_server.app")
    monkeypatch.setenv("SANDBOX_ROOT_DIR", str(tmp_path))
    monkeypatch.setattr(app_module, "_required_token", "threat-fixture-token")
    daemon = TestClient(app_module.app)
    client_type = httpx.Client

    def transport(request: httpx.Request) -> httpx.Response:
        response = daemon.request(
            request.method, request.url.path, headers=dict(request.headers), content=request.content
        )
        return httpx.Response(response.status_code, json=response.json())

    def http_client(*args, **kwargs):
        return client_type(*args, transport=httpx.MockTransport(transport), **kwargs)

    monkeypatch.setattr(httpx, "Client", http_client)
    sandbox = HTTPSandbox("http://assessment.test", token="threat-fixture-token")
    state = {"engagement_name": "threat-fixture", "workspace_path": "/workspace/threat-fixture"}
    sandbox.assessment(
        "initialize",
        {
            "engagement_name": state["engagement_name"],
            "profile": "external",
            "allowed_hosts": ["app.example.test", "*.allowed.example.test"],
            "denied_hosts": ["denied.allowed.example.test"],
        },
        workspace_path=state["workspace_path"],
    )
    workspace = tmp_path / "threat-fixture"
    (workspace / "policy.json").write_text(json.dumps(_enrollment_artifact()))
    _kev_artifacts(workspace)
    try:
        yield sandbox, state, workspace, daemon
    finally:
        sandbox.close()
        daemon.close()


def test_http_threat_checks_share_auth_scope_and_real_evidence_reader(threat_daemon) -> None:
    sandbox, state, workspace, daemon = threat_daemon
    result = sandbox.assessment(
        "evaluate_scenario",
        {
            "scenario_id": "identity.mfa-enrollment",
            "evidence_path": "policy.json",
        },
        workspace_path=state["workspace_path"],
    )
    assert result["status"] == "pass"
    assert result["revision"] == 1
    assert result["baseline_coverage_updated"] is False
    assert sandbox.assessment("scenario_catalog", {}, workspace_path=state["workspace_path"])[
        "scenarios"
    ]
    kev = sandbox.assessment(
        "prioritize_kev",
        {
            "catalog_path": "kev.json",
            "observation_path": "observations.json",
        },
        workspace_path=state["workspace_path"],
    )
    assert kev["priority_counts"]["urgent"] == 1
    assert (
        daemon.post(
            "/assessment",
            json={
                "workspace_path": state["workspace_path"],
                "action": "scenario_catalog",
                "payload": {},
            },
        ).status_code
        == 401
    )
    artifact = _enrollment_artifact()
    artifact["asset"] = "https://denied.allowed.example.test/"
    (workspace / "denied.json").write_text(json.dumps(artifact))
    response = daemon.post(
        "/assessment",
        headers={"Authorization": "Bearer threat-fixture-token"},
        json={
            "workspace_path": state["workspace_path"],
            "action": "evaluate_scenario",
            "payload": {"scenario_id": "identity.mfa-enrollment", "evidence_path": "denied.json"},
        },
    )
    assert response.status_code == 422
    assert "denied_hosts" in response.json()["detail"]


def test_threat_tools_are_registered_quarantined_and_use_the_real_http_contract(
    threat_daemon, monkeypatch: pytest.MonkeyPatch
) -> None:
    from buggy.middleware.untrusted_output import UNTRUSTED_TOOL_NAMES
    from buggy.tools import assessment

    sandbox, state, _, _ = threat_daemon
    monkeypatch.setattr(assessment, "build_sandbox_backend", lambda config: sandbox)
    names = {
        "assessment_scenario_catalog",
        "assessment_evaluate_scenario",
        "assessment_prioritize_kev",
    }
    assert names <= {tool.name for tool in assessment.ASSESSMENT_TOOLS}
    assert names <= UNTRUSTED_TOOL_NAMES
    catalog = json.loads(assessment.assessment_scenario_catalog.invoke({"state": state}))
    assert len(catalog["scenarios"]) == 6
    result = json.loads(
        assessment.assessment_evaluate_scenario.invoke(
            {
                "state": state,
                "scenario_id": "identity.mfa-enrollment",
                "evidence_path": "policy.json",
            }
        )
    )
    assert result["status"] == "pass"
    priority = json.loads(
        assessment.assessment_prioritize_kev.invoke(
            {
                "state": state,
                "catalog_path": "kev.json",
                "observation_path": "observations.json",
            }
        )
    )
    assert priority["records"][0]["priority"] == "urgent"
    for name in names:
        fields = getattr(assessment, name).tool_call_schema.model_json_schema()["properties"]
        assert "state" not in fields and "workspace_path" not in fields


@pytest.mark.parametrize("path_kind", ["traversal", "absolute", "symlink", "private_fields"])
def test_threat_artifacts_remain_confined_and_errors_do_not_echo_content(
    threat_daemon, path_kind: str
) -> None:
    from buggy.backends.http_sandbox import SandboxError

    sandbox, state, workspace, _ = threat_daemon
    artifact = _enrollment_artifact()
    artifact["private"] = "SYNTHETIC_SECRET_MUST_NOT_ESCAPE"
    outside = workspace.parent / "outside.json"
    outside.write_text(json.dumps(artifact))
    (workspace / "linked.json").symlink_to(outside)
    (workspace / "private.json").write_text(json.dumps(artifact))
    paths = {
        "traversal": "../outside.json",
        "absolute": str(outside),
        "symlink": "linked.json",
        "private_fields": "private.json",
    }
    with pytest.raises(SandboxError) as error:
        sandbox.assessment(
            "evaluate_scenario",
            {
                "scenario_id": "identity.mfa-enrollment",
                "evidence_path": paths[path_kind],
            },
            workspace_path=state["workspace_path"],
        )
    assert "SYNTHETIC_SECRET_MUST_NOT_ESCAPE" not in str(error.value)
    report = sandbox.assessment("report", {}, workspace_path=state["workspace_path"])
    assert report["revision"] == 1


def test_langgraph_injects_scope_into_threat_tools_without_model_supplied_state(
    threat_daemon, monkeypatch: pytest.MonkeyPatch
) -> None:
    from typing import Annotated, TypedDict

    from langchain_core.messages import AIMessage
    from langgraph.graph import END, START, StateGraph, add_messages
    from langgraph.prebuilt import ToolNode

    from buggy.tools import assessment

    sandbox, state, _, _ = threat_daemon
    monkeypatch.setattr(assessment, "build_sandbox_backend", lambda config: sandbox)
    ThreatState = TypedDict(
        "ThreatState",
        {
            "messages": Annotated[list, add_messages],
            "engagement_name": str,
            "workspace_path": str,
        },
    )
    graph = StateGraph(ThreatState)
    graph.add_node("tools", ToolNode([assessment.assessment_evaluate_scenario]))
    graph.add_edge(START, "tools")
    graph.add_edge("tools", END)
    result = graph.compile().invoke(
        {
            **state,
            "messages": [
                AIMessage(
                    content="",
                    tool_calls=[
                        {
                            "name": "assessment_evaluate_scenario",
                            "id": "threat-fixture",
                            "args": {
                                "scenario_id": "identity.mfa-enrollment",
                                "evidence_path": "policy.json",
                            },
                        }
                    ],
                )
            ],
        },
        config={"configurable": state},
    )
    message = result["messages"][-1]
    assert message.status == "success"
    assert json.loads(message.content)["status"] == "pass"


def test_kev_workflow_accepts_ignored_url_components_without_echoing_them(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    args = _initialize(tmp_path, capsys)
    _kev_artifacts(tmp_path)
    path = tmp_path / "observations.json"
    observation = json.loads(path.read_text())
    observation["asset"] = "https://app.example.test/path?token=PRIVATE_URL_MARKER#section"
    path.write_text(json.dumps(observation))
    assert (
        main(
            [
                *args,
                "prioritize-kev",
                "--catalog",
                "kev.json",
                "--observations",
                "observations.json",
            ]
        )
        == 0
    )
    output = capsys.readouterr().out
    assert json.loads(output)["records"][0]["priority"] == "urgent"
    assert "PRIVATE_URL_MARKER" not in output


@pytest.mark.parametrize("artifact_name", ["kev.json", "observations.json"])
def test_kev_workflow_uses_the_bounded_import_size_not_the_header_capture_size(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], artifact_name: str
) -> None:
    args = _initialize(tmp_path, capsys)
    _kev_artifacts(tmp_path)
    path = tmp_path / artifact_name
    path.write_text(path.read_text() + " " * (2 * 1024 * 1024))
    assert (
        main(
            [
                *args,
                "prioritize-kev",
                "--catalog",
                "kev.json",
                "--observations",
                "observations.json",
            ]
        )
        == 0
    )
    assert json.loads(capsys.readouterr().out)["records"][0]["priority"] == "urgent"


@pytest.mark.parametrize("suffix", ["", "/nested"])
def test_http_rejects_workspace_aliases_to_another_engagement(threat_daemon, suffix: str) -> None:
    from buggy.sandbox_kernel.assessment import AssessmentStore

    _, _, workspace, daemon = threat_daemon
    (workspace / "nested").mkdir()
    AssessmentStore(workspace / "nested").dispatch(
        "initialize",
        {
            "engagement_name": "nested-fixture",
            "profile": "external",
            "allowed_hosts": ["app.example.test"],
        },
    )
    (workspace.parent / "alias").symlink_to(workspace, target_is_directory=True)
    response = daemon.post(
        "/assessment",
        headers={"Authorization": "Bearer threat-fixture-token"},
        json={
            "workspace_path": "/workspace/alias" + suffix,
            "action": "report",
            "payload": {},
        },
    )
    assert response.status_code == 422


def test_store_rejects_symlinked_workspace_roots(tmp_path: Path) -> None:
    from buggy.sandbox_kernel.assessment import AssessmentError, AssessmentStore

    real = tmp_path / "real"
    real.mkdir()
    alias = tmp_path / "alias"
    alias.symlink_to(real, target_is_directory=True)
    with pytest.raises(AssessmentError, match="symlink"):
        AssessmentStore(alias)


@pytest.mark.parametrize("artifact_name", ["kev.json", "observations.json"])
def test_kev_import_capture_limit_is_enforced_without_partial_results(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], artifact_name: str
) -> None:
    args = _initialize(tmp_path, capsys)
    _kev_artifacts(tmp_path)
    path = tmp_path / artifact_name
    path.write_text(path.read_text() + " " * (16 * 1024 * 1024))
    assert (
        main(
            [
                *args,
                "prioritize-kev",
                "--catalog",
                "kev.json",
                "--observations",
                "observations.json",
            ]
        )
        == 2
    )
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "16 MiB" in captured.err


def test_scenario_request_cannot_override_its_capture_limit(threat_daemon) -> None:
    from buggy.backends.http_sandbox import SandboxError

    sandbox, state, workspace, _ = threat_daemon
    path = workspace / "policy.json"
    path.write_text(path.read_text() + " " * (2 * 1024 * 1024))
    with pytest.raises(SandboxError, match="2 MiB"):
        sandbox.assessment(
            "evaluate_scenario",
            {
                "scenario_id": "identity.mfa-enrollment",
                "evidence_path": "policy.json",
                "capture_limit": 16 * 1024 * 1024,
            },
            workspace_path=state["workspace_path"],
        )
