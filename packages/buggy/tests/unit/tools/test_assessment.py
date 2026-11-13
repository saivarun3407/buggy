from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from deepagents.backends.protocol import FileDownloadResponse


class LocalAssessmentSandbox:
    def __init__(self, root: Path) -> None:
        self.root = root

    def assessment(
        self, action: str, payload: dict[str, Any], *, workspace_path: str
    ) -> dict[str, Any]:
        from buggy.sandbox_kernel.assessment import AssessmentStore

        return AssessmentStore(self.root / workspace_path.removeprefix("/workspace/")).dispatch(
            action, payload
        )

    def capabilities(self, *, probe: bool = False) -> dict[str, Any]:
        from buggy.sandbox_kernel.capabilities import inspect_capabilities

        return inspect_capabilities(probe=probe)

    def workflow(
        self, action: str, payload: dict[str, Any], *, workspace_path: str
    ) -> dict[str, Any]:
        from buggy.sandbox_kernel.defensive_workflows import (
            DefensiveWorkflowRunner,
            workflow_catalog,
        )

        if action == "catalog":
            return workflow_catalog()
        parameters = dict(payload)
        workflow_id = parameters.pop("workflow_id")
        assert parameters["observe"] is False
        return DefensiveWorkflowRunner(self.root / workspace_path.removeprefix("/workspace/")).run(
            workflow_id, parameters
        )

    def download_files(self, paths: list[str]) -> list[FileDownloadResponse]:
        return [
            FileDownloadResponse(
                path=path, content=(self.root / path.removeprefix("/workspace/")).read_bytes()
            )
            for path in paths
        ]


def test_assessment_tools_refuse_missing_engagement_context() -> None:
    from buggy.tools.assessment import AssessmentToolError, assessment_status

    with pytest.raises(AssessmentToolError, match="engagement"):
        assessment_status.invoke({"state": {}}, config={})


def test_assessment_initializes_only_from_engagement_plan_and_roe(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from buggy.tools import assessment as module

    plan = tmp_path / "client-one" / "plan"
    plan.mkdir(parents=True)
    (plan / "roe.json").write_text(json.dumps({"in_scope": [{"target": "app.example.test"}]}))
    (plan / "assessment.json").write_text(
        json.dumps({"profile": "external", "allowed_hosts": ["unapproved.test"]})
    )
    sandbox = LocalAssessmentSandbox(tmp_path)
    monkeypatch.setattr(module, "build_sandbox_backend", lambda config: sandbox)
    state = {"engagement_name": "client-one", "workspace_path": "/workspace/client-one"}
    module.assessment_initialize.invoke({"state": state})
    sandbox.assessment(
        "import",
        {
            "operations": [{"url": "https://app.example.test/", "method": "GET"}],
            "source": {"id": "client-spec", "kind": "openapi", "status": "ok"},
        },
        workspace_path="/workspace/client-one",
    )
    inventory = json.loads(module.assessment_status.invoke({"state": state, "view": "inventory"}))
    assert inventory["total"] == 1
    from buggy.sandbox_kernel.assessment import AssessmentError

    with pytest.raises(AssessmentError):
        sandbox.assessment(
            "import",
            {
                "operations": [{"url": "https://unapproved.test/", "method": "GET"}],
                "source": {"id": "bad-spec", "kind": "openapi", "status": "ok"},
            },
            workspace_path="/workspace/client-one",
        )


@pytest.fixture
def assessment_context(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[Any, dict, Path]:
    from buggy.tools import assessment as module

    workspace = tmp_path / "client-one"
    plan = workspace / "plan"
    plan.mkdir(parents=True)
    (plan / "roe.json").write_text(
        json.dumps(
            {
                "in_scope": [{"target": "*.example.test"}],
                "out_of_scope": [{"target": "excluded.example.test"}],
            }
        )
    )
    (plan / "assessment.json").write_text(json.dumps({"profile": "external"}))
    monkeypatch.setattr(
        module, "build_sandbox_backend", lambda config: LocalAssessmentSandbox(tmp_path)
    )
    state = {"engagement_name": "client-one", "workspace_path": "/workspace/client-one"}
    module.assessment_initialize.invoke({"state": state})
    return module, state, workspace


def test_defensive_workflow_tools_are_artifact_only_and_scope_bound(assessment_context) -> None:
    from datetime import datetime, timezone

    from buggy.middleware.untrusted_output import UNTRUSTED_TOOL_NAMES

    module, state, workspace = assessment_context
    capture = {
        "source": "capture",
        "url": "https://app.example.test/",
        "method": "GET",
        "captured_at": datetime.now(timezone.utc).isoformat(),
        "status_code": 200,
        "headers": {"X-Content-Type-Options": "nosniff"},
    }
    (workspace / "capture.json").write_text(json.dumps(capture))
    assert (
        len(json.loads(module.assessment_capabilities.invoke({"state": state}))["capabilities"])
        == 5
    )
    assert (
        len(json.loads(module.assessment_workflow_catalog.invoke({"state": state}))["workflows"])
        == 5
    )
    arguments = {
        "state": state,
        "workflow_id": "http-capture-review",
        "url": capture["url"],
        "artifact_path": "capture.json",
        "observe": True,
    }
    result = json.loads(module.assessment_run_workflow.invoke(arguments))
    assert result["mode"] == "supplied_artifact"
    assert result["baseline_coverage_updated"] is False
    assert "observe" not in module.assessment_run_workflow.args
    with pytest.raises(module.AssessmentToolError, match="scope"):
        module.assessment_run_workflow.invoke(arguments | {"url": "https://excluded.example.test/"})
    names = {"assessment_capabilities", "assessment_workflow_catalog", "assessment_run_workflow"}
    assert names <= UNTRUSTED_TOOL_NAMES
    assert names <= {tool.name for tool in module.ASSESSMENT_TOOLS}


def test_assessment_import_keeps_every_operation_and_enforces_roe_exclusions(
    assessment_context,
) -> None:
    module, state, workspace = assessment_context
    spec = {
        "openapi": "3.0.0",
        "paths": {f"/items/{i}": {"get": {}} for i in range(137)},
    }
    (workspace / "spec.json").write_text(json.dumps(spec))
    module.assessment_import.invoke(
        {
            "state": state,
            "path": "spec.json",
            "kind": "openapi",
            "base_url": "https://app.example.test",
        }
    )
    page = json.loads(
        module.assessment_status.invoke({"state": state, "view": "inventory", "limit": 1000})
    )
    assert page["total"] == len(page["operations"]) == 137
    with pytest.raises(module.AssessmentToolError, match="scope"):
        module.assessment_import.invoke(
            {
                "state": state,
                "path": "spec.json",
                "kind": "openapi",
                "base_url": "https://excluded.example.test",
            }
        )
    assert (
        json.loads(module.assessment_status.invoke({"state": state, "view": "inventory"}))["total"]
        == 137
    )


def test_assessment_tool_arguments_cannot_select_another_workspace() -> None:
    from buggy.tools.assessment import ASSESSMENT_TOOLS

    for assessment_tool in ASSESSMENT_TOOLS:
        properties = assessment_tool.tool_call_schema.model_json_schema()["properties"]
        assert "state" not in properties
        assert "config" not in properties
        assert "workspace_path" not in properties


def test_assessment_outputs_are_quarantined_as_untrusted_data() -> None:
    from buggy.middleware.untrusted_output import UNTRUSTED_TOOL_NAMES
    from buggy.tools.assessment import ASSESSMENT_TOOLS

    assert {tool.name for tool in ASSESSMENT_TOOLS} <= UNTRUSTED_TOOL_NAMES


def test_assessment_checks_captured_headers_and_keeps_attestations_distinct(
    assessment_context,
) -> None:
    module, state, workspace = assessment_context
    (workspace / "operations.json").write_text(
        json.dumps({"operations": [{"url": "https://app.example.test/items", "method": "GET"}]})
    )
    module.assessment_import.invoke(
        {"state": state, "path": "operations.json", "kind": "observations"}
    )
    report = json.loads(module.assessment_status.invoke({"state": state, "view": "report"}))
    cases = {case["control_id"]: case for case in report["cases"]}
    capture = {
        "url": "https://app.example.test/items",
        "method": "GET",
        "status_code": 200,
        "headers": {"X-Content-Type-Options": "nosniff"},
        "captured_at": "2026-01-01T00:00:00Z",
        "source": "capture",
    }
    (workspace / "response.json").write_text(json.dumps(capture))
    checked = json.loads(
        module.assessment_check_headers.invoke(
            {
                "state": state,
                "case_id": cases["http.nosniff"]["case_id"],
                "evidence_path": "response.json",
            }
        )
    )
    assert checked["case"]["status"] == "pass"
    assert checked["case"]["evaluation_mode"] == "deterministic"
    attested = json.loads(
        module.assessment_record_result.invoke(
            {
                "state": state,
                "case_id": cases["http.hsts"]["case_id"],
                "status": "fail",
                "evidence_paths": ["response.json"],
                "rationale": "HSTS was absent in this captured response.",
            }
        )
    )
    assert attested["case"]["status"] == "fail"
    assert attested["case"]["evaluation_mode"] == "attested"
    report = json.loads(module.assessment_status.invoke({"state": state, "view": "report"}))
    assert report["status_counts"]["blocked"] == 2
    assert report["complete"] is False


@pytest.mark.parametrize("workspace", ["/workspace/client-one/", "  /workspace/client-one  "])
def test_assessment_tools_use_the_normalized_workspace(assessment_context, workspace: str) -> None:
    module, state, _ = assessment_context
    result = json.loads(
        module.assessment_status.invoke({"state": {**state, "workspace_path": workspace}})
    )
    assert result["engagement_name"] == "client-one"


@pytest.mark.parametrize("field", ["workspace_path", "engagement_name"])
def test_explicit_invalid_run_context_does_not_reuse_stale_state(
    assessment_context, field: str
) -> None:
    module, state, _ = assessment_context
    with pytest.raises(module.AssessmentToolError, match="engagement"):
        module.assessment_status.invoke({"state": state}, config={"configurable": {field: ""}})


def test_langgraph_injects_context_without_model_supplied_workspace(assessment_context) -> None:
    from typing import Annotated, TypedDict

    from langchain_core.messages import AIMessage
    from langgraph.graph import END, START, StateGraph, add_messages
    from langgraph.prebuilt import ToolNode

    module, state, _ = assessment_context

    AssessmentState = TypedDict(
        "AssessmentState",
        {
            "messages": Annotated[list, add_messages],
            "engagement_name": str,
            "workspace_path": str,
        },
    )

    builder = StateGraph(AssessmentState)
    builder.add_node("tools", ToolNode([module.assessment_status]))
    builder.add_edge(START, "tools")
    builder.add_edge("tools", END)
    result = builder.compile().invoke(
        {
            **state,
            "messages": [
                AIMessage(
                    content="",
                    tool_calls=[
                        {
                            "name": "assessment_status",
                            "args": {"view": "inventory"},
                            "id": "coverage-fixture",
                        }
                    ],
                )
            ],
        },
        config={"configurable": state},
    )
    message = result["messages"][-1]
    assert message.status == "success"
    assert json.loads(message.content)["total"] == 0
