from __future__ import annotations

import hashlib
import json
import socket
import sqlite3
import subprocess
import sys
from contextlib import closing
from pathlib import Path
from typing import Any

import pytest

from buggy.cli.__main__ import main
from buggy.sandbox_kernel.assessment import AssessmentStore


@pytest.fixture
def context_workspace(tmp_path: Path) -> tuple[Path, AssessmentStore]:
    tmp_path = tmp_path / "context-fixture"
    tmp_path.mkdir()
    store = AssessmentStore(tmp_path)
    store.dispatch(
        "initialize",
        {
            "engagement_name": "context-fixture",
            "profile": "external",
            "allowed_hosts": ["app.example.test"],
        },
    )
    store.dispatch(
        "import",
        {
            "source": {"id": "fixture", "kind": "manual", "status": "ok"},
            "operations": [
                {
                    "url": "https://app.example.test/PRIVATE_CONTEXT_SENTINEL?token=PRIVATE_CONTEXT_SENTINEL",
                    "method": "GET",
                }
            ],
        },
    )
    (tmp_path / "plan").mkdir()
    (tmp_path / "plan" / "opplan.json").write_text(
        json.dumps(
            {
                "schema_version": "1",
                "engagement_name": "context-fixture",
                "objectives": [
                    {
                        "id": "objective-a",
                        "status": "completed",
                        "phase": "recon",
                        "goal": "PRIVATE_CONTEXT_SENTINEL",
                        "notes": "Do not export raw instructions or secrets",
                    }
                ],
            }
        )
    )
    return tmp_path, store


def test_cli_snapshot_is_redacted_markdown_and_does_not_change_the_ledger(
    context_workspace, capsys: pytest.CaptureFixture[str]
) -> None:
    workspace, store = context_workspace
    before = store.dispatch("report", {})["revision"]
    assert main(["assessment", "--workspace", str(workspace), "snapshot"]) == 0
    markdown = capsys.readouterr().out
    assert markdown.startswith("# Engagement metadata snapshot")
    assert "context\\-fixture" in markdown
    assert "https://app\\.example\\.test" in markdown
    assert "completed" in markdown
    assert "PRIVATE_CONTEXT_SENTINEL" not in markdown
    assert "No records exported; no clean-state conclusion" in markdown
    assert store.dispatch("report", {})["revision"] == before


def test_snapshot_refuses_a_different_engagement_label(context_workspace) -> None:
    _, store = context_workspace
    with pytest.raises(ValueError, match="engagement"):
        store.dispatch("context_sources", {"engagement_name": "other-client"})


def test_real_cli_can_redirect_the_snapshot_to_a_markdown_file(context_workspace) -> None:
    workspace, _ = context_workspace
    output = workspace / "context.md"
    with output.open("w") as stream:
        result = subprocess.run(
            [
                sys.executable,
                "-B",
                "-m",
                "buggy.cli",
                "assessment",
                "--workspace",
                str(workspace),
                "snapshot",
            ],
            stdout=stream,
            stderr=subprocess.PIPE,
            text=True,
            timeout=120,
        )
    assert result.returncode == 0, result.stderr
    assert "PRIVATE_CONTEXT_SENTINEL" not in output.read_text()
    assert "No new authorizations or model execution" in output.read_text()


def test_snapshot_combines_scoped_graph_and_observed_skill_metadata(
    context_workspace, monkeypatch
) -> None:
    from buggy import context_export
    from buggy.middleware.kg_internal.store import KGStore

    _, store = context_workspace
    requests, closed = [], []

    class Graph:
        def execute_read(self, query, params, *, engagement):
            requests.append((query, params, engagement))
            if "count(n)" in query:
                return [{"total": 1}]
            return [
                {
                    "engagement": engagement,
                    "id": "PRIVATE_CONTEXT_SENTINEL",
                    "kind": "Vulnerability",
                    "cve_id": "CVE-2024-12345",
                    "cwe_id": "CWE-79",
                    "severity": "high",
                    "status": "confirmed",
                    "host": "app.example.test",
                    "port": 443,
                    "protocol": "https",
                }
            ]

        def close(self):
            closed.append(True)

    monkeypatch.setattr(KGStore, "from_env", lambda: Graph())
    local = store.dispatch("context_sources", {})
    snapshot = context_export.export_snapshot(
        local,
        include_graph=True,
        graph_scope="tenant.context-fixture",
        messages=[
            {
                "content": "PRIVATE_CONTEXT_SENTINEL",
                "tool_calls": [
                    {"name": "load_skill", "args": {"name_or_path": "defensive_review"}}
                ],
            }
        ],
    )
    assert snapshot["source_status"]["findings"] == "ok"
    assert snapshot["source_status"]["skills"] == "ok"
    assert "CVE\\-2024\\-12345" in snapshot["markdown"]
    assert "defensive\\_review" in snapshot["markdown"]
    assert "PRIVATE_CONTEXT_SENTINEL" not in snapshot["markdown"]
    assert all(
        params["engagement"] == scope == "tenant.context-fixture" for _, params, scope in requests
    )
    assert closed == [True]
    assert snapshot["sha256"] == hashlib.sha256(snapshot["markdown"].encode()).hexdigest()


def test_active_session_snapshot_uses_authenticated_workspace_sources(
    context_workspace, monkeypatch
) -> None:
    import importlib

    from fastapi.testclient import TestClient

    from buggy.middleware.untrusted_output import UNTRUSTED_TOOL_NAMES
    from buggy.tools import assessment

    workspace, _ = context_workspace
    app_module = importlib.import_module("buggy.sandbox_server.app")
    monkeypatch.setenv("SANDBOX_ROOT_DIR", str(workspace.parent))
    monkeypatch.setattr(app_module, "_required_token", "context-fixture-token")
    monkeypatch.setenv("SANDBOX_TOKEN", "context-fixture-token")
    with TestClient(app_module.app) as client:

        class Sandbox:
            def assessment(self, action, payload, *, workspace_path):
                response = client.post(
                    "/assessment",
                    headers={"Authorization": "Bearer context-fixture-token"},
                    json={"workspace_path": workspace_path, "action": action, "payload": payload},
                )
                assert response.status_code == 200, response.text
                return response.json()

        monkeypatch.setattr(assessment, "build_sandbox_backend", lambda config: Sandbox())
        state = {
            "engagement_name": "context-fixture",
            "workspace_path": "/workspace/context-fixture",
            "messages": [],
        }
        result = json.loads(
            assessment.assessment_context_snapshot.invoke({"state": state, "include_graph": False})
        )
        assert result["source_status"]["coverage"] == "ok"
        assert result["source_status"]["skills"] == "ok"
        assert result["source_status"]["runtime"] == "ok"
        assert "PRIVATE_CONTEXT_SENTINEL" not in result["markdown"]
        assert "assessment_context_snapshot" in UNTRUSTED_TOOL_NAMES
        assert "assessment_context_snapshot" in {
            tool.name for tool in assessment.ASSESSMENT_REVIEW_TOOLS
        }
        assert (
            client.post(
                "/assessment",
                json={
                    "workspace_path": state["workspace_path"],
                    "action": "context_sources",
                    "payload": {},
                },
            ).status_code
            == 401
        )


def test_cli_graph_outage_stays_partial_without_exporting_exception_details(
    context_workspace, monkeypatch, capsys
) -> None:
    from buggy.middleware.kg_internal.store import KGStore

    workspace, _ = context_workspace

    def unavailable():
        raise RuntimeError("PRIVATE_CONTEXT_SENTINEL")

    monkeypatch.setattr(KGStore, "from_env", unavailable)
    assert (
        main(
            [
                "assessment",
                "--workspace",
                str(workspace),
                "snapshot",
                "--include-kg",
                "--kg-scope",
                "tenant.context-fixture",
                "--require-complete",
            ]
        )
        == 3
    )
    markdown = capsys.readouterr().out
    assert "Status: error" in markdown
    assert "PRIVATE_CONTEXT_SENTINEL" not in markdown


def test_snapshot_validates_local_scope_before_opening_the_graph(
    context_workspace, monkeypatch
) -> None:
    from buggy.context_export import ContextExportError, export_snapshot
    from buggy.middleware.kg_internal.store import KGStore

    _, store = context_workspace
    local = store.dispatch("context_sources", {})
    local["sources"]["scope"]["engagement"] = "other-client"
    opened = []

    def unavailable():
        opened.append(True)
        raise RuntimeError("Unexpected graph access")

    monkeypatch.setattr(KGStore, "from_env", unavailable)
    with pytest.raises(ContextExportError, match="engagement"):
        export_snapshot(local, include_graph=True, graph_scope="tenant.context-fixture")
    assert opened == []


def test_snapshot_rejects_cross_engagement_objectives_beyond_the_row_limit(
    context_workspace,
) -> None:
    workspace, store = context_workspace
    path = workspace / "plan" / "opplan.json"
    plan = json.loads(path.read_text())
    plan["objectives"].append(
        {"id": "other", "engagement_name": "other-client", "status": "completed", "phase": "recon"}
    )
    path.write_text(json.dumps(plan))
    source = store.dispatch("context_sources", {"max_rows": 1})["sources"]["objectives"]
    assert source["status"] == "error"


def test_cli_snapshot_without_a_ledger_discloses_unavailable_sources(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert (
        main(
            [
                "assessment",
                "--workspace",
                str(tmp_path),
                "snapshot",
                "--engagement",
                "empty-fixture",
                "--require-complete",
            ]
        )
        == 3
    )
    markdown = capsys.readouterr().out
    for source in ("scope", "coverage", "inventory", "asvs", "objectives"):
        section = markdown.split(f"## {source}\n", 1)[1].split("\n## ", 1)[0]
        assert "Status: unavailable." in section
    assert "Partial metadata: yes." in markdown
    assert not (tmp_path / "assessment").exists()


@pytest.mark.parametrize("tampered", [False, True])
def test_snapshot_reads_committed_metadata_without_reserving_the_ledger(
    context_workspace: tuple[Path, AssessmentStore],
    monkeypatch: pytest.MonkeyPatch,
    tampered: bool,
) -> None:
    from buggy.context_export import export_snapshot

    workspace, store = context_workspace
    proof = workspace / "proof.txt"
    proof.write_text("PRIVATE_CONTEXT_SENTINEL")
    case = next(
        case
        for case in store.dispatch("report", {})["cases"]
        if case["control_id"] == "http.nosniff"
    )
    store.dispatch(
        "record",
        {
            "case_id": case["case_id"],
            "status": "pass",
            "rationale": "PRIVATE_CONTEXT_SENTINEL",
            "evidence_paths": ["proof.txt"],
        },
    )
    plan = store.dispatch(
        "asvs_init", {"asset": "https://app.example.test/PRIVATE_CONTEXT_SENTINEL", "level": 1}
    )
    saved = store.dispatch(
        "asvs_record",
        {
            "plan_id": plan["plan_id"],
            "requirement_id": "v5.0.0-1.2.1",
            "status": "not_applicable",
            "method": "applicability_review",
            "rationale": "PRIVATE_CONTEXT_SENTINEL",
            "evidence_paths": ["proof.txt"],
        },
    )
    if tampered:
        proof.write_text("Changed PRIVATE_CONTEXT_SENTINEL")
    before = {path: path.read_bytes() for path in workspace.rglob("*") if path.is_file()}
    attempts: list[str] = []

    def forbidden(*args: object, **kwargs: object) -> None:
        attempts.append("network or process")
        pytest.fail("Snapshot collection must not open network connections or start processes")

    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    database = workspace / "assessment" / "coverage.sqlite3"
    with closing(sqlite3.connect(database)) as pending:
        pending.execute("BEGIN IMMEDIATE")
        local = store.dispatch(
            "context_sources", {"engagement_name": "context-fixture", "max_rows": 1}
        )
        assert all(
            local["sources"][source]["status"] == "ok"
            for source in ("scope", "coverage", "inventory", "asvs")
        )
        coverage = local["sources"]["coverage"]["data"]
        asvs = local["sources"]["asvs"]["data"][0]
        assert coverage["revision"] == saved["revision"]
        assert coverage["status_counts"]["pass"] == int(not tampered)
        assert coverage["status_counts"]["inconclusive"] == int(tampered)
        assert asvs["status_counts"]["not_applicable"] == int(not tampered)
        assert asvs["status_counts"]["inconclusive"] == int(tampered)
        assert asvs["coverage"]["applicable"] == 70 - int(not tampered)
        snapshot = export_snapshot(local, max_rows=1)
        assert "PRIVATE_CONTEXT_SENTINEL" not in json.dumps(local) + snapshot["markdown"]
        assert attempts == []
        assert before == {
            path: path.read_bytes() for path in workspace.rglob("*") if path.is_file()
        }


def test_session_snapshot_omits_skills_from_a_different_graph_partition(
    context_workspace: tuple[Path, AssessmentStore],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from buggy.tools import assessment

    _, store = context_workspace

    class Sandbox:
        def assessment(
            self, action: str, payload: dict[str, Any], *, workspace_path: str
        ) -> dict[str, Any]:
            return store.dispatch(action, payload)

    monkeypatch.setattr(assessment, "build_sandbox_backend", lambda config: Sandbox())
    state = {
        "engagement_name": "context-fixture",
        "workspace_path": "/workspace/context-fixture",
        "kg_engagement": "previous-tenant.context-fixture",
        "messages": [
            {
                "tool_calls": [
                    {
                        "name": "load_skill",
                        "args": {"name_or_path": "previous-client-private-skill"},
                    }
                ]
            }
        ],
    }
    snapshot = json.loads(
        assessment.assessment_context_snapshot.invoke(
            {"state": state, "include_graph": False},
            config={"configurable": {"kg_engagement": "current-tenant.context-fixture"}},
        )
    )
    assert snapshot["source_status"]["skills"] == "not_requested"
    assert snapshot["source_status"]["coverage"] == "ok"
    assert "previous" not in snapshot["markdown"]


def test_snapshot_rejects_conflicting_opplan_engagement_tags(
    context_workspace: tuple[Path, AssessmentStore],
) -> None:
    from buggy.context_export import export_snapshot

    workspace, store = context_workspace
    path = workspace / "plan" / "opplan.json"
    plan = json.loads(path.read_text())
    plan["engagement"] = "other-client"
    path.write_text(json.dumps(plan))
    snapshot = export_snapshot(store.dispatch("context_sources", {}), max_rows=1)
    assert snapshot["source_status"]["objectives"] == "error"
    section = snapshot["markdown"].split("## objectives\n", 1)[1].split("\n## ", 1)[0]
    assert "No records exported" in section
    assert "completed" not in section


@pytest.mark.parametrize(
    "failure",
    [
        "http_error",
        "timeout",
        "invalid_json",
        "missing_sources",
        "invalid_sources",
        "wrong_engagement",
    ],
)
def test_session_snapshot_rejects_unusable_sandbox_responses_without_echoing_them(
    monkeypatch: pytest.MonkeyPatch,
    failure: str,
) -> None:
    import httpx

    from buggy.backends.http_sandbox import HTTPSandbox
    from buggy.tools import assessment

    def response(request: httpx.Request) -> httpx.Response:
        if failure == "timeout":
            raise httpx.ReadTimeout("PRIVATE_CONTEXT_SENTINEL", request=request)
        if failure in ("http_error", "invalid_json"):
            return httpx.Response(
                503 if failure == "http_error" else 200, text="PRIVATE_CONTEXT_SENTINEL"
            )
        payloads = {
            "missing_sources": {
                "engagement": "context-fixture",
                "body": "PRIVATE_CONTEXT_SENTINEL",
            },
            "invalid_sources": {
                "engagement": "context-fixture",
                "sources": "PRIVATE_CONTEXT_SENTINEL",
            },
            "wrong_engagement": {"engagement": "other-client", "sources": {}},
        }
        return httpx.Response(200, json=payloads[failure])

    sandbox = HTTPSandbox("http://snapshot.invalid")
    with httpx.Client(
        transport=httpx.MockTransport(response), base_url="http://snapshot.invalid"
    ) as client:
        monkeypatch.setattr(sandbox, "_client", client)
        monkeypatch.setattr(assessment, "build_sandbox_backend", lambda config: sandbox)
        with pytest.raises(assessment.AssessmentToolError) as error:
            assessment.assessment_context_snapshot.invoke(
                {
                    "state": {
                        "engagement_name": "context-fixture",
                        "workspace_path": "/workspace/context-fixture",
                    },
                    "include_graph": False,
                }
            )
    assert "PRIVATE_CONTEXT_SENTINEL" not in str(error.value)
