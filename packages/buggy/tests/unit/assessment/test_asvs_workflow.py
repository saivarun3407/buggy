from __future__ import annotations

import hashlib
import json
import sqlite3
from contextlib import closing
from pathlib import Path

import pytest

from buggy.cli.__main__ import main


def test_cli_catalog_uses_pinned_cumulative_levels_without_creating_state(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert (
        main(
            [
                "assessment",
                "--workspace",
                str(tmp_path),
                "asvs-catalog",
                "--level",
                "2",
                "--limit",
                "1",
            ]
        )
        == 0
    )
    catalog = json.loads(capsys.readouterr().out)
    assert catalog["version"] == "5.0.0"
    assert catalog["catalog_total"] == 345
    assert catalog["total"] == 253
    assert catalog["requirements"][0]["requirement_id"] == "v5.0.0-1.1.1"
    assert catalog["license"] == "CC-BY-SA-4.0"
    assert catalog["next_offset"] == 1
    assert not (tmp_path / "assessment").exists()


def _init(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> list[str]:
    args = ["assessment", "--workspace", str(tmp_path)]
    assert main([*args, "init", "--name", "asvs-fixture", "--scope", "app.example.test"]) == 0
    capsys.readouterr()
    return args


def test_asvs_application_plan_is_persistent_idempotent_and_separate_from_endpoint_cases(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    args = _init(tmp_path, capsys)
    command = [*args, "asvs-init", "--asset", "https://app.example.test", "--level", "1"]
    assert main(command) == 0
    created = json.loads(capsys.readouterr().out)
    assert created["revision"] == 2
    plan_id = created["plan_id"]
    assert main(command) == 0
    assert json.loads(capsys.readouterr().out)["revision"] == 2
    assert main([*args, "asvs-report", "--plan", plan_id, "--limit", "1", "--fail-on-gaps"]) == 1
    report = json.loads(capsys.readouterr().out)
    assert report["total"] == 70
    assert len(report["cases"]) == 1
    assert report["status_counts"]["untested"] == 70
    assert report["complete"] is False
    assert report["cases"][0]["requirement_id"] == "v5.0.0-1.2.1"
    assert main([*args, "report"]) == 0
    baseline = json.loads(capsys.readouterr().out)
    assert baseline["total_operations"] == 0
    assert baseline["total_cases"] == 0
    assert baseline["complete"] is False


def _plan(args: list[str], capsys: pytest.CaptureFixture[str], *flags: str) -> str:
    assert (
        main([*args, "asvs-init", "--asset", "https://app.example.test", "--level", "1", *flags])
        == 0
    )
    return json.loads(capsys.readouterr().out)["plan_id"]


def test_asvs_exclusion_requires_evidence_and_tampering_restores_the_denominator(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    args = _init(tmp_path, capsys)
    plan_id = _plan(args, capsys)
    record = [
        *args,
        "asvs-record",
        "--plan",
        plan_id,
        "--requirement",
        "v5.0.0-1.2.1",
        "--status",
        "not_applicable",
        "--method",
        "applicability_review",
        "--rationale",
        "Synthetic applicability review",
    ]
    assert main(record) == 2
    capsys.readouterr()
    (tmp_path / "proof.txt").write_text("Synthetic reviewed applicability evidence")
    assert main([*record, "--evidence", "proof.txt"]) == 0
    saved = json.loads(capsys.readouterr().out)
    assert saved["evaluation_mode"] == "attested"
    assert saved["revision"] == 3
    assert main([*args, "asvs-report", "--plan", plan_id, "--limit", "1"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["coverage"]["applicable"] == 69
    assert report["status_counts"]["not_applicable"] == 1
    (tmp_path / "proof.txt").write_text("Changed evidence, not the reviewed artifact")
    assert (
        main([*args, "asvs-report", "--plan", plan_id, "--offset", "1000", "--fail-on-gaps"]) == 1
    )
    report = json.loads(capsys.readouterr().out)
    assert report["cases"] == []
    assert report["status_counts"]["not_applicable"] == 0
    assert report["status_counts"]["inconclusive"] == 1
    assert report["coverage"]["applicable"] == 70
    assert report["revision"] == 3


def test_asvs_access_blocks_dispositions_and_next_until_prerequisites_are_available(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    args = _init(tmp_path, capsys)
    (tmp_path / "access.json").write_text(
        json.dumps(
            {
                "v5.0.0-1.2.1": {"roles": ["administrator"], "source_required": True},
            }
        )
    )
    plan_id = _plan(args, capsys, "--prerequisites", "access.json")
    (tmp_path / "proof.txt").write_text("Synthetic source-review evidence")
    record = [
        *args,
        "asvs-record",
        "--plan",
        plan_id,
        "--requirement",
        "v5.0.0-1.2.1",
        "--status",
        "pass",
        "--method",
        "code_review",
        "--rationale",
        "Synthetic code review",
        "--evidence",
        "proof.txt",
    ]
    assert main(record) == 2
    assert "prerequisites" in capsys.readouterr().err
    assert main([*args, "asvs-next", "--plan", plan_id, "--limit", "1000"]) == 0
    assert all(
        case["requirement_id"] != "v5.0.0-1.2.1"
        for case in json.loads(capsys.readouterr().out)["cases"]
    )
    assert main([*args, "access", "--role", "administrator", "--source-available"]) == 0
    capsys.readouterr()
    assert main(record) == 0
    assert json.loads(capsys.readouterr().out)["status"] == "pass"


def test_asvs_record_rejects_stale_revision_without_overwriting_progress(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    args = _init(tmp_path, capsys)
    plan_id = _plan(args, capsys)
    (tmp_path / "proof.txt").write_text("Synthetic reviewed artifact")
    command = [
        *args,
        "--expected-revision",
        "1",
        "asvs-record",
        "--plan",
        plan_id,
        "--requirement",
        "v5.0.0-1.2.1",
        "--status",
        "pass",
        "--method",
        "manual_review",
        "--rationale",
        "Synthetic review",
        "--evidence",
        "proof.txt",
    ]
    assert main(command) == 2
    assert "revision" in capsys.readouterr().err
    assert main([*args, "asvs-report", "--plan", plan_id]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["revision"] == 2
    assert report["status_counts"]["untested"] == 70


@pytest.mark.parametrize("corruption", ["drop_plan", "drop_requirement", "record_link"])
def test_asvs_persistence_detects_missing_work_and_mismatched_audit_links(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], corruption: str
) -> None:
    args = _init(tmp_path, capsys)
    plan_id = _plan(args, capsys)
    (tmp_path / "proof.txt").write_text("Synthetic review artifact")
    assert (
        main(
            [
                *args,
                "asvs-record",
                "--plan",
                plan_id,
                "--requirement",
                "v5.0.0-1.2.1",
                "--status",
                "pass",
                "--method",
                "manual_review",
                "--rationale",
                "Synthetic review",
                "--evidence",
                "proof.txt",
            ]
        )
        == 0
    )
    capsys.readouterr()
    with closing(sqlite3.connect(tmp_path / "assessment" / "coverage.sqlite3")) as db, db:
        if corruption == "record_link":
            details = json.loads(
                db.execute("SELECT details FROM history WHERE revision = 3").fetchone()[0]
            )
            details["requirement_id"] = "v5.0.0-1.2.2"
            db.execute("UPDATE history SET details = ? WHERE revision = 3", (json.dumps(details),))
        else:
            state = json.loads(db.execute("SELECT state FROM ledger").fetchone()[0])
            if corruption == "drop_plan":
                state.pop("asvs_plans")
            else:
                state["asvs_plans"][plan_id]["records"].pop("v5.0.0-1.2.2")
            raw = json.dumps(state, sort_keys=True, separators=(",", ":"))
            digest = hashlib.sha256(raw.encode()).hexdigest()
            db.execute("UPDATE ledger SET state = ?, sha256 = ?", (raw, digest))
            db.execute("UPDATE history SET state_sha256 = ? WHERE revision = 3", (digest,))
    assert main([*args, "asvs-report", "--plan", plan_id]) == 2
    assert "Corrupt" in capsys.readouterr().err


def test_complete_asvs_review_with_a_failure_is_not_reported_as_compliance(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    from buggy.sandbox_kernel.assessment import AssessmentStore

    args = _init(tmp_path, capsys)
    plan_id = _plan(args, capsys)
    (tmp_path / "proof.txt").write_text("Synthetic evidence for fixture attestations")
    store = AssessmentStore(tmp_path)
    cases = store.dispatch("asvs_report", {"plan_id": plan_id, "limit": 1000})["cases"]
    for index, case in enumerate(cases):
        store.dispatch(
            "asvs_record",
            {
                "plan_id": plan_id,
                "requirement_id": case["requirement_id"],
                "status": "fail" if index == 0 else "pass",
                "method": "manual_review",
                "rationale": "Synthetic review, not client verification",
                "evidence_paths": ["proof.txt"],
            },
        )
    assert (
        main(
            [
                *args,
                "asvs-report",
                "--plan",
                plan_id,
                "--limit",
                "1",
                "--format",
                "markdown",
                "--fail-on-gaps",
            ]
        )
        == 0
    )
    markdown = capsys.readouterr().out
    assert "ASVS application review" in markdown
    assert "attested" in markdown
    assert "certification" in markdown
    assert "fail | 1" in markdown
    assert "CC-BY-SA-4.0" in markdown
    report = store.dispatch("asvs_report", {"plan_id": plan_id, "limit": 1})
    assert report["complete"] is True
    assert report["independently_verified"] is False
    assert report["coverage"]["assessed"] == 70
    assert report["status_counts"]["fail"] == 1


def test_asvs_tools_cross_authenticated_http_and_quarantine_catalog_data(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import importlib

    import httpx
    from fastapi.testclient import TestClient

    from buggy.backends.http_sandbox import HTTPSandbox
    from buggy.middleware.untrusted_output import UNTRUSTED_TOOL_NAMES
    from buggy.tools import assessment

    app_module = importlib.import_module("buggy.sandbox_server.app")
    monkeypatch.setenv("SANDBOX_ROOT_DIR", str(tmp_path))
    monkeypatch.setattr(app_module, "_required_token", "asvs-fixture-token")
    daemon = TestClient(app_module.app)
    real_client = httpx.Client

    def transport(request: httpx.Request) -> httpx.Response:
        response = daemon.request(
            request.method, request.url.path, headers=dict(request.headers), content=request.content
        )
        return httpx.Response(response.status_code, json=response.json())

    monkeypatch.setattr(
        httpx,
        "Client",
        lambda *args, **kwargs: real_client(
            *args, transport=httpx.MockTransport(transport), **kwargs
        ),
    )
    sandbox = HTTPSandbox("http://asvs.test", token="asvs-fixture-token")
    state = {"engagement_name": "asvs-fixture", "workspace_path": "/workspace/asvs-fixture"}
    try:
        sandbox.assessment(
            "initialize",
            {
                "engagement_name": "asvs-fixture",
                "profile": "external",
                "allowed_hosts": ["app.example.test"],
            },
            workspace_path=state["workspace_path"],
        )
        workspace = tmp_path / "asvs-fixture"
        (workspace / "plan").mkdir()
        (workspace / "plan" / "asvs.json").write_text(
            json.dumps({"asset": "https://app.example.test", "level": 1})
        )
        (workspace / "proof.txt").write_text("Synthetic ASVS review evidence")
        monkeypatch.setattr(assessment, "build_sandbox_backend", lambda config: sandbox)
        catalog = json.loads(
            assessment.assessment_asvs_catalog.invoke({"state": state, "level": 1, "limit": 1})
        )
        assert catalog["total"] == 70
        initialized = json.loads(assessment.assessment_asvs_initialize.invoke({"state": state}))
        saved = json.loads(
            assessment.assessment_asvs_record.invoke(
                {
                    "state": state,
                    "plan_id": initialized["plan_id"],
                    "requirement_id": "v5.0.0-1.2.1",
                    "status": "pass",
                    "method": "manual_review",
                    "rationale": "Synthetic review",
                    "evidence_paths": ["proof.txt"],
                    "expected_revision": initialized["revision"],
                }
            )
        )
        assert saved["evaluation_mode"] == "attested"
        report = json.loads(
            assessment.assessment_asvs_status.invoke(
                {"state": state, "plan_id": initialized["plan_id"]}
            )
        )
        assert report["status_counts"]["pass"] == 1
        assert report["status_counts"]["untested"] == 69
        assert (
            daemon.post(
                "/assessment",
                json={
                    "workspace_path": state["workspace_path"],
                    "action": "asvs_report",
                    "payload": {"plan_id": initialized["plan_id"]},
                },
            ).status_code
            == 401
        )
        names = {
            "assessment_asvs_catalog",
            "assessment_asvs_initialize",
            "assessment_asvs_record",
            "assessment_asvs_status",
        }
        assert names <= {tool.name for tool in assessment.ASSESSMENT_TOOLS}
        assert names <= UNTRUSTED_TOOL_NAMES
    finally:
        sandbox.close()
        daemon.close()


@pytest.mark.parametrize("role", ["Support Team", "Review-管理者"])
def test_asvs_access_uses_the_same_role_labels_as_the_engagement(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], role: str
) -> None:
    args = _init(tmp_path, capsys)
    assert main([*args, "access", "--role", role]) == 0
    capsys.readouterr()
    (tmp_path / "prerequisites.json").write_text(
        json.dumps(
            {
                "v5.0.0-1.2.1": {"roles": [role], "source_required": False},
            }
        )
    )
    plan_id = _plan(args, capsys, "--prerequisites", "prerequisites.json")
    assert main([*args, "asvs-report", "--plan", plan_id, "--limit", "1"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["cases"][0]["prerequisites_available"] is True
    assert report["cases"][0]["status"] == "untested"


def test_reviewed_asvs_plan_cannot_be_silently_overridden_by_request_fields(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    from buggy.sandbox_kernel.assessment import AssessmentError, AssessmentStore

    _init(tmp_path, capsys)
    (tmp_path / "plan.json").write_text(
        json.dumps({"asset": "https://app.example.test", "level": 1})
    )
    store = AssessmentStore(tmp_path)
    with pytest.raises(AssessmentError, match="fields"):
        store.dispatch("asvs_init", {"plan_path": "plan.json", "prerequisites": {}})
    assert store.dispatch("asvs_list", {})["total"] == 0
