from __future__ import annotations

import json
from pathlib import Path

import pytest

from buggy.cli.__main__ import main


def test_workflow_capability_catalog_does_not_create_assessment_state(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(["workflows", "--workspace", str(tmp_path), "capabilities"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["schema_version"] == 1
    assert len(report["capabilities"]) == 5
    assert not list(tmp_path.iterdir())


def test_workflow_cli_records_and_reopens_an_artifact_run(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    from datetime import datetime, timezone

    from buggy.sandbox_kernel.assessment import AssessmentStore

    store = AssessmentStore(tmp_path)
    store.dispatch(
        "initialize",
        {
            "engagement_name": "workflow-fixture",
            "profile": "external",
            "allowed_hosts": ["app.example.test"],
        },
    )
    (tmp_path / "capture.json").write_text(
        json.dumps(
            {
                "source": "capture",
                "url": "https://app.example.test/",
                "method": "GET",
                "captured_at": datetime.now(timezone.utc).isoformat(),
                "status_code": 200,
                "headers": {
                    "X-Content-Type-Options": "nosniff",
                    "Strict-Transport-Security": "max-age=31536000",
                },
            }
        )
    )
    args = ["workflows", "--workspace", str(tmp_path)]
    assert (
        main(
            [
                *args,
                "run",
                "http-capture-review",
                "--url",
                "https://app.example.test/",
                "--artifact",
                "capture.json",
            ]
        )
        == 0
    )
    result = json.loads(capsys.readouterr().out)
    assert result["status"] == "observed"
    assert result["baseline_coverage_updated"] is False
    assert main([*args, "report", result["run_id"]]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["run_id"] == result["run_id"]
    assert store.dispatch("report", {})["revision"] == 1
