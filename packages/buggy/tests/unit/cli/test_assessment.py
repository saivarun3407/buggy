from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from buggy.cli.__main__ import main


def test_cli_initializes_and_reloads_an_incomplete_assessment(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    args = ["assessment", "--workspace", str(tmp_path)]
    assert main([*args, "init", "--name", "client-one", "--scope", "app.example.test"]) == 0
    capsys.readouterr()
    assert main([*args, "report", "--fail-on-gaps"]) == 1
    report = json.loads(capsys.readouterr().out)
    assert report["complete"] is False
    assert (tmp_path / "assessment" / "coverage.sqlite3").is_file()


def _openapi_spec(count: int = 137) -> dict:
    return {
        "openapi": "3.0.3",
        "info": {"title": "Synthetic API", "version": "1"},
        "paths": {
            f"/items/{index}": {
                "get": {"parameters": [{"name": "page", "in": "query", "example": "hidden"}]}
            }
            for index in range(count)
        },
    }


@pytest.mark.parametrize("encoding", ["json", "yaml"])
def test_prepare_import_openapi_uses_the_complete_pure_parser(
    encoding: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    import yaml

    from buggy.assessment_import import prepare_import
    from buggy.tools.research import api_spec

    spec = _openapi_spec()
    calls = []
    parse = api_spec.parse_openapi_document

    def tracked_parse(document):
        calls.append(document)
        return parse(document)

    def no_loading(*args, **kwargs):
        pytest.fail("Import preparation must not load files or make requests")

    monkeypatch.setattr(api_spec, "parse_openapi_document", tracked_parse)
    monkeypatch.setattr(api_spec, "_load_spec", no_loading)
    content = json.dumps(spec) if encoding == "json" else yaml.safe_dump(spec, sort_keys=False)
    result = prepare_import("openapi", content, "local-spec", "https://app.example.test/v1")

    assert calls == [spec]
    assert len(result["operations"]) == 137
    assert result["operations"][-1]["path"] == "/items/136"
    assert result["base_url"] == "https://app.example.test/v1"
    assert result["source"]["id"] == "local-spec"
    assert result["source"]["kind"] == "openapi"
    assert result["source"]["status"] == "ok"
    assert "hidden" not in json.dumps(result)


def test_prepare_import_observations_are_manual_and_keep_all_records() -> None:
    from buggy.assessment_import import prepare_import

    operations = [
        {"path": "/items", "method": "get"},
        {"path": "/items", "method": "get"},
        {"url": "https://app.example.test/items", "method": "post"},
    ]
    result = prepare_import(
        "observations", json.dumps({"operations": operations}), "review", "https://app.example.test"
    )
    assert len(result["operations"]) == 3
    assert [operation["method"] for operation in result["operations"]] == ["GET", "GET", "POST"]
    assert result["source"]["kind"] == "manual"
    assert result["source"]["status"] == "ok"
    empty = prepare_import("observations", '{"operations": []}', "empty-review")
    assert empty["operations"] == []
    assert empty["source"]["status"] == "empty"


@pytest.mark.parametrize(
    ("kind", "content", "source_id"),
    [
        ("unknown", "{}", "source"),
        ("openapi", "{}", " "),
        ("openapi", "[not valid: SECRET_SENTINEL", "source"),
        ("openapi", "[]", "source"),
        ("openapi", '{"paths": []}', "source"),
        ("openapi", '{"paths": {"/items": {"get": null}}}', "source"),
        ("openapi", '{"paths": {"/items": {"get": {"parameters": [null]}}}}', "source"),
        ("observations", "{}", "source"),
        ("observations", '{"operations": {}}', "source"),
        ("observations", '{"operations": [{"path": "/items"}]}', "source"),
        ("observations", '{"operations": [null]}', "source"),
    ],
)
def test_prepare_import_rejects_malformed_inventory_without_echoing_input(
    kind: str, content: str, source_id: str
) -> None:
    from buggy.assessment_import import AssessmentImportError, prepare_import

    with pytest.raises(AssessmentImportError) as error:
        prepare_import(kind, content, source_id, "https://app.example.test")
    assert "SECRET_SENTINEL" not in str(error.value)


def _har(count: int = 139) -> dict:
    request = {
        "url": "https://url-user:URL_SECRET@app.example.test/items?api_key=QUERY_SECRET#FRAGMENT_SECRET",
        "method": "post",
        "headers": [{"name": "Authorization", "value": "Bearer HEADER_SECRET"}],
        "cookies": [{"name": "session", "value": "COOKIE_SECRET"}],
        "queryString": [{"name": "q", "value": "QUERY_STRING_SECRET"}],
        "postData": {
            "mimeType": "application/json",
            "params": [{"name": "upload", "value": "PARAM_SECRET", "fileName": "FILE_SECRET"}],
            "text": json.dumps(
                {
                    "token": "BODY_SECRET",
                    "profile": {"name": "NESTED_SECRET"},
                    "items": [{"sku": 17}],
                }
            ),
        },
    }
    return {
        "log": {
            "entries": [
                {"request": request, "response": {"content": {"text": "RESPONSE_SECRET"}}}
                for _ in range(count)
            ]
        }
    }


def test_prepare_import_har_keeps_entries_and_only_parameter_names() -> None:
    from buggy.assessment_import import prepare_import

    result = prepare_import("traffic", json.dumps(_har()), "browser-capture")
    serialized = json.dumps(result)
    assert "SECRET" not in serialized
    assert "url-user" not in serialized
    assert "Authorization" not in serialized
    assert "cookies" not in serialized
    assert len(result["operations"]) == 139
    assert result["operations"][0] == result["operations"][-1]
    operation = result["operations"][0]
    assert operation["method"] == "POST"
    assert operation["url"].startswith("https://app.example.test/items")
    assert {parameter["name"] for parameter in operation["parameters"]} == {
        "api_key",
        "q",
        "upload",
        "token",
        "profile",
        "name",
        "items",
        "sku",
    }
    assert all(
        set(parameter) <= {"name", "in", "required"} for parameter in operation["parameters"]
    )
    assert result["source"]["kind"] == "traffic"
    assert result["source"]["status"] == "ok"


def test_prepare_import_har_supports_form_names_and_explicit_empty_inventory() -> None:
    from buggy.assessment_import import prepare_import

    document = _har(1)
    request = document["log"]["entries"][0]["request"]
    request["url"] = "https://[::1]:8443/form?preview=URL_SECRET"
    request["queryString"] = []
    request["postData"] = {
        "mimeType": "application/x-www-form-urlencoded; charset=UTF-8",
        "text": "username=USER_SECRET&password=PASSWORD_SECRET",
    }
    result = prepare_import("traffic", json.dumps(document), "form-capture")
    assert "SECRET" not in json.dumps(result)
    assert result["operations"][0]["url"].startswith("https://[::1]:8443/form")
    assert {p["name"] for p in result["operations"][0]["parameters"]} == {
        "preview",
        "username",
        "password",
    }
    empty = prepare_import("traffic", '{"log": {"entries": []}}', "empty-capture")
    assert empty["operations"] == []
    assert empty["source"]["status"] == "empty"


@pytest.mark.parametrize(
    "har_request",
    [
        {},
        {"url": "not-a-url", "method": "GET"},
        {"url": "file:///SECRET_SENTINEL", "method": "GET"},
        {"url": "https://app.example.test", "method": "GET", "queryString": {}},
        {"url": "https://app.example.test", "method": "GET", "queryString": [{"value": "secret"}]},
        {"url": "https://app.example.test", "method": "POST", "postData": []},
        {
            "url": "https://app.example.test",
            "method": "POST",
            "postData": {"mimeType": "application/json", "text": "SECRET_SENTINEL"},
        },
    ],
)
def test_prepare_import_har_rejects_malformed_requests(har_request: dict) -> None:
    from buggy.assessment_import import AssessmentImportError, prepare_import

    content = json.dumps({"log": {"entries": [{"request": har_request}]}})
    with pytest.raises(AssessmentImportError) as error:
        prepare_import("traffic", content, "capture")
    assert "SECRET_SENTINEL" not in str(error.value)


@pytest.mark.parametrize("status", ["ok", "empty", "error", "unavailable", "mock"])
def test_prepare_import_source_status_is_explicit_and_does_not_echo_provider_details(
    status: str,
) -> None:
    from buggy.assessment_import import prepare_import

    document = {
        "status": status,
        "detail": "provider URL https://provider.example?api_key=OSINT_SECRET",
        "observed_at": "2026-07-31T12:00:00Z",
        "operations": [{"url": "https://ignore.example.test", "method": "GET"}],
    }
    result = prepare_import("source-status", json.dumps(document), "osint-capture")
    assert result["operations"] == []
    assert result["source"]["kind"] == "osint"
    assert result["source"]["status"] == status
    assert result["source"]["observed_at"] == document["observed_at"]
    assert "OSINT_SECRET" not in json.dumps(result)
    assert "provider.example" not in json.dumps(result)


@pytest.mark.parametrize(
    ("extra", "expected"),
    [
        ({"source_status": {"shodan": {"status": "error"}}}, "error"),
        ({"source_status": {"censys": {"status": "unavailable"}}}, "unavailable"),
        ({"source_status": {"mock": {"status": "mock"}}, "sources": ["mock"]}, "mock"),
        ({"errors": ["provider failed with OSINT_SECRET"]}, "error"),
        ({"in_scope": False}, "unavailable"),
        ({"status": "mock", "errors": ["OSINT_SECRET"]}, "mock"),
    ],
)
def test_prepare_import_normalized_osint_does_not_upgrade_source_gaps(
    extra: dict, expected: str
) -> None:
    from buggy.assessment_import import prepare_import

    result = prepare_import("source-status", json.dumps({"status": "ok", **extra}), "osint")
    assert result["source"]["status"] == expected
    assert "OSINT_SECRET" not in json.dumps(result)
    assert result["operations"] == []


@pytest.mark.parametrize(
    "document",
    [
        {},
        {"status": "success"},
        {"status": "ok", "source_status": []},
        {"status": "ok", "source_status": {"shodan": {}}},
        {"status": "ok", "detail": {}},
        {"status": "ok", "observed_at": "OSINT_SECRET"},
        {"status": "ok", "observed_at": "2024-01-01"},
        {"status": "ok", "observed_at": "2024-01-01T00:00:00"},
    ],
)
def test_prepare_import_rejects_malformed_source_status(document: dict) -> None:
    from buggy.assessment_import import AssessmentImportError, prepare_import

    with pytest.raises(AssessmentImportError) as error:
        prepare_import("source-status", json.dumps(document), "osint")
    assert "OSINT_SECRET" not in str(error.value)


def _report_example() -> dict:
    return {
        "engagement_name": "synthetic-review",
        "baseline": "web-api-minimum-v1",
        "complete": False,
        "totals": {"operations": 137, "cases": 685, "sources": 2, "source_gaps": 1},
        "status_counts": {"pass": 1, "fail": 0, "blocked": 137, "untested": 547},
        "source_gaps": [
            {"source_id": "osint-capture", "status": "unavailable", "reason": "No source access"}
        ],
        "cases": [
            {
                "case_id": "case-first",
                "method": "GET",
                "url": "https://app.example.test/items",
                "control_id": "http.nosniff",
                "role": "anonymous",
                "status": "pass",
                "evaluation_mode": "deterministic",
                "reason": "Captured response header",
                "evidence": [{"path": "artifacts/response.json"}],
            }
        ],
        "offset": 50,
        "limit": 1,
        "total": 685,
        "has_more": True,
        "next_offset": 51,
    }


def test_render_report_states_incomplete_baseline_and_does_not_infer_coverage_from_a_page() -> None:
    from buggy.assessment_import import render_report

    report = _report_example()
    original = json.dumps(report)
    markdown = render_report(report)
    assert "**Incomplete**" in markdown
    assert "not full ASVS" in markdown
    assert "web-api-minimum-v1" in markdown
    assert "whole assessment" in markdown
    assert "Showing 1 of 685 cases" in markdown
    assert "offset 50" in markdown
    assert "Next offset: 51" in markdown
    assert "not the full inventory" in markdown
    assert "osint-capture" in markdown
    assert "unavailable" in markdown
    assert "547" in markdown
    assert "case-first" in markdown
    assert "artifacts/response.json" in markdown
    assert json.dumps(report) == original


def test_render_report_handles_gap_pages_and_escapes_artifact_text() -> None:
    from buggy.assessment_import import render_report

    report = _report_example()
    report["gaps"] = report.pop("cases")
    report["gaps"][0]["reason"] = "<script>alert(1)</script>\n| injected"
    markdown = render_report(report)
    assert "Case gaps (page)" in markdown
    assert "Showing 1 of 685 case gaps" in markdown
    assert "<script>" not in markdown
    assert "&lt;script&gt;" in markdown
    assert "\\| injected" in markdown


def test_render_report_completion_does_not_mean_no_findings() -> None:
    from buggy.assessment_import import render_report

    report = _report_example()
    report.update(complete=True, source_gaps=[])
    report["status_counts"] = {"pass": 684, "fail": 1}
    markdown = render_report(report)
    assert "**Complete**" in markdown
    assert "not full ASVS" in markdown
    assert "does not mean no vulnerabilities" in markdown
    assert "fail | 1" in markdown


def test_render_report_without_an_explicit_complete_flag_is_incomplete() -> None:
    from buggy.assessment_import import render_report

    assert "**Incomplete**" in render_report({"cases": []})


def _cli_json(args: list[str], capsys: pytest.CaptureFixture[str], expected: int = 0) -> dict:
    assert main(args) == expected
    captured = capsys.readouterr()
    assert captured.err == ""
    return json.loads(captured.out)


def _cli_init(tmp_path: Path, capsys: pytest.CaptureFixture[str], *flags: str) -> list[str]:
    args = ["assessment", "--workspace", str(tmp_path)]
    _cli_json(
        [*args, "init", "--name", "synthetic-review", "--scope", "app.example.test", *flags], capsys
    )
    return args


def test_cli_imports_all_operations_idempotently_and_paginates_across_processes(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    args = _cli_init(tmp_path, capsys)
    artifact = tmp_path / "spec.json"
    artifact.write_text(json.dumps(_openapi_spec()), encoding="utf-8")
    command = [*args, "import-openapi", str(artifact), "--base-url", "https://app.example.test/v1"]
    imported = _cli_json(command, capsys)
    assert imported["imported"] == 137
    repeated = _cli_json(command, capsys)
    assert repeated["imported"] == 0
    assert repeated["revision"] == imported["revision"]

    operations = []
    offset = 0
    while True:
        page = _cli_json([*args, "inventory", "--offset", str(offset), "--limit", "50"], capsys)
        assert page["total"] == 137
        operations.extend(page["operations"])
        if not page["has_more"]:
            assert page["next_offset"] is None
            break
        offset = page["next_offset"]
    assert len(operations) == len({item["operation_id"] for item in operations}) == 137

    reloaded = subprocess.run(
        [
            sys.executable,
            "-B",
            "-m",
            "buggy.cli",
            *args,
            "inventory",
            "--offset",
            "120",
            "--limit",
            "50",
        ],
        capture_output=True,
        text=True,
        check=False,
        timeout=120,
    )
    assert reloaded.returncode == 0, reloaded.stderr
    final_page = json.loads(reloaded.stdout)
    assert final_page["operations"] == operations[120:]
    assert final_page["revision"] == imported["revision"]
    assert final_page["has_more"] is False


def test_cli_imports_har_and_manual_observations_without_credentials(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    args = _cli_init(tmp_path, capsys)
    traffic = tmp_path / "capture.har"
    traffic.write_text(json.dumps(_har()), encoding="utf-8")
    assert (
        _cli_json([*args, "import-traffic", str(traffic), "--source-id", "capture"], capsys)[
            "imported"
        ]
        == 1
    )
    observations = tmp_path / "observations.yaml"
    observations.write_text("operations:\n  - path: /manual\n    method: GET\n", encoding="utf-8")
    assert (
        _cli_json(
            [
                *args,
                "import-observations",
                str(observations),
                "--base-url",
                "https://app.example.test",
            ],
            capsys,
        )["imported"]
        == 1
    )
    inventory = _cli_json([*args, "inventory"], capsys)
    assert inventory["total"] == 2
    assert "SECRET" not in json.dumps(inventory)
    report = _cli_json([*args, "report"], capsys)
    assert {source["kind"] for source in report["sources"]} == {"traffic", "manual"}


@pytest.mark.parametrize("action", ["report", "gaps"])
def test_cli_source_unavailable_is_a_gap_and_markdown_is_explicitly_incomplete(
    action: str, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    args = _cli_init(tmp_path, capsys)
    artifact = tmp_path / "source-status.json"
    artifact.write_text(
        json.dumps(
            {
                "status": "unavailable",
                "detail": "OSINT_SECRET",
                "observed_at": "2026-07-31T12:00:00Z",
            }
        ),
        encoding="utf-8",
    )
    _cli_json([*args, "import-source-status", str(artifact), "--source-id", "osint"], capsys)
    report = _cli_json([*args, action, "--format", "json", "--fail-on-gaps"], capsys, expected=1)
    assert report["complete"] is False
    assert report["source_gaps"][0]["status"] == "unavailable"
    assert "OSINT_SECRET" not in json.dumps(report)
    assert (
        main(
            [
                *args,
                action,
                "--format",
                "markdown",
                "--fail-on-gaps",
                "--offset",
                "1000",
                "--limit",
                "1",
            ]
        )
        == 1
    )
    captured = capsys.readouterr()
    assert captured.err == ""
    assert "**Incomplete**" in captured.out
    assert "not full ASVS" in captured.out
    assert "unavailable" in captured.out
    assert "OSINT_SECRET" not in captured.out


@pytest.mark.parametrize("action", ["report", "gaps"])
def test_cli_missing_assessment_fails_instead_of_reporting_clean(
    action: str, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(["assessment", "--workspace", str(tmp_path), action, "--fail-on-gaps"]) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "not initialized" in captured.err
    assert not (tmp_path / "assessment" / "coverage.sqlite3").exists()


@pytest.mark.parametrize(
    "kind", ["missing", "directory", "url", "malformed", "invalid-utf8", "oversized"]
)
def test_cli_rejects_bad_local_artifacts_without_partial_imports_or_secret_echo(
    kind: str, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    args = _cli_init(tmp_path, capsys)
    artifact = tmp_path / "artifact.json"
    path = str(artifact)
    if kind == "directory":
        path = str(tmp_path)
    elif kind == "url":
        path = "https://provider.example.test/spec?api_key=SECRET_SENTINEL"
    elif kind == "malformed":
        artifact.write_text("{SECRET_SENTINEL", encoding="utf-8")
    elif kind == "invalid-utf8":
        artifact.write_bytes(b"\xffSECRET_SENTINEL")
    elif kind == "oversized":
        with artifact.open("wb") as handle:
            handle.write(b'{"operations": []}')
            handle.truncate(16 * 1024 * 1024 + 1)
    assert main([*args, "import-observations", path]) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err
    assert "SECRET_SENTINEL" not in captured.err
    if kind == "oversized":
        assert "16 MiB" in captured.err
    assert _cli_json([*args, "inventory"], capsys)["total"] == 0


def test_cli_does_not_auto_initialize_or_overwrite_assessments(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    artifact = tmp_path / "observations.json"
    artifact.write_text('{"operations": []}', encoding="utf-8")
    args = ["assessment", "--workspace", str(tmp_path)]
    assert main([*args, "import-observations", str(artifact)]) == 2
    assert "not initialized" in capsys.readouterr().err
    assert not (tmp_path / "assessment" / "coverage.sqlite3").exists()
    _cli_init(tmp_path, capsys)
    assert main([*args, "init", "--name", "different-review", "--scope", "app.example.test"]) == 2
    assert capsys.readouterr().out == ""
    assert _cli_json([*args, "report"], capsys)["engagement_name"] == "synthetic-review"


def _cli_operation(tmp_path: Path, capsys: pytest.CaptureFixture[str], *flags: str) -> list[str]:
    args = _cli_init(tmp_path, capsys, *flags)
    artifact = tmp_path / "observations.json"
    artifact.write_text(
        '{"operations": [{"url": "https://app.example.test/items", "method": "GET"}]}',
        encoding="utf-8",
    )
    _cli_json([*args, "import-observations", str(artifact), "--source-id", "review"], capsys)
    return args


def test_cli_access_updates_prerequisites_and_rejects_stale_mutation_revisions(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    args = _cli_operation(
        tmp_path,
        capsys,
        "--profile",
        "authenticated",
        "--require-role",
        "reader",
        "--require-role",
        "admin",
        "--role",
        "reader",
    )
    before = _cli_json([*args, "report"], capsys)
    assert before["status_counts"]["blocked"] == 2
    updated = _cli_json(
        [
            *args,
            "--expected-revision",
            str(before["revision"]),
            "access",
            "--role",
            "reader",
            "--role",
            "admin",
            "--source-available",
        ],
        capsys,
    )
    assert set(updated["available_roles"]) == {"reader", "admin"}
    assert updated["source_available"] is True
    assert main([*args, "--expected-revision", str(before["revision"]), "access"]) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "revision" in captured.err.lower()
    after = _cli_json([*args, "report"], capsys)
    assert after["revision"] == updated["revision"]
    assert after["status_counts"]["blocked"] == 0
    assert {case["case_id"] for case in before["cases"]} == {
        case["case_id"] for case in after["cases"]
    }
    page = _cli_json([*args, "next", "--limit", "1"], capsys)
    assert page["total"] == after["totals"]["cases"]
    assert len(page["cases"]) == 1


@pytest.mark.parametrize("status", ["pass", "fail", "blocked", "inconclusive", "not_applicable"])
def test_cli_records_attestations_with_explicit_status_and_repeated_evidence(
    status: str, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    args = _cli_operation(tmp_path, capsys)
    report = _cli_json([*args, "report"], capsys)
    case = next(case for case in report["cases"] if case["control_id"] == "http.nosniff")
    flags = []
    if status in {"pass", "fail"}:
        for name in ("review-one.txt", "review-two.txt"):
            (tmp_path / name).write_text("Synthetic reviewer evidence", encoding="utf-8")
            flags.extend(["--evidence", name])
    saved = _cli_json(
        [
            *args,
            "record",
            "--case",
            case["case_id"],
            "--status",
            status,
            *flags,
            "--rationale",
            "Explicit reviewer attestation",
        ],
        capsys,
    )
    assert saved["status"] == status
    assert saved["case"]["evaluation_mode"] == "attested"
    assert saved["case"]["rationale"] == "Explicit reviewer attestation"
    assert len(saved["case"]["evidence"]) == (2 if flags else 0)
    assert saved["case"]["method"] == case["method"]
    assert saved["case"]["url"] == case["url"]


@pytest.mark.parametrize("evidence", [None, "missing.txt", "../outside.txt"])
def test_cli_pass_fail_recording_requires_workspace_evidence(
    evidence: str | None, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    args = _cli_operation(tmp_path, capsys)
    report = _cli_json([*args, "report"], capsys)
    case = next(case for case in report["cases"] if case["control_id"] == "http.nosniff")
    flags = [] if evidence is None else ["--evidence", evidence]
    for status in ("pass", "fail"):
        assert (
            main(
                [
                    *args,
                    "record",
                    "--case",
                    case["case_id"],
                    "--status",
                    status,
                    *flags,
                    "--rationale",
                    "Synthetic review",
                ]
            )
            == 2
        )
        captured = capsys.readouterr()
        assert captured.out == ""
        assert captured.err
    assert _cli_json([*args, "report"], capsys)["revision"] == report["revision"]


def _write_capture(tmp_path: Path, **overrides) -> str:
    document = {
        "url": "https://app.example.test/items",
        "method": "GET",
        "status_code": 200,
        "headers": {
            "X-Content-Type-Options": "nosniff",
            "Strict-Transport-Security": "max-age=31536000",
        },
        "captured_at": "2024-01-01T00:00:00Z",
        "source": "capture",
        **overrides,
    }
    (tmp_path / "response.json").write_text(json.dumps(document), encoding="utf-8")
    return "response.json"


@pytest.mark.parametrize("control", ["http.nosniff", "http.hsts"])
def test_cli_checks_only_supplied_header_artifacts_without_network(
    control: str,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import httpx

    args = _cli_operation(tmp_path, capsys)
    report = _cli_json([*args, "report"], capsys)
    case = next(case for case in report["cases"] if case["control_id"] == control)
    evidence = _write_capture(tmp_path)

    def no_requests(*args, **kwargs):
        pytest.fail("Artifact header checks must not make requests")

    monkeypatch.setattr(httpx.Client, "request", no_requests)
    monkeypatch.setattr(httpx.AsyncClient, "request", no_requests)
    saved = _cli_json(
        [*args, "check-headers", "--case", case["case_id"], "--evidence", evidence], capsys
    )
    assert saved["status"] == "pass"
    assert saved["case"]["evaluation_mode"] == "deterministic"
    assert saved["case"]["evidence"][0]["path"] == evidence
    assert saved["case"]["url"] == case["url"]
    assert saved["case"]["method"] == case["method"]


@pytest.mark.parametrize(
    "overrides",
    [
        {"url": "https://app.example.test/different-operation"},
        {"method": "POST"},
        {"source": "mock"},
        {"captured_at": "not-a-timestamp"},
        {"status_code": "200"},
        {"headers": []},
    ],
)
def test_cli_rejects_header_artifact_metadata_mismatches_without_mutation(
    overrides: dict, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    args = _cli_operation(tmp_path, capsys)
    before = _cli_json([*args, "report"], capsys)
    case = next(case for case in before["cases"] if case["control_id"] == "http.nosniff")
    evidence = _write_capture(tmp_path, **overrides)
    assert main([*args, "check-headers", "--case", case["case_id"], "--evidence", evidence]) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err
    assert _cli_json([*args, "report"], capsys)["revision"] == before["revision"]


@pytest.mark.parametrize("action", ["record", "check-headers"])
def test_cli_does_not_accept_forged_case_metadata_flags(
    action: str, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    args = [
        "assessment",
        "--workspace",
        str(tmp_path),
        action,
        "--case",
        "case-id",
        "--evidence",
        "response.json",
    ]
    if action == "record":
        args.extend(["--status", "pass", "--rationale", "Synthetic review"])
    with pytest.raises(SystemExit) as error:
        main([*args, "--method", "POST"])
    assert error.value.code == 2
    assert "unrecognized arguments: --method POST" in capsys.readouterr().err


def test_cli_complete_baseline_can_still_include_findings_and_a_paginated_report(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    args = _cli_operation(
        tmp_path, capsys, "--require-role", "reader", "--role", "reader", "--source-available"
    )
    report = _cli_json([*args, "report"], capsys)
    (tmp_path / "review.txt").write_text(
        "Synthetic evidence reviewed for this baseline", encoding="utf-8"
    )
    for index, case in enumerate(report["cases"]):
        _cli_json(
            [
                *args,
                "record",
                "--case",
                case["case_id"],
                "--status",
                "fail" if index == 0 else "pass",
                "--evidence",
                "review.txt",
                "--rationale",
                "Explicit attestation",
            ],
            capsys,
        )
    complete = _cli_json([*args, "report", "--limit", "1", "--fail-on-gaps"], capsys)
    assert complete["complete"] is True
    assert complete["status_counts"]["fail"] == 1
    assert complete["has_more"] is True
    assert main([*args, "report", "--format", "markdown", "--limit", "1", "--fail-on-gaps"]) == 0
    markdown = capsys.readouterr().out
    assert "**Complete**" in markdown
    assert "not full ASVS" in markdown
    assert "does not mean no vulnerabilities" in markdown


@pytest.mark.parametrize("kind", ["traffic", "observations"])
def test_prepare_import_preserves_valid_extension_http_methods(kind: str) -> None:
    from buggy.assessment_import import prepare_import

    operation = {"url": "https://app.example.test/items", "method": "M-SEARCH"}
    document = (
        {"operations": [operation]}
        if kind == "observations"
        else {"log": {"entries": [{"request": operation}]}}
    )
    assert (
        prepare_import(kind, json.dumps(document), "extension")["operations"][0]["method"]
        == "M-SEARCH"
    )


@pytest.mark.parametrize(
    "base_url",
    [
        "https://app.example.test?api_key=SECRET_SENTINEL",
        "https://app.example.test#SECRET_SENTINEL",
        "https://user:SECRET_SENTINEL@app.example.test",
    ],
)
def test_prepare_import_rejects_ambiguous_base_urls_instead_of_silently_rewriting_them(
    base_url: str,
) -> None:
    from buggy.assessment_import import AssessmentImportError, prepare_import

    with pytest.raises(AssessmentImportError) as error:
        prepare_import(
            "observations",
            '{"operations": [{"path": "/items", "method": "GET"}]}',
            "manual",
            base_url,
        )
    assert "SECRET_SENTINEL" not in str(error.value)


@pytest.mark.parametrize(
    ("kind", "content"),
    [
        ("openapi", '{"paths": {"/items": {"get": {}}}}'),
        (
            "traffic",
            '{"log": {"entries": [{"request": {"url": "https://app.example.test", "method": "GET"}}]}}',
        ),
        ("observations", '{"operations": [{"path": "/items", "method": "GET"}]}'),
        ("source-status", '{"status": "unavailable"}'),
    ],
)
def test_prepare_import_is_repeatable_without_file_or_network_io(
    kind: str, content: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    import httpx

    from buggy.assessment_import import prepare_import

    def no_io(*args, **kwargs):
        pytest.fail("Shared import preparation must be pure")

    monkeypatch.setattr(Path, "open", no_io)
    monkeypatch.setattr(httpx.Client, "request", no_io)
    monkeypatch.setattr(httpx.AsyncClient, "request", no_io)
    first = prepare_import(kind, content, "explicit-source", "https://app.example.test")
    assert prepare_import(kind, content, "explicit-source", "https://app.example.test") == first


def test_cli_accepts_exactly_16_mib_without_truncating_valid_input(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    args = _cli_init(tmp_path, capsys)
    content = '{"operations": []}'
    artifact = tmp_path / "boundary.json"
    artifact.write_text(content + " " * (16 * 1024 * 1024 - len(content)), encoding="utf-8")
    result = _cli_json([*args, "import-observations", str(artifact)], capsys)
    assert result["imported"] == 0
    assert _cli_json([*args, "report"], capsys)["source_gaps"][0]["status"] == "empty"


def test_cli_persists_exclusions_across_imports(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    args = _cli_init(
        tmp_path, capsys, "--scope", "*.example.test", "--exclude-host", "excluded.example.test"
    )
    spec = tmp_path / "excluded.json"
    spec.write_text(
        json.dumps({"operations": [{"url": "https://excluded.example.test/", "method": "GET"}]})
    )
    assert main([*args, "import-observations", str(spec)]) == 2
    assert "excluded" in capsys.readouterr().err
    inventory = _cli_json([*args, "inventory"], capsys)
    assert inventory["total"] == 0


def test_working_osint_status_is_not_an_empty_inventory_or_an_optional_provider_failure(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    args = _cli_init(tmp_path, capsys)
    artifact = tmp_path / "osint-status.json"
    artifact.write_text(
        json.dumps(
            {
                "status": "ok",
                "sources": ["shodan"],
                "in_scope": True,
                "source_status": {
                    "shodan": {"configured": True, "status": "ok"},
                    "censys": {"configured": False, "status": "unavailable"},
                    "zoomeye": {"configured": False, "status": "unavailable"},
                },
            }
        )
    )
    result = _cli_json(
        [*args, "import-source-status", str(artifact), "--source-id", "osint"], capsys
    )
    assert result["imported"] == 0
    report = _cli_json([*args, "report"], capsys)
    assert report["sources"][0]["status"] == "ok"
    assert report["source_gaps"] == []
    assert report["total_operations"] == 0
    assert report["complete"] is False
