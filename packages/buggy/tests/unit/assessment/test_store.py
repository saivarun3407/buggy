from __future__ import annotations

import hashlib
import json
import multiprocessing
import os
import sqlite3
from contextlib import closing

import pytest

from buggy.sandbox_kernel.assessment import (
    AssessmentConflictError,
    AssessmentError,
    AssessmentStore,
)


def initialize(store, **overrides):
    payload = {
        "engagement_name": "synthetic-review",
        "profile": "authenticated",
        "allowed_hosts": ["api.example.test", "*.services.example.test"],
    }
    payload.update(overrides)
    return store.dispatch("initialize", payload)


def import_operations(store, operations=None, **overrides):
    payload = {
        "base_url": "https://api.example.test",
        "operations": operations
        if operations is not None
        else [{"path": "/items", "method": "GET"}],
        "source": {"id": "spec", "kind": "openapi", "status": "ok"},
    }
    payload.update(overrides)
    return store.dispatch("import", payload)


def case_for(store, control, role=None):
    return next(
        case
        for case in store.dispatch("report", {"limit": 1000})["cases"]
        if case["control_id"] == control and (role is None or case["role"] == role)
    )


def record(store, case, **overrides):
    payload = {
        "case_id": case["case_id"],
        "status": "pass",
        "evidence_paths": ["evidence.txt"],
        "rationale": "Reviewer attests to the synthetic artifact.",
    }
    payload.update(overrides)
    return store.dispatch("record", payload)


def write_capture(tmp_path, **overrides):
    artifact = {
        "url": "https://api.example.test/items",
        "method": "GET",
        "status_code": 200,
        "headers": {
            "X-Content-Type-Options": "nosniff",
            "Strict-Transport-Security": "max-age=31536000",
            "Set-Cookie": "session=do-not-store-http-secret",
        },
        "captured_at": "2025-01-02T03:04:05Z",
        "source": "capture",
        "body": "do-not-store-http-body",
    }
    artifact.update(overrides)
    (tmp_path / "response.json").write_text(json.dumps(artifact))
    return "response.json"


def check_headers(store, case, evidence_path="response.json", **overrides):
    return store.dispatch(
        "check_headers", {"case_id": case["case_id"], "evidence_path": evidence_path} | overrides
    )


def concurrent_update(workspace, index, case_id, barrier, results):
    try:
        store = AssessmentStore(workspace)
        barrier.wait(timeout=20)
        imported = import_operations(
            store,
            [{"path": f"/parallel/{index}/{item}", "method": "GET"} for item in range(6)],
            source={"id": f"worker-{index}", "kind": "manual", "status": "ok"},
        )
        saved = record(
            store, {"case_id": case_id}, rationale=f"Synthetic concurrent reviewer {index}"
        )
        results.put({"revisions": [imported["revision"], saved["revision"]]})
    except Exception as exc:
        results.put({"error": f"{type(exc).__name__}: {exc}"})


def test_initialize_and_large_inventory_are_persistent_and_idempotent(tmp_path):
    store = AssessmentStore(str(tmp_path))
    config = {"required_roles": ["reader", "administrator"]}
    initialized = initialize(store, **config)
    assert initialized["schema_version"] == 1
    assert initialized["baseline"] == "web-api-minimum-v1"
    assert "not full ASVS" in initialized["baseline_description"]
    assert initialized["revision"] == 1
    assert (tmp_path / "assessment" / "coverage.sqlite3").is_file()

    operations = [
        {
            "path": f"/Items/{index}",
            "method": "get",
            "parameters": [
                {"name": "page", "in": "query", "required": False, "example": "do-not-store"}
            ],
        }
        for index in range(137)
    ]
    imported = import_operations(store, operations, base_url="https://API.EXAMPLE.TEST:443/v1")
    assert imported["imported"] == 137
    assert imported["total_cases"] == 137 * 5
    assert imported["revision"] == 2

    collected = []
    offset = 0
    while True:
        page = store.dispatch("inventory", {"offset": offset, "limit": 50})
        assert page["total"] == 137
        assert page["revision"] == 2
        collected.extend(page["operations"])
        if not page["has_more"]:
            assert page["next_offset"] is None
            break
        offset = page["next_offset"]
    assert len(collected) == len({op["operation_id"] for op in collected}) == 137
    assert {op["method"] for op in collected} == {"GET"}
    assert all(op["url"].startswith("https://api.example.test/v1/Items/") for op in collected)
    assert all(op["url"].endswith("?page") for op in collected)
    assert all(op["provenance"] == ["spec"] for op in collected)
    assert "do-not-store" not in json.dumps(collected)

    again = import_operations(store, operations, base_url="https://API.EXAMPLE.TEST:443/v1")
    assert again["imported"] == 0
    assert again["revision"] == 2
    assert initialize(store, **config)["revision"] == 2
    fresh = AssessmentStore(tmp_path)
    assert fresh.dispatch("inventory", {"limit": 1000})["operations"] == collected

    for changes in (
        {"engagement_name": "other"},
        {"profile": "external"},
        {"allowed_hosts": ["other.example.test"]},
        {"required_roles": ["reader"]},
    ):
        with pytest.raises(AssessmentError):
            initialize(store, **(config | changes))
    assert fresh.dispatch("inventory", {})["revision"] == 2
    report = fresh.dispatch("report", {"limit": 3})
    assert report["total"] == report["totals"]["cases"] == 685
    assert len(report["cases"]) == 3
    assert report["status_counts"]["untested"] == 274
    assert report["status_counts"]["blocked"] == 411
    assert report["complete"] is False
    gaps = fresh.dispatch("gaps", {"offset": 500, "limit": 2})
    assert gaps["total"] == 685
    assert gaps["totals"] == report["totals"]
    assert gaps["coverage"] == report["coverage"]
    assert len(gaps["gaps"]) == 2


@pytest.mark.parametrize("profile", ["external", "authenticated", "source-assisted"])
def test_missing_access_is_blocked_in_every_profile(tmp_path, profile):
    store = AssessmentStore(tmp_path)
    initialize(store, profile=profile)
    empty = store.dispatch("report", {})
    assert empty["complete"] is False
    assert empty["coverage"]["percent"] is None
    import_operations(store)
    report = store.dispatch("report", {})
    assert report["required_roles"] == ["authenticated"]
    assert report["available_roles"] == []
    assert report["source_available"] is False
    assert report["status_counts"] == {
        "untested": 2,
        "blocked": 2,
        "pass": 0,
        "fail": 0,
        "inconclusive": 0,
        "not_applicable": 0,
    }
    by_control = {case["control_id"]: case for case in report["cases"]}
    assert "authenticated" in by_control["auth.access-control"]["reason"]
    assert "source" in by_control["source.authorization"]["reason"].lower()
    assert by_control["source.authorization"]["role"] == "source"
    page = store.dispatch("next", {"limit": 1})
    assert page["total"] == 2
    assert page["next_offset"] == 1
    assert page["cases"][0]["role"] == "anonymous"
    assert page["cases"][0]["method"] == "GET"
    assert page["cases"][0]["url"] == "https://api.example.test/items"


def test_access_changes_only_prerequisite_blockers_and_preserves_role_cases(tmp_path):
    store = AssessmentStore(tmp_path)
    initialize(store, required_roles=["reader", "administrator"], available_roles=["reader"])
    import_operations(store)
    report = store.dispatch("report", {})
    auth = {
        case["role"]: case
        for case in report["cases"]
        if case["control_id"] == "auth.access-control"
    }
    assert auth["reader"]["status"] == "untested"
    assert auth["administrator"]["status"] == "blocked"
    assert auth["reader"]["case_id"] != auth["administrator"]["case_id"]
    original_ids = {case["case_id"] for case in report["cases"]}
    assert store.dispatch("next", {})["total"] == 3

    updated = store.dispatch(
        "access", {"available_roles": ["reader", "administrator"], "source_available": True}
    )
    assert updated["revision"] == 3
    report = store.dispatch("report", {})
    assert report["status_counts"]["untested"] == 5
    assert report["status_counts"]["not_applicable"] == 0
    assert {case["case_id"] for case in report["cases"]} == original_ids
    assert store.dispatch("next", {})["total"] == 5
    assert (
        store.dispatch(
            "access", {"available_roles": ["administrator", "reader"], "source_available": True}
        )["revision"]
        == 3
    )

    store.dispatch("access", {"available_roles": ["administrator"], "source_available": True})
    report = store.dispatch("report", {})
    assert report["status_counts"]["blocked"] == 1
    assert report["status_counts"]["untested"] == 4
    assert report["coverage"]["assessed"] == 0
    assert report["coverage"]["applicable"] == 5
    assert [entry["action"] for entry in report["history"]] == [
        "initialize",
        "import",
        "access",
        "access",
    ]


@pytest.mark.parametrize("status", ["mock", "error", "unavailable", "empty"])
def test_source_outages_never_credit_operations_or_erase_prior_provenance(tmp_path, status):
    store = AssessmentStore(tmp_path)
    initialize(store)
    import_operations(store)
    original = store.dispatch("inventory", {})["operations"][0]
    cases = store.dispatch("report", {})["cases"]
    source = {"id": "spec", "kind": "openapi", "status": status, "detail": "Synthetic source gap"}
    offered = [] if status == "empty" else [{"path": "/not-credited", "method": "POST"}]
    result = import_operations(store, offered, source=source)
    assert result["imported"] == 0
    assert result["ignored"] == len(offered)
    assert store.dispatch("inventory", {})["operations"] == [original]
    report = store.dispatch("report", {})
    assert report["cases"] == cases
    assert report["complete"] is False
    assert report["source_gaps"][0]["status"] == status
    assert report["source_gaps"][0]["reason"]
    assert report["sources"][0]["operation_ids"] == [original["operation_id"]]
    assert [entry["status"] for entry in report["sources"][0]["history"]] == ["ok", status]
    assert import_operations(store, offered, source=source)["revision"] == result["revision"]

    recovered = import_operations(store, [{"path": "/new", "method": "POST"}])
    assert recovered["imported"] == 1
    report = store.dispatch("report", {})
    assert report["source_gaps"] == []
    assert len(report["sources"][0]["operation_ids"]) == 2
    assert len(report["sources"][0]["history"]) == 3
    assert report["totals"]["operations"] == 2
    assert report["totals"]["cases"] == 8

    import_operations(store, source={"id": "capture-index", "kind": "traffic", "status": "ok"})
    inventory = store.dispatch("inventory", {})
    existing = next(
        op for op in inventory["operations"] if op["operation_id"] == original["operation_id"]
    )
    assert existing["provenance"] == ["capture-index", "spec"]
    assert inventory["total"] == 2


def test_empty_success_is_an_explicit_source_gap(tmp_path):
    store = AssessmentStore(tmp_path)
    initialize(store)
    import_operations(store, [])
    report = store.dispatch("gaps", {})
    assert report["totals"]["operations"] == 0
    assert report["source_gaps"][0]["status"] == "empty"
    assert report["complete"] is False


def test_attested_evidence_is_hashed_not_stored_and_role_results_survive_imports(tmp_path):
    store = AssessmentStore(tmp_path)
    initialize(
        store,
        required_roles=["reader", "administrator"],
        available_roles=["reader", "administrator"],
        source_available=True,
    )
    import_operations(store)
    content = b"Synthetic private response; Authorization: Bearer do-not-persist-this-value"
    (tmp_path / "evidence.txt").write_bytes(content)
    administrator = case_for(store, "auth.access-control", "administrator")
    saved = record(store, administrator)
    assert saved["revision"] == 3
    result = saved["case"]
    assert result["status"] == "pass"
    assert result["evaluation_mode"] == "attested"
    assert "not independently verified" in result["reason"]
    assert result["evidence"] == [
        {
            "path": "evidence.txt",
            "sha256": hashlib.sha256(content).hexdigest(),
            "size_bytes": len(content),
        }
    ]
    assert result["trusted"] is True
    assert len(result["history"]) == 1
    assert result["history"][0]["revision"] == 3
    assert case_for(store, "auth.access-control", "reader")["status"] == "untested"

    reader = case_for(store, "auth.access-control", "reader")
    record(store, reader, status="fail")
    import_operations(store, source={"id": "traffic", "kind": "traffic", "status": "ok"})
    restored = case_for(AssessmentStore(tmp_path), "auth.access-control", "administrator")
    assert restored["status"] == "pass"
    assert restored["evidence"] == result["evidence"]
    assert restored["history"] == result["history"]
    assert restored["provenance"] == ["spec", "traffic"]
    assert case_for(store, "auth.access-control", "reader")["status"] == "fail"
    report = store.dispatch("report", {})
    assert report["coverage"]["evaluation_modes"] == {"attested": 2, "deterministic": 0}
    assert "do-not-persist-this-value" not in json.dumps(report)
    assert (
        b"do-not-persist-this-value"
        not in (tmp_path / "assessment" / "coverage.sqlite3").read_bytes()
    )


@pytest.mark.parametrize("status", ["pass", "fail"])
def test_record_requires_real_evidence_and_available_prerequisites(tmp_path, status):
    store = AssessmentStore(tmp_path)
    initialize(store)
    import_operations(store)
    (tmp_path / "evidence.txt").write_text("Synthetic evidence")
    header = case_for(store, "http.nosniff")
    before = store.dispatch("report", {})
    for evidence_paths in ([], ["missing.txt"], ["evidence.txt", "missing.txt"], "evidence.txt"):
        with pytest.raises(AssessmentError):
            record(store, header, status=status, evidence_paths=evidence_paths)
    for control in ("auth.access-control", "source.authorization"):
        with pytest.raises(AssessmentError, match="unavailable"):
            record(store, case_for(store, control), status=status)
    assert store.dispatch("report", {}) == before


def test_not_applicable_requires_rationale_and_cannot_bypass_missing_access(tmp_path):
    store = AssessmentStore(tmp_path)
    initialize(store)
    import_operations(store)
    header = case_for(store, "http.hsts")
    for rationale in (None, "", "  "):
        with pytest.raises(AssessmentError):
            record(store, header, status="not_applicable", evidence_paths=[], rationale=rationale)
    for control in ("auth.access-control", "source.authorization"):
        with pytest.raises(AssessmentError, match="unavailable"):
            record(store, case_for(store, control), status="not_applicable", evidence_paths=[])
    saved = record(
        store,
        header,
        status="not_applicable",
        evidence_paths=[],
        rationale="Explicitly excluded for this synthetic protocol context.",
    )
    assert saved["case"]["status"] == "not_applicable"
    report = store.dispatch("report", {})
    assert report["coverage"]["not_applicable"] == 1
    assert report["coverage"]["applicable"] == 3
    assert report["complete"] is False


@pytest.mark.parametrize("status", ["blocked", "inconclusive"])
def test_unresolved_attestations_remain_eligible_without_fabricating_results(tmp_path, status):
    store = AssessmentStore(tmp_path)
    initialize(store)
    import_operations(store)
    header = case_for(store, "http.nosniff")
    saved = record(
        store,
        header,
        status=status,
        evidence_paths=[],
        rationale="Additional artifact review is needed.",
    )
    assert saved["case"]["status"] == status
    assert saved["case"]["evidence"] == []
    assert header["case_id"] in {case["case_id"] for case in store.dispatch("next", {})["cases"]}
    assert store.dispatch("report", {})["complete"] is False


def test_evidence_paths_are_isolated_and_symlinks_and_special_files_are_rejected(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    outside = tmp_path / "outside.txt"
    outside.write_text("Synthetic outside artifact that must not be read")
    store = AssessmentStore(workspace)
    initialize(store)
    import_operations(store)
    header = case_for(store, "http.nosniff")
    (workspace / "leak.txt").symlink_to(outside)
    (workspace / "linked-directory").symlink_to(tmp_path, target_is_directory=True)
    (workspace / "empty.txt").touch()
    (workspace / "directory").mkdir()
    os.mkfifo(workspace / "pipe")
    before = store.dispatch("report", {})
    paths = [
        str(outside),
        "../outside.txt",
        "directory/../../outside.txt",
        "leak.txt",
        "linked-directory/outside.txt",
        "C:\\outside.txt",
        "C:/outside.txt",
        "..\\outside.txt",
        "empty.txt",
        "directory",
        "pipe",
        "",
        ".",
        "missing.txt",
        123,
        "assessment/coverage.sqlite3",
    ]
    for path in paths:
        with pytest.raises(AssessmentError):
            record(store, header, evidence_paths=[path])
    assert store.dispatch("report", {}) == before
    (workspace / "directory" / "proof.txt").write_text("Explicitly cited synthetic proof")
    assert record(store, header, evidence_paths=["directory/proof.txt"])["case"]["status"] == "pass"


def test_only_explicitly_cited_files_are_read(tmp_path, monkeypatch):
    store = AssessmentStore(tmp_path)
    initialize(store)
    import_operations(store)
    header = case_for(store, "http.nosniff")
    (tmp_path / "evidence.txt").write_text("Explicit synthetic evidence")
    (tmp_path / "unrelated.txt").write_text("Not cited, must not be opened")
    real_open = os.open
    reads = []

    def tracking_open(path, flags, *args, **kwargs):
        if not flags & os.O_DIRECTORY:
            reads.append(str(path))
        return real_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(os, "open", tracking_open)
    monkeypatch.setattr(os, "supports_dir_fd", os.supports_dir_fd | {tracking_open})
    record(store, header)
    store.dispatch("report", {})
    store.dispatch("gaps", {})
    assert reads and set(reads) == {"evidence.txt"}


@pytest.mark.parametrize("change", ["replace", "delete", "symlink"])
def test_changed_evidence_invalidates_full_coverage_even_outside_the_page(tmp_path, change):
    store = AssessmentStore(tmp_path)
    initialize(store, available_roles=["authenticated"], source_available=True)
    import_operations(store)
    cases = store.dispatch("report", {})["cases"]
    for index, case in enumerate(cases):
        name = f"evidence-{index}.txt"
        (tmp_path / name).write_text(f"Synthetic attestation {index}")
        record(store, case, evidence_paths=[name])
    complete = store.dispatch("report", {"limit": 1})
    assert complete["complete"] is True
    assert complete["coverage"]["percent"] == 100
    assert complete["total"] == 4
    assert len(complete["cases"]) == 1
    revision = complete["revision"]
    last_path = tmp_path / f"evidence-{len(cases) - 1}.txt"
    if change == "replace":
        last_path.write_text("Changed synthetic artifact")
    elif change == "delete":
        last_path.unlink()
    else:
        replacement = tmp_path / "replacement.txt"
        replacement.write_bytes(last_path.read_bytes())
        last_path.unlink()
        last_path.symlink_to(replacement)
    fresh = AssessmentStore(tmp_path)
    report = fresh.dispatch("report", {"limit": 1})
    assert report["revision"] == revision
    assert report["complete"] is False
    assert report["totals"]["untrusted"] == 1
    assert report["status_counts"]["pass"] == 3
    assert report["status_counts"]["inconclusive"] == 1
    assert report["coverage"]["percent"] == 75
    gap = fresh.dispatch("gaps", {})["gaps"][0]
    assert gap["case_id"] == cases[-1]["case_id"]
    assert gap["recorded_status"] == "pass"
    assert gap["status"] == "inconclusive"
    assert gap["trusted"] is False
    assert gap["evidence_errors"][0]["path"] == last_path.name
    assert fresh.dispatch("next", {})["cases"][0]["case_id"] == gap["case_id"]
    assert len(gap["history"]) == 1
    if last_path.is_symlink():
        last_path.unlink()
    last_path.write_text("New reviewed synthetic evidence")
    saved = record(fresh, gap, evidence_paths=[last_path.name])
    assert len(saved["case"]["history"]) == 2
    assert saved["revision"] == revision + 1
    assert fresh.dispatch("report", {})["complete"] is True


def test_losing_access_reblocks_without_destroying_prior_attestations(tmp_path):
    store = AssessmentStore(tmp_path)
    initialize(store, available_roles=["authenticated"], source_available=True)
    import_operations(store)
    (tmp_path / "evidence.txt").write_text("Synthetic authorization review")
    case = case_for(store, "auth.access-control")
    saved = record(store, case)["case"]
    initialize(store, available_roles=[], source_available=False)
    assert case_for(store, "auth.access-control")["status"] == "pass"
    store.dispatch("access", {"available_roles": [], "source_available": False})
    blocked = case_for(store, "auth.access-control")
    assert blocked["status"] == "blocked"
    assert blocked["recorded_status"] == "pass"
    assert blocked["history"] == saved["history"]
    store.dispatch("access", {"available_roles": ["authenticated"], "source_available": True})
    assert case_for(store, "auth.access-control")["status"] == "pass"


@pytest.mark.parametrize(
    ("control", "headers", "expected"),
    [
        ("http.nosniff", {"X-CoNtEnT-TyPe-OpTiOnS": " NoSnIfF "}, "pass"),
        ("http.nosniff", {"x-content-type-options": ["nosniff"]}, "pass"),
        ("http.nosniff", {}, "fail"),
        ("http.nosniff", {"X-Content-Type-Options": "invalid"}, "fail"),
        ("http.nosniff", {"X-Content-Type-Options": "nosniff, nosniff"}, "fail"),
        (
            "http.nosniff",
            {"X-Content-Type-Options": "nosniff", "x-content-type-options": "other"},
            "fail",
        ),
        ("http.hsts", {"STRICT-transport-security": "max-age=1; includeSubDomains"}, "pass"),
        ("http.hsts", {"Strict-Transport-Security": 'MAX-AGE="60"; preload'}, "pass"),
        ("http.hsts", {}, "fail"),
        ("http.hsts", {"Strict-Transport-Security": "max-age=0"}, "fail"),
        ("http.hsts", {"Strict-Transport-Security": "max-age=-1"}, "fail"),
        ("http.hsts", {"Strict-Transport-Security": "max-age=1e3"}, "fail"),
        ("http.hsts", {"Strict-Transport-Security": "max-age=100; max-age=0"}, "fail"),
        ("http.hsts", {"Strict-Transport-Security": ["max-age=100", "max-age=200"]}, "fail"),
    ],
)
def test_header_checks_are_deterministic_and_case_insensitive(tmp_path, control, headers, expected):
    store = AssessmentStore(tmp_path)
    initialize(store)
    import_operations(store)
    path = write_capture(tmp_path, headers=headers)
    saved = check_headers(store, case_for(store, control), path)
    assert saved["case"]["status"] == expected
    assert saved["case"]["evaluation_mode"] == "deterministic"
    assert (
        saved["case"]["evidence"][0]["sha256"]
        == hashlib.sha256((tmp_path / path).read_bytes()).hexdigest()
    )
    assert saved["case"]["history"][0]["action"] == "check_headers"
    assert saved["case"]["trusted"] is True


def test_hsts_on_http_is_explicitly_not_applicable(tmp_path):
    store = AssessmentStore(tmp_path)
    initialize(store)
    import_operations(store, [{"url": "http://api.example.test/items", "method": "GET"}])
    write_capture(tmp_path, url="http://api.example.test:80/items")
    saved = check_headers(store, case_for(store, "http.hsts"))
    assert saved["case"]["status"] == "not_applicable"
    assert "HTTPS" in saved["case"]["reason"]
    report = store.dispatch("report", {})
    assert report["coverage"]["not_applicable"] == 1
    assert report["coverage"]["applicable"] == 3
    assert report["status_counts"]["blocked"] == 2


@pytest.mark.parametrize("status_code", [101, 301, 401, 403, 429, 500, 503])
def test_non_success_responses_are_inconclusive_not_assessed_as_targets(tmp_path, status_code):
    store = AssessmentStore(tmp_path)
    initialize(store)
    import_operations(store)
    write_capture(tmp_path, status_code=status_code)
    saved = check_headers(store, case_for(store, "http.nosniff"))
    assert saved["case"]["status"] == "inconclusive"
    assert str(status_code) in saved["case"]["reason"]
    assert store.dispatch("report", {})["coverage"]["assessed"] == 0


@pytest.mark.parametrize(
    "changes",
    [
        {"headers": {"X-Content-Type-Options": "nosniff", "Cf-Mitigated": "challenge"}},
        {"headers": {"Strict-Transport-Security": "max-age=10", "X-Amzn-Waf-Action": "captcha"}},
        {"error": "synthetic transport failure"},
        {"challenge": True},
        {"is_response": False},
    ],
)
def test_challenge_error_and_non_response_artifacts_are_inconclusive(tmp_path, changes):
    store = AssessmentStore(tmp_path)
    initialize(store)
    import_operations(store)
    write_capture(tmp_path, **changes)
    saved = check_headers(store, case_for(store, "http.nosniff"))
    assert saved["case"]["status"] == "inconclusive"
    assert store.dispatch("report", {})["complete"] is False


@pytest.mark.parametrize(
    "changes",
    [
        {"source": "mock"},
        {"source": "manual"},
        {"source": None},
        {"captured_at": None},
        {"captured_at": "not-a-time"},
        {"captured_at": "2025-01-01T12:00:00"},
        {"captured_at": "9999-01-01T00:00:00Z"},
        {"url": "https://api.example.test/Items"},
        {"method": "POST"},
        {"url": "https://different.example.test/items"},
        {"url": "https://user:password@api.example.test/items"},
        {"url": "https://api.example.test/items?new-name=secret"},
        {"url": "/items"},
        {"status_code": 0},
        {"status_code": 600},
        {"status_code": True},
        {"status_code": "200"},
        {"headers": []},
        {"headers": {"bad\nname": "nosniff"}},
        {"headers": {"X-Content-Type-Options": "nosniff\r\nInjected: yes"}},
    ],
)
def test_invalid_or_mismatched_captures_are_rejected_without_mutation(tmp_path, changes):
    store = AssessmentStore(tmp_path)
    initialize(store)
    import_operations(store)
    before = store.dispatch("report", {})
    write_capture(tmp_path, **changes)
    with pytest.raises(AssessmentError):
        check_headers(store, case_for(store, "http.nosniff"))
    assert store.dispatch("report", {}) == before


def test_header_artifacts_match_canonical_urls_without_retaining_response_secrets(tmp_path):
    store = AssessmentStore(tmp_path)
    initialize(store)
    import_operations(
        store,
        [{"url": "https://API.EXAMPLE.TEST:443/Items?token=import-secret&a=1", "method": "GET"}],
    )
    write_capture(
        tmp_path, url="https://api.example.test/Items?a=2&token=capture-secret", method="get"
    )
    saved = check_headers(store, case_for(store, "http.nosniff"))
    assert saved["case"]["status"] == "pass"
    assert saved["case"]["url"] == "https://api.example.test/Items?a&token"
    output = json.dumps(store.dispatch("report", {}))
    raw = (tmp_path / "assessment" / "coverage.sqlite3").read_bytes()
    for marker in (
        "do-not-store-http-secret",
        "do-not-store-http-body",
        "import-secret",
        "capture-secret",
    ):
        assert marker not in output
        assert marker.encode() not in raw
    for control in ("auth.access-control", "source.authorization"):
        with pytest.raises(AssessmentError):
            check_headers(store, case_for(store, control))


def test_completed_assessment_keeps_na_separate_and_source_gaps_prevent_completion(tmp_path):
    store = AssessmentStore(tmp_path)
    initialize(store, available_roles=["authenticated"], source_available=True)
    import_operations(store)
    (tmp_path / "evidence.txt").write_text("Synthetic role authorization artifact")
    write_capture(tmp_path)
    check_headers(store, case_for(store, "http.nosniff"))
    check_headers(store, case_for(store, "http.hsts"))
    record(store, case_for(store, "auth.access-control"))
    record(
        store,
        case_for(store, "source.authorization"),
        status="not_applicable",
        evidence_paths=[],
        rationale="Synthetic endpoint's source review is explicitly excluded for this case.",
    )
    report = store.dispatch("report", {"limit": 1})
    assert report["complete"] is True
    assert report["coverage"]["applicable"] == report["coverage"]["assessed"] == 3
    assert report["coverage"]["not_applicable"] == 1
    assert report["coverage"]["evaluation_modes"] == {"attested": 1, "deterministic": 2}
    import_operations(store, [], source={"id": "spec", "kind": "openapi", "status": "error"})
    gap_report = store.dispatch("gaps", {})
    assert gap_report["total"] == 0
    assert gap_report["source_gaps"]
    assert gap_report["complete"] is False
    assert gap_report["coverage"] == report["coverage"]
    import_operations(store)
    assert store.dispatch("report", {})["complete"] is True


@pytest.mark.parametrize(
    "invalid",
    [
        {"url": "https://outside.example.test/items", "method": "GET"},
        {"url": "https://services.example.test/items", "method": "GET"},
        {"url": "https://api.example.test.evil.test/items", "method": "GET"},
        {"url": "https://user:secret@api.example.test/items", "method": "GET"},
        {"url": "ftp://api.example.test/items", "method": "GET"},
        {"url": "https://api.example.test:99999/items", "method": "GET"},
        {"url": "https://api.example.test/%ZZ", "method": "GET"},
        {"url": " https://api.example.test/items", "method": "GET"},
        {"path": "//outside.example.test/items", "method": "GET"},
        {"path": "/items", "method": "GET\nPOST"},
        {"path": "/items", "method": None},
        {"path": "/items", "method": "GET", "parameters": [{"name": "x", "in": "unknown"}]},
        {"path": "/items", "method": "GET", "parameters": "invalid"},
        None,
    ],
)
@pytest.mark.parametrize("source_status", ["ok", "mock"])
def test_invalid_import_batches_roll_back_every_operation_and_source(
    tmp_path, invalid, source_status
):
    store = AssessmentStore(tmp_path)
    initialize(store)
    import_operations(store)
    before = store.dispatch("report", {})
    with pytest.raises(AssessmentError):
        import_operations(
            store,
            [{"path": "/must-not-be-imported", "method": "POST"}, invalid],
            source={"id": "new-source", "kind": "traffic", "status": source_status},
        )
    assert AssessmentStore(tmp_path).dispatch("report", {}) == before
    assert store.dispatch("inventory", {})["total"] == 1


def test_direct_import_denies_excluded_host_before_wildcard_allow_and_rolls_back(tmp_path):
    store = AssessmentStore(tmp_path)
    initialize(store, allowed_hosts=["*.example.test"], denied_hosts=["excluded.example.test"])
    import_operations(store)
    before = store.dispatch("report", {})
    with pytest.raises(AssessmentError, match="denied_hosts"):
        store.dispatch(
            "import",
            {
                "operations": [
                    {"url": "https://valid.example.test/new", "method": "GET"},
                    {"url": "https://excluded.example.test/private", "method": "POST"},
                ],
                "source": {"id": "direct-http", "kind": "manual", "status": "ok"},
            },
        )
    assert AssessmentStore(tmp_path).dispatch("report", {}) == before
    assert store.dispatch("inventory", {})["revision"] == before["revision"] == 2
    assert store.dispatch("inventory", {})["total"] == 1
    assert before["denied_hosts"] == ["excluded.example.test"]


def test_denied_policy_is_canonical_immutable_and_visible_after_reload(tmp_path):
    store = AssessmentStore(tmp_path)
    config = {
        "allowed_hosts": ["*.EXAMPLE.TEST."],
        "denied_hosts": [
            "Excluded.EXAMPLE.TEST.",
            "*.Private.Example.Test.",
            "excluded.example.test",
        ],
    }
    initialized = initialize(store, **config)
    assert initialized["denied_hosts"] == ["*.private.example.test", "excluded.example.test"]
    import_operations(store)
    before = store.dispatch("report", {})
    same_policy = config | {"denied_hosts": ["*.PRIVATE.EXAMPLE.TEST", "EXCLUDED.EXAMPLE.TEST"]}
    assert initialize(AssessmentStore(tmp_path), **same_policy)["revision"] == before["revision"]
    for denied_hosts in ([], ["other.example.test"], ["excluded.example.test"]):
        with pytest.raises(AssessmentError, match="Immutable engagement denied_hosts"):
            initialize(store, **(config | {"denied_hosts": denied_hosts}))
    with pytest.raises(AssessmentError, match="Immutable engagement denied_hosts"):
        initialize(store, allowed_hosts=config["allowed_hosts"])
    assert store.dispatch("report", {}) == before
    for action in ("next", "report", "gaps"):
        assert (
            AssessmentStore(tmp_path).dispatch(action, {})["denied_hosts"]
            == initialized["denied_hosts"]
        )


@pytest.mark.parametrize(
    "host",
    [
        "EXCLUDED.EXAMPLE.TEST",
        "excluded.example.test.",
        "ExClUdEd.ExAmPlE.TeSt.:443",
        "child.PRIVATE.example.test",
        "deep.child.private.example.test.",
    ],
)
def test_exact_and_wildcard_denials_cover_case_and_terminal_dot_variants(tmp_path, host):
    store = AssessmentStore(tmp_path)
    initialize(
        store,
        allowed_hosts=["*.example.test"],
        denied_hosts=["excluded.example.test", "*.private.example.test"],
    )
    import_operations(
        store,
        [
            {"url": f"https://{allowed}/items", "method": "GET"}
            for allowed in (
                "child.excluded.example.test",
                "private.example.test",
                "notprivate.example.test",
            )
        ],
    )
    before = store.dispatch("report", {})
    with pytest.raises(AssessmentError, match="denied_hosts"):
        import_operations(store, [{"url": f"https://{host}/items", "method": "GET"}])
    assert store.dispatch("report", {}) == before
    assert before["totals"]["operations"] == 3


@pytest.mark.parametrize("kind", ["openapi", "traffic", "source", "manual", "osint"])
@pytest.mark.parametrize("status", ["ok", "mock", "error", "unavailable"])
def test_direct_source_metadata_and_per_operation_base_cannot_bypass_denials(
    tmp_path, kind, status
):
    store = AssessmentStore(tmp_path)
    initialize(store, allowed_hosts=["*.example.test"], denied_hosts=["excluded.example.test"])
    import_operations(store)
    before = store.dispatch("report", {})
    with pytest.raises(AssessmentError, match="denied_hosts"):
        store.dispatch(
            "import",
            {
                "base_url": "https://api.example.test",
                "allowed_hosts": ["excluded.example.test"],
                "denied_hosts": [],
                "operations": [
                    {
                        "path": "/private",
                        "base_url": "https://EXCLUDED.example.test.",
                        "method": "GET",
                        "allowed_hosts": ["excluded.example.test"],
                        "denied_hosts": [],
                    }
                ],
                "source": {
                    "id": "direct-source",
                    "kind": kind,
                    "status": status,
                    "denied_hosts": [],
                },
            },
        )
    assert AssessmentStore(tmp_path).dispatch("report", {}) == before


@pytest.mark.parametrize(
    ("network", "canonical", "excluded", "neighbor"),
    [
        ("192.0.2.99/24", "192.0.2.0/24", "192.0.2.17", "192.0.3.17"),
        (
            "2001:DB8:ABCD:1::99/48",
            "2001:db8:abcd::/48",
            "2001:db8:abcd:ffff::1",
            "2001:db8:abce::1",
        ),
        ("192.0.2.0/24", "192.0.2.0/24", "::ffff:192.0.2.17", "::ffff:192.0.3.17"),
    ],
)
def test_cidr_denials_are_canonical_and_apply_to_literal_ip_hosts(
    tmp_path, network, canonical, excluded, neighbor
):
    store = AssessmentStore(tmp_path)
    allowed = ["*.example.test", excluded, neighbor]
    initialized = initialize(store, allowed_hosts=allowed, denied_hosts=[network])
    assert initialized["denied_hosts"] == [canonical]
    neighbor_url = f"https://[{neighbor}]/items" if ":" in neighbor else f"https://{neighbor}/items"
    import_operations(
        store,
        [
            {"url": neighbor_url, "method": "GET"},
            {"url": "https://192-0-2-17.example.test/items", "method": "GET"},
        ],
    )
    before = store.dispatch("report", {})
    excluded_url = (
        f"https://[{excluded}]/private" if ":" in excluded else f"https://{excluded}/private"
    )
    with pytest.raises(AssessmentError, match="denied_hosts"):
        import_operations(store, [{"url": excluded_url, "method": "GET"}])
    assert (
        initialize(AssessmentStore(tmp_path), allowed_hosts=allowed, denied_hosts=[canonical])[
            "revision"
        ]
        == before["revision"]
    )
    with pytest.raises(AssessmentError, match="Immutable engagement denied_hosts"):
        initialize(store, allowed_hosts=allowed, denied_hosts=[])
    assert store.dispatch("report", {}) == before


@pytest.mark.parametrize(
    "denied_hosts",
    [
        None,
        "excluded.example.test",
        {},
        [None],
        ["*"],
        ["private.*.example.test"],
        ["https://excluded.example.test"],
        ["excluded.example.test:443"],
        ["*.192.0.2.1"],
        ["192.0.2.0/33"],
        ["2001:db8::/129"],
        ["fe80::%zone/64"],
        ["excluded.example.test/24"],
        ["192.0.2.0/255.255.255.0"],
    ],
)
def test_invalid_denied_scope_is_rejected_before_storage_mutation(tmp_path, denied_hosts):
    store = AssessmentStore(tmp_path)
    with pytest.raises(AssessmentError):
        initialize(store, denied_hosts=denied_hosts)
    assert not (tmp_path / "assessment" / "coverage.sqlite3").exists()
    assert initialize(store)["denied_hosts"] == []


def test_cidr_scope_is_not_accepted_as_an_allow_rule(tmp_path):
    store = AssessmentStore(tmp_path)
    with pytest.raises(AssessmentError):
        initialize(store, allowed_hosts=["192.0.2.0/24"])
    assert not (tmp_path / "assessment" / "coverage.sqlite3").exists()


def test_legacy_v1_missing_denials_preserves_progress_checksums_and_history(tmp_path):
    store = AssessmentStore(tmp_path)
    initialize(store)
    import_operations(store)
    (tmp_path / "evidence.txt").write_text("Synthetic legacy evidence")
    saved = record(store, case_for(store, "http.nosniff"))["case"]
    expected = store.dispatch("report", {})
    expected["history"][0]["details"].pop("denied_hosts")
    database = tmp_path / "assessment" / "coverage.sqlite3"
    with closing(sqlite3.connect(database)) as db, db:
        state = json.loads(db.execute("SELECT state FROM ledger").fetchone()[0])
        state.pop("denied_hosts")
        raw = json.dumps(state, sort_keys=True, separators=(",", ":"))
        digest = hashlib.sha256(raw.encode()).hexdigest()
        initial_details = json.loads(
            db.execute("SELECT details FROM history WHERE revision = 1").fetchone()[0]
        )
        initial_details.pop("denied_hosts")
        db.execute(
            "UPDATE history SET details = ? WHERE revision = 1", (json.dumps(initial_details),)
        )
        db.execute("UPDATE ledger SET state = ?, sha256 = ?", (raw, digest))
        db.execute(
            "UPDATE history SET state_sha256 = ? WHERE revision = ?", (digest, state["revision"])
        )
        legacy_row = db.execute("SELECT state, sha256, revision FROM ledger").fetchone()
        legacy_history = db.execute("SELECT * FROM history ORDER BY revision").fetchall()
    fresh = AssessmentStore(tmp_path)
    assert fresh.dispatch("report", {}) == expected
    assert initialize(fresh)["denied_hosts"] == []
    assert initialize(fresh, denied_hosts=[])["revision"] == expected["revision"]
    with pytest.raises(AssessmentError, match="Immutable engagement denied_hosts"):
        initialize(fresh, denied_hosts=["excluded.example.test"])
    with closing(sqlite3.connect(database)) as db, db:
        assert db.execute("SELECT state, sha256, revision FROM ledger").fetchone() == legacy_row
        assert db.execute("SELECT * FROM history ORDER BY revision").fetchall() == legacy_history
        assert "denied_hosts" not in json.loads(legacy_row[0])
    updated = fresh.dispatch(
        "access", {"available_roles": ["authenticated"], "source_available": True}
    )
    assert updated["revision"] == expected["revision"] + 1
    assert updated["denied_hosts"] == []
    assert case_for(AssessmentStore(tmp_path), "http.nosniff")["history"] == saved["history"]
    with closing(sqlite3.connect(database)) as db, db:
        raw, digest = db.execute("SELECT state, sha256 FROM ledger").fetchone()
        assert json.loads(raw)["denied_hosts"] == []
        assert hashlib.sha256(raw.encode()).hexdigest() == digest
        assert (
            db.execute("SELECT * FROM history ORDER BY revision").fetchall()[:-1] == legacy_history
        )
        assert db.execute("PRAGMA user_version").fetchone()[0] == 1


def test_legacy_optional_default_does_not_bypass_raw_state_checksum(tmp_path):
    store = AssessmentStore(tmp_path)
    initialize(store)
    with closing(sqlite3.connect(tmp_path / "assessment" / "coverage.sqlite3")) as db, db:
        state = json.loads(db.execute("SELECT state FROM ledger").fetchone()[0])
        state.pop("denied_hosts")
        raw = json.dumps(state, sort_keys=True, separators=(",", ":"))
        db.execute("UPDATE ledger SET state = ?", (raw,))
    with pytest.raises(AssessmentError):
        store.dispatch("report", {})
    with pytest.raises(AssessmentError):
        initialize(store)


def test_missing_field_cannot_erase_an_explicit_initialized_deny_policy(tmp_path):
    store = AssessmentStore(tmp_path)
    initialize(store, denied_hosts=["excluded.example.test"])
    with closing(sqlite3.connect(tmp_path / "assessment" / "coverage.sqlite3")) as db, db:
        state = json.loads(db.execute("SELECT state FROM ledger").fetchone()[0])
        state.pop("denied_hosts")
        raw = json.dumps(state, sort_keys=True, separators=(",", ":"))
        digest = hashlib.sha256(raw.encode()).hexdigest()
        db.execute("UPDATE ledger SET state = ?, sha256 = ?", (raw, digest))
        db.execute(
            "UPDATE history SET state_sha256 = ? WHERE revision = ?", (digest, state["revision"])
        )
    with pytest.raises(AssessmentError):
        store.dispatch("report", {})


@pytest.mark.parametrize(
    "denied_hosts",
    [
        None,
        "excluded.example.test",
        ["EXCLUDED.EXAMPLE.TEST."],
        ["192.0.2.1/24"],
        ["192.0.2.0/33"],
        ["api.example.test"],
    ],
)
def test_checksummed_denial_state_is_validated_and_existing_operations_must_comply(
    tmp_path, denied_hosts
):
    store = AssessmentStore(tmp_path)
    initialize(store, denied_hosts=["excluded.example.test"])
    import_operations(store)
    with closing(sqlite3.connect(tmp_path / "assessment" / "coverage.sqlite3")) as db, db:
        state = json.loads(db.execute("SELECT state FROM ledger").fetchone()[0])
        state["denied_hosts"] = denied_hosts
        raw = json.dumps(state, sort_keys=True, separators=(",", ":"))
        digest = hashlib.sha256(raw.encode()).hexdigest()
        initial_details = json.loads(
            db.execute("SELECT details FROM history WHERE revision = 1").fetchone()[0]
        )
        initial_details["denied_hosts"] = denied_hosts
        db.execute(
            "UPDATE history SET details = ? WHERE revision = 1", (json.dumps(initial_details),)
        )
        db.execute("UPDATE ledger SET state = ?, sha256 = ?", (raw, digest))
        db.execute(
            "UPDATE history SET state_sha256 = ? WHERE revision = ?", (digest, state["revision"])
        )
    for action in ("inventory", "report", "gaps"):
        with pytest.raises(AssessmentError):
            store.dispatch(action, {})


def test_operation_identity_preserves_path_case_methods_query_names_and_nondefault_ports(tmp_path):
    store = AssessmentStore(tmp_path)
    initialize(store)
    operations = [
        {"url": "https://API.EXAMPLE.TEST:443/Items?token=secret-1&name=a", "method": "get"},
        {"url": "https://api.example.test/Items?name=b&token=secret-2", "method": "GET"},
        {"url": "https://api.example.test/items?token=secret-3&name=b", "method": "GET"},
        {"url": "https://api.example.test/Items?name=b&token=secret-4", "method": "POST"},
        {"url": "https://api.example.test:8443/Items?name=b&token=secret-5", "method": "GET"},
        {"url": "https://nested.a.services.example.test/Items", "method": "GET"},
    ]
    imported = import_operations(store, operations)
    assert imported["imported"] == 5
    inventory = store.dispatch("inventory", {})["operations"]
    assert len({op["operation_id"] for op in inventory}) == 5
    assert all("secret-" not in op["url"] for op in inventory)
    original_ids = {case["case_id"] for case in store.dispatch("report", {})["cases"]}
    assert len(original_ids) == 20
    import_operations(store, list(reversed(operations)))
    assert {case["case_id"] for case in store.dispatch("report", {})["cases"]} == original_ids


@pytest.mark.parametrize(
    "changes",
    [
        {"engagement_name": "../escape"},
        {"engagement_name": "unsafe name"},
        {"engagement_name": " padded "},
        {"engagement_name": ""},
        {"allowed_hosts": []},
        {"allowed_hosts": ["*"]},
        {"allowed_hosts": ["https://api.example.test"]},
        {"allowed_hosts": ["api.example.test:443"]},
        {"allowed_hosts": ["*.127.0.0.1"]},
        {"profile": "full-asvs"},
        {"required_roles": "authenticated"},
        {"available_roles": [None]},
        {"source_available": "true"},
    ],
)
def test_invalid_initialization_never_creates_or_resets_a_ledger(tmp_path, changes):
    store = AssessmentStore(tmp_path)
    with pytest.raises(AssessmentError):
        initialize(store, **changes)
    assert not (tmp_path / "assessment" / "coverage.sqlite3").exists()
    with pytest.raises(AssessmentError, match="not initialized"):
        store.dispatch("inventory", {})
    assert initialize(store)["revision"] == 1


@pytest.mark.parametrize("action", ["inventory", "next", "report", "gaps"])
@pytest.mark.parametrize(
    "page", [{"limit": 0}, {"limit": 1001}, {"limit": True}, {"offset": -1}, {"offset": "1"}]
)
def test_invalid_pagination_is_rejected_without_mutation(tmp_path, action, page):
    store = AssessmentStore(tmp_path)
    initialize(store)
    import_operations(store)
    with pytest.raises(AssessmentError):
        store.dispatch(action, page)
    assert store.dispatch("inventory", {})["revision"] == 2
    empty_page = store.dispatch(action, {"offset": 1000, "limit": 1000})
    assert empty_page["has_more"] is False
    assert empty_page["next_offset"] is None
    assert empty_page["total"] > 0


def test_every_mutation_rejects_stale_revisions_and_preserves_the_winning_update(tmp_path):
    store = AssessmentStore(tmp_path)
    initialize(store, expected_revision=0)
    import_operations(store, expected_revision=1)
    (tmp_path / "evidence.txt").write_text("Synthetic revision evidence")
    write_capture(tmp_path)
    case = case_for(store, "http.nosniff")
    before = store.dispatch("report", {})
    for action in (
        lambda: initialize(store, expected_revision=1),
        lambda: import_operations(store, expected_revision=1),
        lambda: store.dispatch(
            "access", {"available_roles": [], "source_available": False, "expected_revision": 1}
        ),
        lambda: record(store, case, expected_revision=1),
        lambda: check_headers(store, case, expected_revision=1),
    ):
        with pytest.raises(AssessmentConflictError):
            action()
    assert issubclass(AssessmentConflictError, AssessmentError)
    assert issubclass(AssessmentError, ValueError)
    assert store.dispatch("report", {}) == before
    winner = record(AssessmentStore(tmp_path), case, expected_revision=2)
    assert winner["revision"] == 3
    with pytest.raises(AssessmentConflictError):
        record(store, case, expected_revision=2)
    assert case_for(store, "http.nosniff")["history"] == winner["case"]["history"]


@pytest.mark.parametrize("contents", [b"", b"not a SQLite database"])
def test_corrupt_database_is_rejected_instead_of_reset(tmp_path, contents):
    directory = tmp_path / "assessment"
    directory.mkdir()
    database = directory / "coverage.sqlite3"
    database.write_bytes(contents)
    store = AssessmentStore(tmp_path)
    with pytest.raises(AssessmentError):
        initialize(store)
    assert database.read_bytes() == contents


def test_schema_mismatch_and_copied_workspace_are_rejected(tmp_path):
    workspace = tmp_path / "one"
    workspace.mkdir()
    store = AssessmentStore(workspace)
    initialize(store)
    import_operations(store)
    database = workspace / "assessment" / "coverage.sqlite3"
    with closing(sqlite3.connect(database)) as db, db:
        assert db.execute("PRAGMA user_version").fetchone()[0] == 1
        db.execute("PRAGMA user_version = 99")
    with pytest.raises(AssessmentError):
        initialize(store)
    with closing(sqlite3.connect(database)) as db, db:
        assert db.execute("PRAGMA user_version").fetchone()[0] == 99
        db.execute("PRAGMA user_version = 1")
    other = tmp_path / "two"
    (other / "assessment").mkdir(parents=True)
    (other / "assessment" / "coverage.sqlite3").write_bytes(database.read_bytes())
    with pytest.raises(AssessmentError, match="mismatched"):
        initialize(AssessmentStore(other))
    assert store.dispatch("inventory", {})["total"] == 1


@pytest.mark.parametrize(
    "corruption", ["missing_case", "unknown_control", "operation_url", "evidence", "schema_type"]
)
def test_checksummed_but_inconsistent_state_is_not_silently_rebuilt(tmp_path, corruption):
    store = AssessmentStore(tmp_path)
    initialize(store)
    import_operations(store)
    database = tmp_path / "assessment" / "coverage.sqlite3"
    with closing(sqlite3.connect(database)) as db, db:
        state = json.loads(db.execute("SELECT state FROM ledger").fetchone()[0])
        case_id = next(iter(state["cases"]))
        if corruption == "missing_case":
            del state["cases"][case_id]
        elif corruption == "unknown_control":
            state["cases"][case_id]["control_id"] = "full-asvs"
        elif corruption == "operation_url":
            next(iter(state["operations"].values()))["url"] = "https://outside.example.test/items"
        elif corruption == "evidence":
            state["cases"][case_id]["status"] = "pass"
            state["cases"][case_id]["evaluation_mode"] = "attested"
        else:
            state["schema_version"] = True
        raw = json.dumps(state, sort_keys=True, separators=(",", ":"))
        digest = hashlib.sha256(raw.encode()).hexdigest()
        db.execute("UPDATE ledger SET state = ?, sha256 = ?", (raw, digest))
        db.execute(
            "UPDATE history SET state_sha256 = ? WHERE revision = ?", (digest, state["revision"])
        )
    for action in (lambda: initialize(store), lambda: store.dispatch("inventory", {})):
        with pytest.raises(AssessmentError):
            action()


def test_corrupt_audit_history_is_rejected(tmp_path):
    store = AssessmentStore(tmp_path)
    initialize(store)
    import_operations(store)
    with closing(sqlite3.connect(tmp_path / "assessment" / "coverage.sqlite3")) as db, db:
        db.execute("UPDATE history SET details = '{' WHERE revision = 1")
    with pytest.raises(AssessmentError):
        initialize(store)
    with pytest.raises(AssessmentError):
        store.dispatch("report", {})


def test_encoded_query_parameter_names_are_preserved_exactly(tmp_path):
    store = AssessmentStore(tmp_path)
    initialize(store)
    import_operations(
        store,
        [
            {"url": "https://api.example.test/items?%20token%20=first-secret", "method": "GET"},
            {"path": "/items", "method": "GET", "parameters": [{"name": " token ", "in": "query"}]},
            {"url": "https://api.example.test/items?token=second-secret", "method": "GET"},
        ],
    )
    operations = store.dispatch("inventory", {})["operations"]
    assert len(operations) == 2
    spaced = next(op for op in operations if op["url"].endswith("?%20token%20"))
    assert spaced["parameters"][0]["name"] == " token "
    case = next(
        case
        for case in store.dispatch("report", {})["cases"]
        if case["operation_id"] == spaced["operation_id"] and case["control_id"] == "http.nosniff"
    )
    write_capture(tmp_path, url="https://api.example.test/items?%20token%20=capture-secret")
    assert check_headers(store, case)["case"]["status"] == "pass"


def test_multiline_authored_notes_and_optional_null_metadata_are_supported(tmp_path):
    store = AssessmentStore(tmp_path)
    initialize(store, expected_revision=None)
    source = {
        "id": "notes",
        "kind": "manual",
        "status": "ok",
        "observed_at": None,
        "detail": "Synthetic input\nSecond line",
    }
    import_operations(store, source=source, expected_revision=None)
    (tmp_path / "evidence.txt").write_text("Synthetic evidence only")
    rationale = "Synthetic reviewer rationale:\n\tSecond line"
    saved = record(store, case_for(store, "http.nosniff"), rationale=rationale)
    assert saved["case"]["rationale"] == rationale
    assert (
        AssessmentStore(tmp_path).dispatch("report", {})["sources"][0]["detail"] == source["detail"]
    )
    before = store.dispatch("report", {})
    for detail in (0, False, [], {}):
        with pytest.raises(AssessmentError):
            import_operations(store, source=source | {"detail": detail})
    assert store.dispatch("report", {}) == before


def test_cross_process_imports_and_case_history_updates_are_serialized(tmp_path):
    store = AssessmentStore(tmp_path)
    initialize(store)
    import_operations(store)
    (tmp_path / "evidence.txt").write_text("Shared synthetic concurrency evidence")
    case_id = case_for(store, "http.nosniff")["case_id"]
    context = multiprocessing.get_context("spawn")
    barrier = context.Barrier(4)
    results = context.Queue()
    processes = [
        context.Process(
            target=concurrent_update, args=(str(tmp_path), index, case_id, barrier, results)
        )
        for index in range(4)
    ]
    try:
        for process in processes:
            process.start()
        updates = [results.get(timeout=120) for _ in processes]
        for process in processes:
            process.join(timeout=60)
            assert process.exitcode == 0
        assert all("error" not in result for result in updates), updates
        revisions = [revision for result in updates for revision in result["revisions"]]
        assert sorted(revisions) == list(range(3, 11))
    finally:
        for process in processes:
            if process.is_alive():
                process.terminate()
                process.join(timeout=5)
        results.close()
        results.join_thread()
    report = AssessmentStore(tmp_path).dispatch("report", {"limit": 1000})
    assert report["revision"] == 10
    assert report["totals"]["operations"] == 25
    assert report["totals"]["cases"] == 100
    case = next(case for case in report["cases"] if case["case_id"] == case_id)
    assert len(case["history"]) == 4
    assert {entry["rationale"] for entry in case["history"]} == {
        f"Synthetic concurrent reviewer {index}" for index in range(4)
    }
    assert len(report["history"]) == 10
