"""Exercise offline ASVS review bookkeeping using only synthetic review metadata."""

from __future__ import annotations

import builtins
import hashlib
import inspect
import io
import json
import os
import socket
import subprocess
from collections.abc import Callable
from copy import deepcopy
from pathlib import Path
from typing import Any, NoReturn, get_type_hints

import pytest

from buggy.sandbox_kernel import asvs_catalog
from buggy.sandbox_kernel.asvs_review import (
    ASVSReviewError,
    create_plan,
    record_result,
    report_plan,
    validate_plans,
)

ASSET = "https://synthetic.example.test"
OTHER_ASSET = "https://other.example.test"
REQUIREMENT = "v5.0.0-1.1.1"
STAMP = "2025-01-02T03:04:05Z"
SECRET = "synthetic-private-marker-do-not-echo"
EVIDENCE = {"path": "reviews/synthetic.txt", "sha256": "a" * 64, "size_bytes": 12}
RECORD_KEYS = {"status", "rationale", "method", "evidence", "history"}
PLAN_KEYS = {
    "plan_id",
    "asset",
    "level",
    "catalog_version",
    "catalog_sha256",
    "prerequisites",
    "records",
}


@pytest.fixture(autouse=True)
def forbid_network_and_processes(monkeypatch: pytest.MonkeyPatch) -> None:
    def forbidden(*args: Any, **kwargs: Any) -> NoReturn:
        raise AssertionError("Review bookkeeping must not use network or process operations")

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


def first_id(plan: dict[str, Any]) -> str:
    return next(iter(plan["records"]))


def record(plan: dict[str, Any], **overrides: Any) -> dict[str, Any]:
    arguments = {
        "requirement_id": first_id(plan),
        "status": "pass",
        "rationale": "Reviewer attests to synthetic review metadata.",
        "method": "manual_review",
        "evidence": [deepcopy(EVIDENCE)],
        "revision": 1,
        "recorded_at": STAMP,
        "available_roles": [],
        "source_available": False,
    } | overrides
    return record_result(plan, **arguments)


def report(plan: dict[str, Any], **overrides: Any) -> dict[str, Any]:
    arguments = {
        "available_roles": [],
        "source_available": False,
        "evidence_checks": {EVIDENCE["path"]: deepcopy(EVIDENCE)},
    } | overrides
    return report_plan(plan, **arguments)


def test_public_contract_has_explicit_annotations() -> None:
    assert issubclass(ASVSReviewError, ValueError)
    for function in (create_plan, record_result, validate_plans, report_plan):
        signature = inspect.signature(function)
        hints = get_type_hints(function)
        assert set(hints) == set(signature.parameters) | {"return"}
    assert inspect.signature(create_plan).parameters["level"].default == 2
    assert inspect.signature(create_plan).parameters["prerequisites"].default is None
    for name in ("revision", "recorded_at", "available_roles", "source_available"):
        assert (
            inspect.signature(record_result).parameters[name].kind is inspect.Parameter.KEYWORD_ONLY
        )


@pytest.mark.parametrize(("level", "count"), [(1, 70), (2, 253), (3, 345)])
def test_plan_contains_the_complete_catalog_in_official_order(level: int, count: int) -> None:
    plan = create_plan(ASSET, level)
    selected = asvs_catalog.requirements(level)
    assert set(plan) == PLAN_KEYS
    assert plan["asset"] == ASSET
    assert plan["level"] == level
    assert plan["catalog_version"] == asvs_catalog.CATALOG_VERSION == "5.0.0"
    assert plan["catalog_sha256"] == asvs_catalog.CATALOG_SHA256
    assert plan["prerequisites"] == {}
    assert list(plan["records"]) == [item["requirement_id"] for item in selected]
    assert len(plan["records"]) == count
    assert all(key.startswith("v5.0.0-") for key in plan["records"])
    for value in plan["records"].values():
        assert value == {
            "status": "untested",
            "rationale": "",
            "method": None,
            "evidence": [],
            "history": [],
        }
    first, second = list(plan["records"].values())[:2]
    assert first is not second
    assert first["evidence"] is not second["evidence"]
    assert first["history"] is not second["history"]


def test_ids_cover_canonical_configuration_without_mutating_inputs() -> None:
    prerequisites = {REQUIREMENT: {"roles": ["reader", "admin", "reader"], "source_required": True}}
    original = deepcopy(prerequisites)
    plan = create_plan(ASSET, prerequisites=prerequisites)
    canonical = {REQUIREMENT: {"roles": ["admin", "reader"], "source_required": True}}
    assert prerequisites == original
    assert plan["prerequisites"] == canonical
    assert plan == create_plan(ASSET, 2, canonical)
    configuration = {key: value for key, value in plan.items() if key not in {"records", "plan_id"}}
    digest = hashlib.sha256(
        json.dumps(configuration, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    assert plan["plan_id"] == "asvs_plan_" + digest
    plans = [
        plan,
        create_plan(OTHER_ASSET, 2, canonical),
        create_plan(ASSET, 3, canonical),
        create_plan(ASSET),
        create_plan(ASSET, prerequisites={REQUIREMENT: {"roles": [], "source_required": False}}),
        create_plan(
            ASSET, prerequisites={REQUIREMENT: {"roles": ["admin"], "source_required": True}}
        ),
    ]
    assert len({item["plan_id"] for item in plans}) == len(plans)
    validate_plans({item["plan_id"]: item for item in plans}, revision=0)
    prerequisites[REQUIREMENT]["roles"].append("new-role")
    assert plan["prerequisites"] == canonical
    assert create_plan(ASSET) == create_plan(ASSET, prerequisites={})


@pytest.mark.parametrize(
    "asset", [None, True, 1, "", " ", "a" * 4097, "synthetic\nasset", "\ud800"]
)
def test_invalid_assets_are_domain_errors(asset: Any) -> None:
    with pytest.raises(ASVSReviewError):
        create_plan(asset)


@pytest.mark.parametrize("level", [None, True, 0, 4, 1.0, "2", []])
def test_levels_are_strict_integers(level: Any) -> None:
    with pytest.raises(ASVSReviewError):
        create_plan(ASSET, level)


@pytest.mark.parametrize(
    "prerequisites",
    [
        [],
        {"v5.0.0-99.99.99": {"roles": [], "source_required": False}},
        {"1.1.1": {"roles": [], "source_required": False}},
        {REQUIREMENT: None},
        {REQUIREMENT: {}},
        {REQUIREMENT: {"roles": [], "source_required": False, "status": "not_applicable"}},
        {REQUIREMENT: {"roles": "admin", "source_required": False}},
        {REQUIREMENT: {"roles": ("admin",), "source_required": False}},
        {REQUIREMENT: {"roles": [True], "source_required": False}},
        {REQUIREMENT: {"roles": ["   "], "source_required": False}},
        {REQUIREMENT: {"roles": ["\x00" + SECRET], "source_required": False}},
        {REQUIREMENT: {"roles": ["x" * 129], "source_required": False}},
        {REQUIREMENT: {"roles": [], "source_required": 1}},
    ],
)
def test_prerequisites_have_strict_selected_shapes(prerequisites: Any) -> None:
    before = deepcopy(prerequisites)
    with pytest.raises(ASVSReviewError) as error:
        create_plan(ASSET, prerequisites=prerequisites)
    assert SECRET not in str(error.value)
    assert prerequisites == before


def test_prerequisites_cannot_select_higher_level_requirements() -> None:
    level_three = next(item for item in asvs_catalog.requirements(3) if item["level"] == 3)
    with pytest.raises(ASVSReviewError):
        create_plan(
            ASSET, 1, {level_three["requirement_id"]: {"roles": [], "source_required": False}}
        )


@pytest.mark.parametrize(
    ("status", "method", "with_evidence"),
    [
        ("pass", "code_review", True),
        ("fail", "config_review", True),
        ("not_applicable", "applicability_review", True),
        ("blocked", "manual_review", False),
        ("inconclusive", "supplied_capture", False),
    ],
)
def test_record_changes_only_one_case_and_returns_detached_attested_history(
    status: str, method: str, with_evidence: bool
) -> None:
    plan = create_plan(ASSET, 1)
    before = deepcopy(plan)
    untouched_id = list(plan["records"])[1]
    untouched = plan["records"][untouched_id]
    evidence = [deepcopy(EVIDENCE)] if with_evidence else []
    roles = ["reader", "admin", "reader"]
    result = record(plan, status=status, method=method, evidence=evidence, available_roles=roles)
    stored = plan["records"][first_id(plan)]
    assert set(stored) == RECORD_KEYS
    assert result == stored and result is not stored
    assert result["status"] == status
    assert result["method"] == method
    event = result["history"][0]
    assert event == {
        "status": status,
        "rationale": "Reviewer attests to synthetic review metadata.",
        "method": method,
        "evidence": evidence,
        "revision": 1,
        "recorded_at": STAMP,
        "evaluation_mode": "attested",
        "available_roles": ["admin", "reader"],
        "source_available": False,
    }
    assert plan["records"][untouched_id] is untouched
    assert {key: value for key, value in plan.items() if key != "records"} == {
        key: value for key, value in before.items() if key != "records"
    }
    assert roles == ["reader", "admin", "reader"]
    event["status"] = "inconclusive"
    if evidence:
        evidence[0]["sha256"] = "b" * 64
        result["evidence"][0]["path"] = "changed.txt"
        assert stored["evidence"] == [EVIDENCE]
        assert stored["history"][0]["evidence"] == [EVIDENCE]
        assert stored["evidence"] is not stored["history"][0]["evidence"]
    assert stored["history"][0]["status"] == status
    validate_plans({plan["plan_id"]: plan}, revision=1)


@pytest.mark.parametrize("status", ["pass", "fail", "not_applicable"])
def test_supported_dispositions_always_require_evidence(status: str) -> None:
    plan = create_plan(ASSET, 1)
    before = deepcopy(plan)
    with pytest.raises(ASVSReviewError):
        record(plan, status=status, method="applicability_review", evidence=[])
    assert plan == before


def test_not_applicable_requires_an_explicit_applicability_review() -> None:
    plan = create_plan(ASSET, 1)
    with pytest.raises(ASVSReviewError):
        record(plan, status="not_applicable", method="manual_review")


@pytest.mark.parametrize(
    "overrides",
    [
        {"requirement_id": "v5.0.0-99.99.99"},
        {"requirement_id": []},
        {"status": "untested"},
        {"status": SECRET},
        {"status": []},
        {"rationale": ""},
        {"rationale": "\t\n "},
        {"rationale": "a" * 8193},
        {"rationale": "\x00" + SECRET},
        {"rationale": True},
        {"method": "independently_verified"},
        {"method": None},
        {"method": []},
        {"evidence": None},
        {"evidence": (EVIDENCE,)},
        {"evidence": [EVIDENCE, EVIDENCE]},
        {"evidence": [EVIDENCE | {"body": SECRET}]},
        {"evidence": [{"path": "synthetic.txt", "size_bytes": 12}]},
        {"evidence": [EVIDENCE | {"sha256": "A" * 64}]},
        {"evidence": [EVIDENCE | {"sha256": SECRET}]},
        {"evidence": [EVIDENCE | {"sha256": 1}]},
        {"evidence": [EVIDENCE | {"size_bytes": True}]},
        {"evidence": [EVIDENCE | {"size_bytes": -1}]},
        {"evidence": [EVIDENCE | {"size_bytes": 12.0}]},
        {"revision": True},
        {"revision": 0},
        {"revision": -1},
        {"revision": 1.0},
        {"recorded_at": "2025-01-02T03:04:05"},
        {"recorded_at": "2025-02-30T03:04:05Z"},
        {"recorded_at": "2025-01-02T03:04:05+00:60"},
        {"recorded_at": "2025-01-02"},
        {"recorded_at": SECRET},
        {"recorded_at": None},
        {"available_roles": "admin"},
        {"available_roles": ["\n" + SECRET]},
        {"available_roles": [None]},
        {"source_available": 1},
    ],
)
def test_rejected_result_is_atomic_and_does_not_echo_input(overrides: dict[str, Any]) -> None:
    plan = create_plan(ASSET, 1)
    before = deepcopy(plan)
    arguments = deepcopy(overrides)
    with pytest.raises(ASVSReviewError) as error:
        record(plan, **overrides)
    assert plan == before
    assert overrides == arguments
    assert SECRET not in str(error.value)
    assert error.value.__cause__ is None


@pytest.mark.parametrize(
    "path",
    [
        "",
        ".",
        "..",
        "../synthetic.txt",
        "a/../b",
        "/synthetic.txt",
        "a\\b",
        "C:x",
        "C:/x",
        "a:b",
        "a//b",
        "a/./b",
        "a/",
        "\x00" + SECRET,
    ],
)
def test_evidence_paths_must_be_canonical_workspace_relative_paths(path: str) -> None:
    plan = create_plan(ASSET, 1)
    with pytest.raises(ASVSReviewError):
        record(plan, evidence=[EVIDENCE | {"path": path}])


def test_zero_size_metadata_is_valid_without_reading_or_interpreting_the_artifact() -> None:
    plan = create_plan(ASSET, 1)
    empty_metadata = EVIDENCE | {"sha256": hashlib.sha256(b"").hexdigest(), "size_bytes": 0}
    result = record(plan, evidence=[empty_metadata])
    assert result["evidence"] == [empty_metadata]


@pytest.mark.parametrize("status", ["pass", "fail", "not_applicable"])
@pytest.mark.parametrize(("roles", "source"), [([], False), (["admin"], False), ([], True)])
def test_missing_declared_access_rejects_supported_outcomes_and_keeps_views_blocked(
    status: str, roles: list[str], source: bool
) -> None:
    plan = create_plan(
        ASSET, prerequisites={REQUIREMENT: {"roles": ["admin"], "source_required": True}}
    )
    before = deepcopy(plan)
    with pytest.raises(ASVSReviewError):
        record(
            plan,
            requirement_id=REQUIREMENT,
            status=status,
            method="applicability_review",
            available_roles=roles,
            source_available=source,
        )
    assert plan == before
    view = next(
        case
        for case in report(plan, available_roles=roles, source_available=source)["cases"]
        if case["requirement_id"] == REQUIREMENT
    )
    assert view["recorded_status"] == "untested"
    assert view["status"] == "blocked"
    assert view["applicability"] == "unreviewed"
    assert view["prerequisites_available"] is False
    assert view["trusted"] is False


@pytest.mark.parametrize("status", ["blocked", "inconclusive"])
def test_pending_outcomes_without_evidence_are_never_trusted(status: str) -> None:
    plan = create_plan(ASSET, 1)
    record(plan, status=status, evidence=[])
    view = report(plan)["cases"][0]
    assert view["status"] == status
    assert view["applicability"] == "unreviewed"
    assert view["trusted"] is False
    assert view["evidence_integrity"] == "not_cited"
    blocked_plan = create_plan(
        ASSET, prerequisites={REQUIREMENT: {"roles": ["admin"], "source_required": True}}
    )
    record(blocked_plan, requirement_id=REQUIREMENT, status=status, evidence=[])
    validate_plans({blocked_plan["plan_id"]: blocked_plan}, revision=1)


def test_history_is_chronological_and_previous_entries_are_detached() -> None:
    plan = create_plan(ASSET, 1)
    earlier = record(plan, status="fail", revision=3)
    stored_earlier = plan["records"][first_id(plan)]
    before = deepcopy(stored_earlier)
    second_evidence = EVIDENCE | {"path": "reviews/later.txt", "sha256": "b" * 64}
    latest = record(
        plan, revision=7, recorded_at="2025-01-02T04:04:06+01:00", evidence=[second_evidence]
    )
    assert stored_earlier == before == earlier
    assert [entry["revision"] for entry in latest["history"]] == [3, 7]
    assert [entry["status"] for entry in latest["history"]] == ["fail", "pass"]
    for overrides in ({"revision": 7}, {"revision": 6}, {"revision": 8, "recorded_at": STAMP}):
        snapshot = deepcopy(plan)
        with pytest.raises(ASVSReviewError):
            record(plan, **overrides)
        assert plan == snapshot
    other_id = list(plan["records"])[1]
    with pytest.raises(ASVSReviewError):
        record(plan, requirement_id=other_id, revision=6, recorded_at="2025-01-03T00:00:00Z")
    validate_plans({plan["plan_id"]: plan}, revision=10)
    with pytest.raises(ASVSReviewError):
        validate_plans({plan["plan_id"]: plan}, revision=6)


def test_validation_accepts_legacy_empty_maps_but_not_invalid_revision_types() -> None:
    assert validate_plans({}, revision=0) is None
    assert validate_plans({}, revision=12) is None
    for revision in (True, -1, 1.0, "1", None):
        with pytest.raises(ASVSReviewError):
            validate_plans({}, revision=revision)
    for plans in ([], None, "invalid"):
        with pytest.raises(ASVSReviewError):
            validate_plans(plans, revision=1)


@pytest.mark.parametrize(
    "mutate",
    [
        lambda p: p["records"].pop(first_id(p)),
        lambda p: p["records"].update({"v5.0.0-99.99.99": deepcopy(p["records"][first_id(p)])}),
        lambda p: p.update(asset=OTHER_ASSET),
        lambda p: p.update(level=2),
        lambda p: p.update(level=True),
        lambda p: p.update(catalog_version="4.0.3"),
        lambda p: p.update(catalog_sha256="b" * 64),
        lambda p: p.update(plan_id="asvs_plan_forged"),
        lambda p: p.update(prerequisites={first_id(p): {"roles": [], "source_required": False}}),
        lambda p: p.update(extra=SECRET),
        lambda p: p["records"][first_id(p)].update(status="not_applicable"),
        lambda p: p["records"][first_id(p)].update(rationale="not an initial record"),
        lambda p: p["records"][first_id(p)].update(method="manual_review"),
        lambda p: p["records"][first_id(p)].update(evidence=[EVIDENCE]),
        lambda p: p["records"][first_id(p)].update(history={}),
        lambda p: p["records"][first_id(p)].pop("method"),
        lambda p: p["records"][first_id(p)].update(extra=SECRET),
    ],
)
def test_initial_corruption_is_rejected_without_silent_reset(
    mutate: Callable[[dict[str, Any]], Any],
) -> None:
    plan = create_plan(ASSET, 1)
    plan_id = plan["plan_id"]
    mutate(plan)
    before = deepcopy(plan)
    for operation in (
        lambda: validate_plans({plan_id: plan}, revision=0),
        lambda: record(plan),
        lambda: report(plan),
    ):
        with pytest.raises(ASVSReviewError):
            operation()
        assert plan == before


@pytest.mark.parametrize(
    "mutate",
    [
        lambda r: r.update(status="fail"),
        lambda r: r.update(evidence=[EVIDENCE | {"size_bytes": True}]),
        lambda r: r.update(history=[]),
        lambda r: r["history"][0].update(status="untested"),
        lambda r: r["history"][0].update(evidence=[]),
        lambda r: r["history"][0].update(evidence=[EVIDENCE | {"body": SECRET}]),
        lambda r: r["history"][0].update(evaluation_mode="deterministic"),
        lambda r: r["history"][0].update(revision=True),
        lambda r: r["history"][0].update(revision=0),
        lambda r: r["history"][0].update(recorded_at="2025-01-02"),
        lambda r: r["history"][0].update(available_roles=["reader", "admin", "reader"]),
        lambda r: r["history"][0].update(source_available=1),
        lambda r: r["history"].append(deepcopy(r["history"][0])),
        lambda r: r["history"][0].pop("rationale"),
    ],
)
def test_all_current_and_historical_outcomes_are_validated(
    mutate: Callable[[dict[str, Any]], Any],
) -> None:
    plan = create_plan(ASSET, 1)
    record(plan)
    mutate(plan["records"][first_id(plan)])
    before = deepcopy(plan)
    with pytest.raises(ASVSReviewError):
        validate_plans({plan["plan_id"]: plan}, revision=10)
    assert plan == before


def test_validation_rejects_noncanonical_prerequisites_and_missing_historical_access() -> None:
    plan = create_plan(
        ASSET, prerequisites={REQUIREMENT: {"roles": ["admin", "reader"], "source_required": True}}
    )
    record(
        plan, requirement_id=REQUIREMENT, available_roles=["admin", "reader"], source_available=True
    )
    for field, value in (("available_roles", []), ("source_available", False)):
        corrupt = deepcopy(plan)
        corrupt["records"][REQUIREMENT]["history"][0][field] = value
        with pytest.raises(ASVSReviewError):
            validate_plans({corrupt["plan_id"]: corrupt}, revision=1)
    plan["prerequisites"][REQUIREMENT]["roles"] = ["reader", "admin"]
    with pytest.raises(ASVSReviewError):
        validate_plans({plan["plan_id"]: plan}, revision=1)


def test_global_history_revisions_and_time_are_consistent_across_plans() -> None:
    plan = create_plan(ASSET, 1)
    other = create_plan(OTHER_ASSET, 1)
    record(plan, revision=3)
    record(other, revision=3)
    with pytest.raises(ASVSReviewError):
        validate_plans({item["plan_id"]: item for item in (plan, other)}, revision=3)
    other = create_plan(OTHER_ASSET, 1)
    record(other, revision=4, recorded_at="2025-01-01T00:00:00Z")
    with pytest.raises(ASVSReviewError):
        validate_plans({item["plan_id"]: item for item in (plan, other)}, revision=4)
    with pytest.raises(ASVSReviewError):
        validate_plans({"wrong-plan-id": plan}, revision=4)


def test_reports_include_full_catalog_views_and_separate_attested_plan_metadata() -> None:
    plan = create_plan(ASSET)
    before = deepcopy(plan)
    result = report(plan, evidence_checks={})
    assert len(result["cases"]) == result["total"] == 253
    assert result["plan"] == {key: value for key, value in plan.items() if key != "records"}
    assert result["status_counts"] == {
        "untested": 253,
        "pass": 0,
        "fail": 0,
        "not_applicable": 0,
        "blocked": 0,
        "inconclusive": 0,
    }
    assert result["coverage"] == {
        "total": 253,
        "applicable": 253,
        "assessed": 0,
        "remaining": 253,
        "not_applicable": 0,
        "percent": 0.0,
    }
    assert result["complete"] is False
    assert result["evaluation_mode"] == "attested"
    assert result["independently_verified"] is False
    assert result["baseline_coverage_updated"] is False
    assert "manual catalog review" in result["baseline_description"].lower()
    assert "not independent verification" in result["baseline_description"].lower()
    assert "certification" in result["baseline_description"].lower()
    release = asvs_catalog.catalog()
    for field in ("source_commit", "source_url", "attribution", "license", "license_url", "notice"):
        assert result["catalog"][field] == release[field]
    selected = asvs_catalog.requirements()
    assert [case["requirement_id"] for case in result["cases"]] == [
        item["requirement_id"] for item in selected
    ]
    for case, requirement in zip(result["cases"], selected, strict=True):
        assert case["control_id"] == "asvs:" + requirement["requirement_id"]
        assert case["case_id"] == plan["plan_id"] + ":" + requirement["requirement_id"]
        assert {key: case[key] for key in requirement} == requirement
        assert case["url"] == ASSET
        assert case["role"] == "application"
        assert case["method"] == "REVIEW"
        assert case["verification_method"] is None
        assert case["recorded_status"] == case["status"] == "untested"
        assert case["applicability"] == "unreviewed"
        assert case["trusted"] is False
        assert case["evidence_integrity"] == "not_cited"
    result["plan"]["prerequisites"][REQUIREMENT] = {"roles": [], "source_required": False}
    result["cases"][0]["history"].append({})
    assert plan == before
    reordered = deepcopy(plan)
    reordered["records"] = dict(reversed(list(reordered["records"].items())))
    assert [case["case_id"] for case in report(reordered)["cases"]] == [
        case["case_id"] for case in result["cases"]
    ]


@pytest.mark.parametrize("status", ["pass", "fail", "not_applicable"])
@pytest.mark.parametrize(
    "checks",
    [
        {},
        {EVIDENCE["path"]: None},
        {EVIDENCE["path"]: EVIDENCE | {"sha256": "b" * 64}},
        {EVIDENCE["path"]: EVIDENCE | {"size_bytes": 13}},
        {EVIDENCE["path"]: EVIDENCE | {"path": "other.txt"}},
        {EVIDENCE["path"]: EVIDENCE | {"size_bytes": True}},
        {EVIDENCE["path"]: {"sha256": EVIDENCE["sha256"]}},
    ],
)
def test_unchecked_or_changed_current_evidence_invalidates_including_exclusions(
    status: str, checks: dict[str, Any]
) -> None:
    plan = create_plan(ASSET, 1)
    record(plan, status=status, method="applicability_review")
    before = deepcopy(plan)
    inputs = deepcopy(checks)
    result = report(plan, evidence_checks=checks)
    case = result["cases"][0]
    assert case["recorded_status"] == status
    assert case["status"] == "inconclusive"
    assert case["applicability"] == "unreviewed"
    assert case["evidence_integrity"] == "untrusted"
    assert case["evidence_errors"]
    assert case["trusted"] is False
    assert case["evaluation_mode"] == "attested"
    assert case["verification_method"] == "applicability_review"
    assert result["coverage"] == {
        "total": 70,
        "applicable": 70,
        "assessed": 0,
        "remaining": 70,
        "not_applicable": 0,
        "percent": 0.0,
    }
    assert result["complete"] is False
    assert plan == before and checks == inputs


def test_only_current_evidence_is_required_and_any_bad_reference_invalidates() -> None:
    plan = create_plan(ASSET, 1)
    record(plan, status="fail")
    current = EVIDENCE | {"path": "reviews/current.txt", "sha256": "c" * 64}
    record(plan, evidence=[current], revision=2)
    result = report(plan, evidence_checks={current["path"]: current})
    assert result["cases"][0]["status"] == "pass"
    assert result["cases"][0]["trusted"] is True
    assert result["cases"][0]["evidence_integrity"] == "matched"
    assert len(result["cases"][0]["history"]) == 2
    record(plan, evidence=[EVIDENCE, current], revision=3)
    assert report(plan)["cases"][0]["status"] == "inconclusive"


def test_missing_access_overrides_evidence_failure_and_reinstates_na_denominator() -> None:
    plan = create_plan(
        ASSET, prerequisites={REQUIREMENT: {"roles": ["admin"], "source_required": True}}
    )
    record(
        plan,
        requirement_id=REQUIREMENT,
        status="not_applicable",
        method="applicability_review",
        available_roles=["admin"],
        source_available=True,
    )
    result = report(plan, evidence_checks={})
    case = next(case for case in result["cases"] if case["requirement_id"] == REQUIREMENT)
    assert case["status"] == "blocked"
    assert case["recorded_status"] == "not_applicable"
    assert case["applicability"] == "unreviewed"
    assert not case["trusted"] and not case["prerequisites_available"]
    assert case["evidence_integrity"] == "untrusted"
    assert "prerequisites" in case["reason"].lower() and "evidence" in case["reason"].lower()
    assert result["coverage"]["applicable"] == 253
    restored = report(plan, available_roles=["admin"], source_available=True)
    assert restored["coverage"]["applicable"] == 252
    assert restored["status_counts"]["not_applicable"] == 1


def test_coverage_denominators_do_not_depend_on_parent_case_pagination() -> None:
    plan = create_plan(ASSET, 1)
    ids = list(plan["records"])
    record(plan, requirement_id=ids[0])
    record(
        plan,
        requirement_id=ids[1],
        status="not_applicable",
        method="applicability_review",
        revision=2,
    )
    record(plan, requirement_id=ids[-1], status="fail", revision=3)
    result = report(plan)
    assert result["coverage"] == {
        "total": 70,
        "applicable": 69,
        "assessed": 2,
        "remaining": 67,
        "not_applicable": 1,
        "percent": 2.90,
    }
    assert result["complete"] is False
    for offset in range(0, 70, 7):
        page = result | {"cases": result["cases"][offset : offset + 7]}
        assert len(page["cases"]) == 7
        assert page["total"] == 70
        assert page["coverage"]["remaining"] == 67
    assert (
        report(create_plan(OTHER_ASSET, 1))["cases"][0]["case_id"] != result["cases"][0]["case_id"]
    )


@pytest.mark.parametrize("status", ["fail", "not_applicable"])
def test_complete_means_supported_dispositions_not_compliance_or_security(status: str) -> None:
    plan = create_plan(ASSET, 1)
    for revision, requirement_id in enumerate(plan["records"], 1):
        record(
            plan,
            requirement_id=requirement_id,
            status=status,
            method="applicability_review",
            revision=revision,
        )
    result = report(plan)
    assert result["complete"] is True
    assert result["status_counts"][status] == 70
    assert result["coverage"]["remaining"] == 0
    assert result["coverage"]["applicable"] == (70 if status == "fail" else 0)
    assert result["coverage"]["assessed"] == (70 if status == "fail" else 0)
    assert result["coverage"]["percent"] == (100.0 if status == "fail" else None)
    assert all(case["trusted"] for case in result["cases"])
    assert result["evaluation_mode"] == "attested"
    assert result["independently_verified"] is False
    assert "failures may remain" in result["notice"].lower()
    assert "not compliance" in result["notice"].lower()
    assert "certification" in result["notice"].lower()
    assert not ({"compliance", "compliant", "no_findings", "secure", "is_secure"} & set(result))
    assert report(plan, evidence_checks={})["complete"] is False


@pytest.mark.parametrize(
    "overrides",
    [
        {"available_roles": "admin"},
        {"source_available": 1},
        {"evidence_checks": []},
        {"evidence_checks": {"synthetic.txt": "error"}},
        {"evidence_checks": {1: None}},
    ],
)
def test_report_input_shapes_are_strict(overrides: dict[str, Any]) -> None:
    plan = create_plan(ASSET, 1)
    before = deepcopy(plan)
    with pytest.raises(ASVSReviewError):
        report(plan, **overrides)
    assert plan == before


def test_engine_reads_only_the_bundled_catalog_not_evidence_or_client_files(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bundle = Path(str(asvs_catalog.__file__)).with_name(
        "OWASP_Application_Security_Verification_Standard_5.0.0_en.json"
    )
    real_open = builtins.open

    def guarded_open(file: Any, *args: Any, **kwargs: Any) -> Any:
        if not isinstance(file, (str, os.PathLike)) or Path(file) != bundle:
            raise AssertionError("Only the pinned catalog may be read")
        if (args[0] if args else kwargs.get("mode", "r")) != "rb":
            raise AssertionError("The catalog must only be read")
        return real_open(file, *args, **kwargs)

    with monkeypatch.context() as isolated:
        isolated.setattr(builtins, "open", guarded_open)
        isolated.setattr(io, "open", guarded_open)
        plan = create_plan(ASSET, 1)
        record(plan)
        validate_plans({plan["plan_id"]: plan}, revision=1)
        assert report(plan)["cases"][0]["status"] == "pass"
