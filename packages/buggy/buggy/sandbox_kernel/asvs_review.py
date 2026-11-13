"""Track explicitly attested application-level ASVS reviews without performing verification."""

from __future__ import annotations

import hashlib
import json
import re
from copy import deepcopy
from datetime import datetime
from typing import Any

from . import asvs_catalog

__all__ = ["ASVSReviewError", "create_plan", "record_result", "report_plan", "validate_plans"]

_METADATA = ("plan_id", "asset", "level", "catalog_version", "catalog_sha256", "prerequisites")
_OUTCOME = ("status", "rationale", "method", "evidence")
_ACCESS = ("available_roles", "source_available")
_EVENT = _OUTCOME + _ACCESS + ("revision", "recorded_at", "evaluation_mode")
_DISPOSITIONS = ("pass", "fail", "not_applicable")
_STATUSES = ("untested", *_DISPOSITIONS, "blocked", "inconclusive")
_METHODS = (
    "code_review",
    "config_review",
    "supplied_capture",
    "manual_review",
    "applicability_review",
)
_EVIDENCE = ("path", "sha256", "size_bytes")
_ISO_TIME = r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-](?:[01]\d|2[0-3]):[0-5]\d)"


class ASVSReviewError(ValueError):
    """Invalid review input or corrupt persisted review state."""


def _need(condition: bool, message: str = "Invalid ASVS review input or corrupt state") -> None:
    if not condition:
        raise ASVSReviewError(message)


def _shape(value: Any, fields: tuple[str, ...]) -> None:
    _need(type(value) is dict and set(value) == set(fields))


def _text(value: Any, maximum: int, multiline: bool = False) -> None:
    _need(type(value) is str and bool(value.strip()) and len(value) <= maximum)
    _need(not re.search(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f\ud800-\udfff]", value))
    _need(multiline or not re.search(r"[\t\r\n]", value))


def _roles(value: Any) -> list[str]:
    _need(type(value) is list)
    for role in value:
        _text(role, 128)
    return sorted({role.strip() for role in value})


def _access(roles: Any, source: Any) -> dict[str, Any]:
    _need(type(source) is bool)
    return {"available_roles": _roles(roles), "source_available": source}


def _missing(plan: dict[str, Any], requirement_id: str, access: dict[str, Any]) -> bool:
    prerequisite = plan["prerequisites"].get(requirement_id, dict(roles=[], source_required=False))
    return not set(prerequisite["roles"]).issubset(access["available_roles"]) or (
        prerequisite["source_required"] and not access["source_available"]
    )


def _timestamp(value: Any) -> datetime:
    _text(value, 80)
    _need(re.fullmatch(_ISO_TIME, value) is not None)
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        raise ASVSReviewError("Invalid review timestamp") from None


def _evidence(value: Any) -> None:
    _shape(value, _EVIDENCE)
    path = value["path"]
    _text(path, 4096)
    _need(
        path == path.strip()
        and "\\" not in path
        and ":" not in path
        and all(part not in ("", ".", "..") for part in path.split("/"))
    )
    _need(
        type(value["sha256"]) is str and re.fullmatch(r"[0-9a-f]{64}", value["sha256"]) is not None
    )
    _need(type(value["size_bytes"]) is int and value["size_bytes"] >= 0)


def _outcome(value: dict[str, Any], initial: bool = False) -> None:
    status, rationale, method, evidence = (value[key] for key in _OUTCOME)
    _need(type(status) is str and status in (_STATUSES if initial else _STATUSES[1:]))
    _need(type(evidence) is list)
    for reference in evidence:
        _evidence(reference)
    _need(len({item["path"] for item in evidence}) == len(evidence))
    if status == "untested":
        _need(type(rationale) is str and rationale == "" and method is None and not evidence)
    else:
        _text(rationale, 8192, multiline=True)
        _need(type(method) is str and method in _METHODS)
        _need(status not in _DISPOSITIONS or bool(evidence))
        _need(status != "not_applicable" or method == "applicability_review")


def create_plan(
    asset: str, level: int = 2, prerequisites: dict[str, dict[str, Any]] | None = None
) -> dict[str, Any]:
    """Return a deterministic fully untested plan with canonical engagement role labels."""
    _text(asset, 4096)
    _need(asset == asset.strip() and type(level) is int and level in (1, 2, 3))
    try:
        selected = [item["requirement_id"] for item in asvs_catalog.requirements(level)]
    except asvs_catalog.ASVSCatalogError:
        raise ASVSReviewError("ASVS catalog is unavailable or invalid") from None
    prerequisites = {} if prerequisites is None else prerequisites
    _need(type(prerequisites) is dict)
    _need(all(type(key) is str and key in selected for key in prerequisites))
    canonical = {}
    for key in sorted(prerequisites):
        value = prerequisites[key]
        _shape(value, ("roles", "source_required"))
        _need(type(value["source_required"]) is bool)
        roles = _roles(value["roles"])
        canonical[key] = {"roles": roles, "source_required": value["source_required"]}
    configuration = {
        "asset": asset,
        "level": level,
        "catalog_version": asvs_catalog.CATALOG_VERSION,
        "catalog_sha256": asvs_catalog.CATALOG_SHA256,
        "prerequisites": canonical,
    }
    digest = hashlib.sha256(
        json.dumps(configuration, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    return {
        "plan_id": "asvs_plan_" + digest,
        **configuration,
        "records": {
            key: dict(status="untested", rationale="", method=None, evidence=[], history=[])
            for key in selected
        },
    }


def _ordered(events: list[tuple[int, datetime]]) -> list[tuple[int, datetime]]:
    ordered = sorted(events)
    _need(all(a[0] < b[0] and a[1] <= b[1] for a, b in zip(ordered, ordered[1:])))
    return ordered


def _plan(plan: Any) -> list[tuple[int, datetime]]:
    _shape(plan, _METADATA + ("records",))
    expected = create_plan(plan["asset"], plan["level"], plan["prerequisites"])
    _need(
        all(
            type(plan[key]) is type(expected[key]) and plan[key] == expected[key]
            for key in _METADATA
        )
    )
    _need(type(plan["records"]) is dict and set(plan["records"]) == set(expected["records"]))
    events = []
    for requirement_id, record in plan["records"].items():
        _shape(record, _OUTCOME + ("history",))
        _outcome(record, initial=True)
        history = record["history"]
        _need(type(history) is list)
        if not history:
            _need(record == expected["records"][requirement_id])
            continue
        previous = 0
        for event in history:
            _shape(event, _EVENT)
            _outcome(event)
            access = _access(event["available_roles"], event["source_available"])
            _need(access == {key: event[key] for key in _ACCESS})
            mode = event["evaluation_mode"]
            _need(type(mode) is str and mode == "attested")
            if event["status"] in _DISPOSITIONS:
                _need(not _missing(plan, requirement_id, access))
            revision = event["revision"]
            _need(type(revision) is int and revision > previous)
            events.append((revision, _timestamp(event["recorded_at"])))
            previous = revision
        _need(all(record[key] == history[-1][key] for key in _OUTCOME))
    return _ordered(events)


def validate_plans(plans: dict[str, dict[str, Any]], *, revision: int) -> None:
    """Reject corrupt plans, nonchronological global history, or revisions beyond the store."""
    _need(type(plans) is dict and type(revision) is int and revision >= 0)
    events = []
    for plan_id, plan in plans.items():
        events.extend(_plan(plan))
        _need(type(plan_id) is str and plan_id == plan["plan_id"])
    ordered = _ordered(events)
    _need(not ordered or ordered[-1][0] <= revision)


def record_result(
    plan: dict[str, Any],
    requirement_id: str,
    status: str,
    rationale: str,
    method: str,
    evidence: list[dict[str, Any]],
    *,
    revision: int,
    recorded_at: str,
    available_roles: list[str],
    source_available: bool,
) -> dict[str, Any]:
    """Replace one validated result and return a detached copy of its complete record."""
    _need(type(revision) is int and revision > 0)
    previous = _plan(plan)
    _need(type(requirement_id) is str and requirement_id in plan["records"])
    outcome = {"status": status, "rationale": rationale, "method": method, "evidence": evidence}
    _outcome(outcome)
    access, timestamp = _access(available_roles, source_available), _timestamp(recorded_at)
    _need(not previous or (previous[-1][0] < revision and previous[-1][1] <= timestamp))
    _need(
        status not in _DISPOSITIONS or not _missing(plan, requirement_id, access),
        "Declared review prerequisites are unavailable",
    )
    event = deepcopy(
        outcome
        | access
        | {"revision": revision, "recorded_at": recorded_at, "evaluation_mode": "attested"}
    )
    updated = deepcopy(outcome) | {
        "history": deepcopy(plan["records"][requirement_id]["history"]) + [event]
    }
    result = deepcopy(updated)
    plan["records"][requirement_id] = updated
    return result


def _matches(reference: dict[str, Any], actual: Any) -> bool:
    if type(actual) is not dict or actual.keys() != reference.keys():
        return False
    return all(
        type(actual[key]) is type(reference[key]) and actual[key] == reference[key]
        for key in reference
    )


def report_plan(
    plan: dict[str, Any],
    *,
    available_roles: list[str],
    source_available: bool,
    evidence_checks: dict[str, dict[str, Any] | None],
) -> dict[str, Any]:
    """Return detached cases and full coverage with checks mapping paths to current evidence metadata or None."""
    _plan(plan)
    access = _access(available_roles, source_available)
    _need(
        type(evidence_checks) is dict
        and all(
            type(key) is str and (value is None or type(value) is dict)
            for key, value in evidence_checks.items()
        )
    )
    try:
        release = asvs_catalog.catalog(plan["level"], limit=1000)
    except asvs_catalog.ASVSCatalogError:
        raise ASVSReviewError("ASVS catalog is unavailable or invalid") from None
    cases = []
    for requirement in release.pop("requirements"):
        requirement_id = requirement["requirement_id"]
        record = plan["records"][requirement_id]
        missing = _missing(plan, requirement_id, access)
        errors = [
            {"path": item["path"], "reason": "Evidence is missing, unchecked, or changed."}
            for item in record["evidence"]
            if not _matches(item, evidence_checks.get(item["path"]))
        ]
        status = "blocked" if missing else "inconclusive" if errors else record["status"]
        reasons = []
        if missing:
            reasons.append("Declared review prerequisites are unavailable.")
        if errors:
            reasons.append("Referenced evidence is untrusted; reassessment is required.")
        fallback = "Not yet reviewed." if status == "untested" else "Reviewer-attested outcome."
        applicability = "not_applicable" if status == "not_applicable" else "applicable"
        integrity = "matched" if record["evidence"] else "not_cited"
        case = requirement | deepcopy(record)
        case.update(
            plan_id=plan["plan_id"],
            control_id="asvs:" + requirement_id,
            case_id=plan["plan_id"] + ":" + requirement_id,
            url=plan["asset"],
            method="REVIEW",
            verification_method=record["method"],
            role="application",
            recorded_status=record["status"],
            status=status,
            applicability=applicability if status in _DISPOSITIONS else "unreviewed",
            evaluation_mode="attested" if record["history"] else None,
            independently_verified=False,
            prerequisites_available=not missing,
            trusted=status in _DISPOSITIONS and not (missing or errors),
            evidence_errors=errors,
            evidence_integrity="untrusted" if errors else integrity,
            reason=" ".join(reasons) or fallback,
        )
        cases.append(case)
    counts = {status: sum(case["status"] == status for case in cases) for status in _STATUSES}
    applicable, assessed = len(cases) - counts["not_applicable"], counts["pass"] + counts["fail"]
    remaining = counts["untested"] + counts["blocked"] + counts["inconclusive"]
    for field in ("offset", "limit", "next_offset", "has_more"):
        release.pop(field)
    return {
        "plan": deepcopy({key: plan[key] for key in _METADATA}),
        "catalog": release,
        "cases": cases,
        "total": len(cases),
        "status_counts": counts,
        "coverage": {
            "total": len(cases),
            "applicable": applicable,
            "assessed": assessed,
            "remaining": remaining,
            "not_applicable": counts["not_applicable"],
            "percent": round(100 * assessed / applicable, 2) if applicable else None,
        },
        "complete": remaining == 0,
        "evaluation_mode": "attested",
        "independently_verified": False,
        "baseline_coverage_updated": False,
        "baseline_description": "Manual catalog review of OWASP ASVS; reviewer-attested, not independent verification or certification.",
        "notice": "Completion means all selected requirements have current supported dispositions; failures may remain; attested review is not compliance, independent verification, or certification.",
    }
