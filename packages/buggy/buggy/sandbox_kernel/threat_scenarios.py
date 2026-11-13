"""Versioned defensive checks of supplied artifacts, with no live verification."""

from __future__ import annotations

import ipaddress
import re
from bisect import bisect_left
from copy import deepcopy
from datetime import datetime, timezone
from urllib.parse import unquote, urlsplit, urlunsplit


class ScenarioInputError(ValueError):
    """Malformed normalized input; messages are safe, fixed error codes."""


_VERSION = "2026-09-05"
_SOURCE_BASE = "https://cloud.google.com/blog/topics/threat-intelligence/"
_SOURCES = [
    {
        "url": _SOURCE_BASE + "defense-against-shinyhunters-cybercrime-saas",
        "publication_date": "2026-01-30",
        "role": "high_level_defensive_guidance",
    },
    {
        "url": _SOURCE_BASE + "expansion-shinyhunters-saas-data-theft",
        "publication_date": "2026-01-30",
        "role": "campaign_context_only",
    },
]
_LIMITATIONS = (
    "Supplied snapshots, simulations, and attestations are not live control verification. "
    "Authenticity and inventory completeness are caller assertions. Selected high-level controls, "
    "not all current actor activity and not full ASVS coverage. The caller enforces RoE and supplies "
    "credential-free URLs and non-secret surrogate identifiers, never credentials or raw telemetry. "
    "URL validation is not a general secret detector."
)
_SCENARIOS = {
    "identity.phishing-resistant-mfa": (
        "policy_export",
        "Require phishing-resistant authentication across the declared user scope.",
        {
            "authentication_policies": [
                {
                    "enabled": "boolean",
                    "scope": "string",
                    "allowed_methods": ["string"],
                    "exclusions": ["string"],
                }
            ]
        },
        "Nonempty enforcement-policy inventory; every policy enabled, scope exactly all_users, "
        "exclusions empty, allowed_methods nonempty and limited to fido2, passkey, webauthn.",
        "Conservative normalized enforcement policies; provider precedence is not modeled.",
    ),
    "identity.mfa-enrollment": (
        "policy_export",
        "Require protected MFA enrollment and change visibility.",
        {
            "enrollment_policy": {
                "phishing_resistant_reauthentication_required": "boolean",
                "managed_device_required": "boolean",
                "change_notifications_enabled": "boolean",
            }
        },
        "All enrollment_policy booleans true; inventory_complete asserts coverage of all enrollment flows.",
        "Policy assertions only; no enrollment, reauthentication, or notification is performed.",
    ),
    "saas.oauth-consent": (
        "policy_export",
        "Restrict consent and identify unapproved application grants.",
        {
            "user_consent": "disabled|admin_only|enabled",
            "admin_approval_required": "boolean",
            "approved_app_ids": ["string"],
            "grants": [{"app_id": "string", "admin_approved": "boolean"}],
        },
        "user_consent disabled or admin_only; admin_approval_required true; grants nonempty; every "
        "grant admin_approved true and app_id in explicit approved_app_ids. Absence from the "
        "approved list proves failure only when inventory_complete is true.",
        "No consent, application access, credential handling, or token exchange is performed.",
    ),
    "saas.guest-access": (
        "policy_export",
        "Require explicit guest read and export denial for sensitive resources.",
        {
            "guest_ids": ["string"],
            "sensitive_resource_ids": ["string"],
            "permissions": [
                {
                    "guest_id": "string",
                    "resource_id": "string",
                    "read_allowed": "boolean",
                    "export_allowed": "boolean",
                }
            ],
        },
        "Nonempty unique guest_ids and sensitive_resource_ids; exactly one permission row per "
        "guest/resource pair, no extra pairs, both access booleans false.",
        "Only the declared permission matrix is checked; no actual resource reads or exports.",
    ),
    "session.revocation": (
        "simulation_log",
        "Assess supplied synthetic session and refresh denial after revocation.",
        {
            "synthetic": "boolean",
            "revoked_at": "timestamp",
            "probes": [
                {
                    "category": "session|refresh",
                    "observed_at": "timestamp",
                    "http_status": "http_status_or_null",
                }
            ],
        },
        "synthetic true; both categories present; every probe strictly after revoked_at and at or "
        "before the snapshot. Only HTTP 401/403 prove denial; 2xx fails; null, errors, redirects, "
        "other statuses, missing categories or inconsistent timing are inconclusive.",
        "No sessions are created or revoked and no tokens are supplied or reused.",
    ),
    "detection.saas-export": (
        "simulation_log",
        "Assess timely alerts for supplied synthetic SaaS-export events.",
        {
            "synthetic": "boolean",
            "simulation_id": "string",
            "events": [{"simulation_id": "string", "occurred_at": "timestamp"}],
            "alerts": [{"simulation_id": "string", "detected_at": "timestamp"}],
            "observation_window": {
                "started_at": "timestamp",
                "ended_at": "timestamp",
                "complete": "boolean",
            },
            "max_detection_latency_seconds": "positive_integer",
        },
        "synthetic true; nonempty events for the exact simulation_id; a complete window contains "
        "all matching records, ends at/before the snapshot, and covers every event's full latency "
        "budget. Each event needs an exact-ID alert at/after it within the inclusive latency bound. "
        "An explicitly empty alerts list fails only with complete inventory/window; missing fields "
        "or windows are inconclusive. Events are normalized SaaS-export simulations, not real exports.",
        "Run-ID/time correlation only, never technique/name matching; no actual exports or alert generation.",
    ),
}


def list_scenarios() -> dict:
    """Return independent catalog data, including the normalized artifact schemas."""
    return {
        "catalog_version": _VERSION,
        "limitations": _LIMITATIONS,
        "attribution_scope": "ShinyHunters-branded clusters UNC6661, UNC6671, UNC6240 are distinct; "
        "not universal actor attribution.",
        "schema_notation": "Objects require all listed fields; [schema] means an array (at most 10000 items); "
        "| separates exact string alternatives. boolean is strict; positive_integer excludes booleans; "
        "string is a non-secret surrogate label matching [A-Za-z0-9][A-Za-z0-9_.:-]{0,127}. "
        "timestamp is YYYY-MM-DDTHH:MM:SS[.ffffff] with Z or a numeric +/-HH:MM timezone. "
        "http_status_or_null is integer 100..599 or null for an error. "
        "Unknown fields/malformed values raise ScenarioInputError; missing data fields are inconclusive "
        "unless a failure is proven. inventory_complete asserts exhaustive inventories/scopes and must "
        "be true for pass; empty inventories never establish good posture. max_age_hours is a positive "
        "integer (default 168); stale/future snapshots are inconclusive. freshness describes the envelope; "
        "probe/event records also must be within max_age_hours of now. Attestations need the same data.",
        "artifact_envelope": {
            "schema_version": 1,
            "asset": "Absolute credential-free HTTP(S) URL (max 2048 characters; ASCII DNS/IP host). "
            "No userinfo, query, fragment, nested escapes, or common secret-bearing path labels.",
            "observed_at": "timestamp",
            "evidence_kind": "policy_export|simulation_log|operator_attestation",
            "data": "scenario required_data_fields",
        },
        "scenarios": [
            {
                "scenario_id": key,
                "defensive_objective": objective,
                "expected_artifact_kind": kind,
                "accepted_evidence_kinds": [kind, "operator_attestation"],
                "required_data_fields": {"inventory_complete": "boolean", **deepcopy(fields)},
                "pass_requirements": rules,
                "limitations": _LIMITATIONS + " " + limitation,
                "source_refs": deepcopy(_SOURCES),
            }
            for key, (kind, objective, fields, rules, limitation) in _SCENARIOS.items()
        ],
    }


def _timestamp(value, error="invalid_data"):
    if type(value) is str and re.fullmatch(
        r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|[+-](?:[01]\d|2[0-3]):[0-5]\d)",
        value,
    ):
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)
        except (ValueError, OverflowError):
            pass
    raise ScenarioInputError(error)


def _asset(value):
    try:
        if type(value) is not str or len(value) > 2048 or any(c in value for c in "?#\\"):
            raise ValueError
        if re.search(r"%(?![0-9A-Fa-f]{2})", value):
            raise ValueError
        decoded = unquote(value, errors="strict")
        if any(c.isspace() or ord(c) < 32 or ord(c) == 127 or c in "\\@?#%" for c in decoded):
            raise ValueError
        secret_path = (
            r"(?i)(?:^|[/;])(?:password|passwd|secret|token|(?:access|refresh|id)[_-]?token|"
            r"api[_-]?key|authorization|credential|sessionid)(?:[/=:;]|$)"
        )
        if re.search(secret_path, urlsplit(decoded).path):
            raise ValueError
        parts = urlsplit(value)
        host, port = parts.hostname, parts.port
        if (
            parts.scheme not in ("http", "https")
            or not host
            or parts.username is not None
            or parts.password is not None
        ):
            raise ValueError
        if (
            parts.netloc.endswith(":")
            or (port is not None and not 1 <= port <= 65535)
            or "%" in host
        ):
            raise ValueError
        try:
            host = ipaddress.ip_address(host).compressed
        except ValueError:
            labels = host.removesuffix(".").split(".")
            if len(host) > 253 or not all(
                re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in labels
            ):
                raise ValueError from None
        authority = f"[{host}]" if ":" in host else host
        if port is not None:
            authority += f":{port}"
        return urlunsplit((parts.scheme, authority, parts.path or "/", "", ""))
    except (ValueError, UnicodeError):
        raise ScenarioInputError("invalid_asset") from None


def _validate(value, schema):
    if type(schema) is dict:
        if type(value) is not dict or value.keys() - schema.keys():
            raise ScenarioInputError("invalid_data")
        results = [_validate(value[key], schema[key]) for key in value]
        return schema.keys() <= value.keys() and all(results)
    if type(schema) is list:
        if type(value) is not list or len(value) > 10000:
            raise ScenarioInputError("invalid_data")
        return all([_validate(item, schema[0]) for item in value])
    if schema == "timestamp":
        _timestamp(value)
        return True
    valid = {
        "boolean": lambda: type(value) is bool,
        "string": lambda: (
            type(value) is str and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}", value)
        ),
        "positive_integer": lambda: type(value) is int and value > 0,
        "http_status_or_null": lambda: value is None or type(value) is int and 100 <= value <= 599,
    }
    if not (
        valid[schema]() if schema in valid else type(value) is str and value in schema.split("|")
    ):
        raise ScenarioInputError("invalid_data")
    return True


def _assess(scenario_id, data, snapshot, complete, clock, max_age_seconds):
    bad, gaps = set(), set()
    if scenario_id == "identity.phishing-resistant-mfa":
        policies = data.get("authentication_policies", [])
        if not policies:
            gaps.add("policy_inventory_empty")
        for policy in policies:
            if policy.get("enabled") is False:
                bad.add("mfa_policy_disabled")
            if "scope" in policy and policy["scope"] != "all_users":
                bad.add("mfa_scope_gap")
            if policy.get("exclusions"):
                bad.add("mfa_exclusions_present")
            methods = policy.get("allowed_methods", [])
            if not methods:
                gaps.add("authentication_methods_missing")
            if set(methods) - {"fido2", "passkey", "webauthn"}:
                bad.add("non_resistant_authentication_method")
    elif scenario_id == "identity.mfa-enrollment":
        if any(value is False for value in data.get("enrollment_policy", {}).values()):
            bad.add("enrollment_protection_disabled")
    elif scenario_id == "saas.oauth-consent":
        grants = data.get("grants", [])
        approved = set(data.get("approved_app_ids", []))
        if data.get("user_consent") == "enabled":
            bad.add("user_consent_unrestricted")
        if data.get("admin_approval_required") is False or any(
            row.get("admin_approved") is False for row in grants
        ):
            bad.add("administrative_approval_missing")
        if (
            data.get("inventory_complete") is True
            and "approved_app_ids" in data
            and any("app_id" in row and row["app_id"] not in approved for row in grants)
        ):
            bad.add("unapproved_app_grant")
        if not grants:
            gaps.add("grant_inventory_empty")
    elif scenario_id == "saas.guest-access":
        guests, resources = data.get("guest_ids", []), data.get("sensitive_resource_ids", [])
        rows = data.get("permissions", [])
        pairs = [(row.get("guest_id"), row.get("resource_id")) for row in rows]
        guest_set, resource_set = set(guests), set(resources)
        scoped = [guest in guest_set and resource in resource_set for guest, resource in pairs]
        if any(
            inside and (row.get("read_allowed") is True or row.get("export_allowed") is True)
            for inside, row in zip(scoped, rows)
        ):
            bad.add("guest_sensitive_access_allowed")
        if (
            not guests
            or not resources
            or len(guest_set) != len(guests)
            or len(resource_set) != len(resources)
            or len(set(pairs)) != len(pairs)
            or len(pairs) != len(guests) * len(resources)
            or not all(scoped)
        ):
            gaps.add("permission_matrix_incomplete")
    elif data.get("synthetic") is not True:
        gaps.add("synthetic_evidence_required")
    elif scenario_id == "session.revocation":
        revoked = _timestamp(data["revoked_at"]) if "revoked_at" in data else None
        categories = set()
        for row in data.get("probes", []):
            if not {"category", "observed_at", "http_status"} <= row.keys():
                continue
            observed = _timestamp(row["observed_at"])
            if revoked is None or not revoked < observed <= snapshot:
                gaps.add("probe_timing_unproven")
                continue
            if (clock - observed).total_seconds() > max_age_seconds:
                gaps.add("probe_records_stale")
                continue
            categories.add(row["category"])
            status = row["http_status"]
            if status is not None and 200 <= status <= 299:
                bad.add("revoked_access_accepted")
            elif status not in (401, 403):
                gaps.add("probe_denial_unproven")
        if categories != {"session", "refresh"}:
            gaps.add("probe_categories_incomplete")
    elif complete and data["inventory_complete"]:
        window = data["observation_window"]
        start, end = _timestamp(window["started_at"]), _timestamp(window["ended_at"])
        events = [
            _timestamp(row["occurred_at"])
            for row in data["events"]
            if row["simulation_id"] == data["simulation_id"]
        ]
        alerts = sorted(
            _timestamp(row["detected_at"])
            for row in data["alerts"]
            if row["simulation_id"] == data["simulation_id"]
        )
        limit = data["max_detection_latency_seconds"]
        if not events:
            gaps.add("simulation_events_missing")
        elif any((clock - at).total_seconds() > max_age_seconds for at in events):
            gaps.add("simulation_records_stale")
        elif (
            not window["complete"]
            or not start <= end <= snapshot
            or any(not start <= at <= end for at in events + alerts)
            or any((end - at).total_seconds() < limit for at in events)
        ):
            gaps.add("observation_window_incomplete")
        else:
            for at in events:
                index = bisect_left(alerts, at)
                if index == len(alerts):
                    bad.add("matching_alert_missing")
                elif (alerts[index] - at).total_seconds() > limit:
                    bad.add("detection_latency_exceeded")
    return bad, gaps


def evaluate_scenario(
    scenario_id: str, artifact: dict, *, now: datetime | None = None, max_age_hours: int = 168
) -> dict:
    """Evaluate only supplied normalized evidence; never contact or verify the asset."""
    if type(scenario_id) is not str or scenario_id not in _SCENARIOS:
        raise ScenarioInputError("unknown_scenario")
    envelope_fields = {"schema_version", "asset", "observed_at", "evidence_kind", "data"}
    if type(artifact) is not dict or artifact.keys() != envelope_fields:
        raise ScenarioInputError("invalid_envelope")
    if type(artifact["schema_version"]) is not int or artifact["schema_version"] != 1:
        raise ScenarioInputError("invalid_schema_version")
    asset = _asset(artifact["asset"])
    snapshot = _timestamp(artifact["observed_at"], "invalid_observed_at")
    kind = artifact["evidence_kind"]
    if type(kind) is not str or kind not in (
        "policy_export",
        "simulation_log",
        "operator_attestation",
    ):
        raise ScenarioInputError("invalid_evidence_kind")
    if type(max_age_hours) is not int or max_age_hours <= 0:
        raise ScenarioInputError("invalid_max_age_hours")
    clock = datetime.now(timezone.utc) if now is None else now
    if not isinstance(clock, datetime) or clock.tzinfo is None or clock.utcoffset() is None:
        raise ScenarioInputError("invalid_now")
    age = (clock - snapshot).total_seconds() / 3600
    freshness = "future" if age < 0 else "stale" if age > max_age_hours else "fresh"
    expected_kind, _, fields, _, _ = _SCENARIOS[scenario_id]
    data = artifact["data"]
    complete = _validate(data, {"inventory_complete": "boolean", **fields})
    bad, gaps = _assess(scenario_id, data, snapshot, complete, clock, max_age_hours * 3600)
    if not complete:
        gaps.add("missing_evidence_fields")
    if data.get("inventory_complete") is not True:
        gaps.add("inventory_incomplete")
    blocked = []
    if freshness != "fresh":
        blocked.append(freshness + "_artifact")
    if kind not in (expected_kind, "operator_attestation"):
        blocked.append("evidence_kind_mismatch")
    status = "inconclusive" if blocked else "fail" if bad else "inconclusive" if gaps else "pass"
    return {
        "scenario_id": scenario_id,
        "catalog_version": _VERSION,
        "asset": asset,
        "status": status,
        "observed_at": snapshot.isoformat(),
        "evaluated_at": clock.astimezone(timezone.utc).isoformat(),
        "reason_codes": sorted(set(blocked) | bad | gaps) or ["supplied_requirements_satisfied"],
        "summary": "Supplied artifact result: " + status + "; not live control verification.",
        "evidence_kind": kind,
        "evaluation_mode": "supplied_artifact",
        "source_refs": deepcopy(_SOURCES),
        "freshness": {
            "status": freshness,
            "age_hours": age,
            "max_age_hours": max_age_hours,
            "basis": "artifact_observed_at",
        },
    }
