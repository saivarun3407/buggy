from __future__ import annotations

import builtins
import io
import json
import os
import socket
import subprocess
import urllib.request
from copy import deepcopy
from datetime import datetime, timedelta, timezone

import pytest

from buggy.sandbox_kernel.threat_scenarios import (
    ScenarioInputError,
    evaluate_scenario,
    list_scenarios,
)

NOW = datetime(2026, 9, 5, 12, tzinfo=timezone.utc)
MFA = "identity.phishing-resistant-mfa"
ENROLLMENT = "identity.mfa-enrollment"
OAUTH = "saas.oauth-consent"
GUEST = "saas.guest-access"
REVOCATION = "session.revocation"
DETECTION = "detection.saas-export"
DATA = {
    MFA: {
        "authentication_policies": [
            {
                "enabled": True,
                "scope": "all_users",
                "allowed_methods": ["fido2", "passkey", "webauthn"],
                "exclusions": [],
            }
        ]
    },
    ENROLLMENT: {
        "enrollment_policy": {
            "phishing_resistant_reauthentication_required": True,
            "managed_device_required": True,
            "change_notifications_enabled": True,
        }
    },
    OAUTH: {
        "user_consent": "admin_only",
        "admin_approval_required": True,
        "approved_app_ids": ["approved-app"],
        "grants": [{"app_id": "approved-app", "admin_approved": True}],
    },
    GUEST: {
        "guest_ids": ["guest-a", "guest-b"],
        "sensitive_resource_ids": ["resource-a", "resource-b"],
        "permissions": [
            {
                "guest_id": guest,
                "resource_id": resource,
                "read_allowed": False,
                "export_allowed": False,
            }
            for guest in ("guest-a", "guest-b")
            for resource in ("resource-a", "resource-b")
        ],
    },
    REVOCATION: {
        "synthetic": True,
        "revoked_at": "2026-09-05T11:00:00Z",
        "probes": [
            {"category": category, "observed_at": "2026-09-05T11:01:00Z", "http_status": status}
            for category, status in (("session", 401), ("refresh", 403))
        ],
    },
    DETECTION: {
        "synthetic": True,
        "simulation_id": "run-a",
        "events": [{"simulation_id": "run-a", "occurred_at": "2026-09-05T11:00:00Z"}],
        "alerts": [{"simulation_id": "run-a", "detected_at": "2026-09-05T11:00:30Z"}],
        "observation_window": {
            "started_at": "2026-09-05T10:59:00Z",
            "ended_at": "2026-09-05T11:10:00Z",
            "complete": True,
        },
        "max_detection_latency_seconds": 60,
    },
}


def artifact_for(scenario_id):
    return {
        "schema_version": 1,
        "asset": "https://saas.example.test/tenant",
        "observed_at": NOW.isoformat(),
        "evidence_kind": "simulation_log"
        if scenario_id in (REVOCATION, DETECTION)
        else "policy_export",
        "data": {"inventory_complete": True, **deepcopy(DATA[scenario_id])},
    }


def changed(scenario_id, path, value):
    artifact = artifact_for(scenario_id)
    target = artifact["data"]
    for component in path[:-1]:
        target = target[component]
    target[path[-1]] = value
    return artifact


BENCHMARK = [
    (MFA, ("authentication_policies", 0, "allowed_methods"), ["fido2", "sms"]),
    (ENROLLMENT, ("enrollment_policy", "managed_device_required"), False),
    (OAUTH, ("grants", 0, "app_id"), "unapproved-app"),
    (GUEST, ("permissions", 0, "read_allowed"), True),
    (REVOCATION, ("probes", 0, "http_status"), 200),
    (DETECTION, ("alerts", 0, "simulation_id"), "other-run"),
]


@pytest.mark.parametrize("scenario_id,path,bad_value", BENCHMARK, ids=list(DATA))
@pytest.mark.parametrize("expected", ["pass", "fail", "inconclusive"])
def test_known_outcome_benchmark(scenario_id, path, bad_value, expected):
    artifact = artifact_for(scenario_id)
    if expected == "fail":
        artifact = changed(scenario_id, path, bad_value)
    elif expected == "inconclusive":
        artifact["data"]["inventory_complete"] = False
    result = evaluate_scenario(scenario_id, artifact, now=NOW)
    assert result["status"] == expected, {
        "scenario": scenario_id,
        "expected": expected,
        "actual": result["status"],
        "false_pass": result["status"] == "pass" and expected != "pass",
        "missed_failure": expected == "fail" and result["status"] != "fail",
        "false_failure": expected != "fail" and result["status"] == "fail",
    }
    assert result["scenario_id"] == scenario_id
    assert result["catalog_version"] == "2026-09-05"
    assert result["evaluation_mode"] == "supplied_artifact"
    assert result["evidence_kind"] == artifact["evidence_kind"]
    assert result["freshness"]["status"] == "fresh"
    assert result["source_refs"] and result["reason_codes"]
    assert "not live control verification" in result["summary"]


def test_results_preserve_observation_and_evaluation_timestamps():
    artifact = artifact_for(ENROLLMENT)
    artifact["observed_at"] = "2026-09-05T12:30:00+02:00"
    result = evaluate_scenario(ENROLLMENT, artifact, now=NOW)
    assert result["observed_at"] == "2026-09-05T10:30:00+00:00"
    assert result["evaluated_at"] == NOW.isoformat()
    assert result["freshness"]["age_hours"] == 1.5


def test_catalog_is_constructible_versioned_defensive_and_independent():
    catalog = list_scenarios()
    assert catalog["catalog_version"] == "2026-09-05"
    assert {item["scenario_id"] for item in catalog["scenarios"]} == set(DATA)
    assert "not all current actor activity" in catalog["limitations"]
    assert all(
        cluster in catalog["attribution_scope"] for cluster in ("UNC6661", "UNC6671", "UNC6240")
    )
    assert "not universal actor attribution" in catalog["attribution_scope"]
    for scenario in catalog["scenarios"]:
        assert scenario["defensive_objective"]
        assert scenario["expected_artifact_kind"] in ("policy_export", "simulation_log")
        assert scenario["required_data_fields"]["inventory_complete"] == "boolean"
        assert scenario["pass_requirements"] and scenario["limitations"]
        assert all(source["publication_date"] == "2026-01-30" for source in scenario["source_refs"])
    catalog["scenarios"][0]["required_data_fields"].clear()
    catalog["scenarios"][0]["source_refs"][0]["url"] = "modified"
    assert list_scenarios()["scenarios"][0]["required_data_fields"]
    assert list_scenarios()["scenarios"][0]["source_refs"][0]["url"].startswith(
        "https://cloud.google.com/"
    )


@pytest.mark.parametrize("scenario_id", DATA)
@pytest.mark.parametrize("hours,status", [(-169, "stale"), (1, "future")])
def test_stale_and_future_snapshots_never_pass(scenario_id, hours, status):
    artifact = artifact_for(scenario_id)
    artifact["observed_at"] = (NOW + timedelta(hours=hours)).isoformat()
    result = evaluate_scenario(scenario_id, artifact, now=NOW)
    assert result["status"] == "inconclusive"
    assert result["freshness"]["status"] == status
    assert f"{status}_artifact" in result["reason_codes"]


@pytest.mark.parametrize("scenario_id", DATA)
def test_missing_data_fields_and_empty_data_are_inconclusive(scenario_id):
    artifact = artifact_for(scenario_id)
    artifact["data"] = {}
    assert evaluate_scenario(scenario_id, artifact, now=NOW)["status"] == "inconclusive"


def field_paths(value, prefix=()):
    if isinstance(value, dict):
        for key, child in value.items():
            yield prefix + (key,), child
            yield from field_paths(child, prefix + (key,))
    elif isinstance(value, list) and value:
        yield from field_paths(value[0], prefix + (0,))


FIELDS = [
    (sid, path, value) for sid in DATA for path, value in field_paths(artifact_for(sid)["data"])
]


@pytest.mark.parametrize("scenario_id,path,value", FIELDS)
def test_every_required_data_field_is_required(scenario_id, path, value):
    artifact = artifact_for(scenario_id)
    target = artifact["data"]
    for part in path[:-1]:
        target = target[part]
    del target[path[-1]]
    assert evaluate_scenario(scenario_id, artifact, now=NOW)["status"] == "inconclusive"


@pytest.mark.parametrize(
    "scenario_id,path", [(sid, path) for sid, path, value in FIELDS if type(value) is bool]
)
@pytest.mark.parametrize("value", ["true", "false", 1, 0, None, [], {}])
def test_all_required_booleans_are_strict(scenario_id, path, value):
    with pytest.raises(ScenarioInputError, match="^invalid_data$"):
        evaluate_scenario(scenario_id, changed(scenario_id, path, value), now=NOW)


@pytest.mark.parametrize(
    "scenario_id,path,bad_value",
    [
        row if row[0] != OAUTH else (OAUTH, ("grants", 0, "admin_approved"), False)
        for row in BENCHMARK[:-1]
    ],
    ids=list(DATA)[:-1],
)
def test_proven_policy_or_probe_failure_can_fail_partial_inventory(scenario_id, path, bad_value):
    artifact = changed(scenario_id, path, bad_value)
    artifact["data"]["inventory_complete"] = False
    assert evaluate_scenario(scenario_id, artifact, now=NOW)["status"] == "fail"


@pytest.mark.parametrize(
    "scenario_id,path,value,expected",
    [
        (MFA, ("authentication_policies",), [], "inconclusive"),
        (MFA, ("authentication_policies", 0, "allowed_methods"), [], "inconclusive"),
        (MFA, ("authentication_policies", 0, "exclusions"), ["excluded-group"], "fail"),
        (MFA, ("authentication_policies", 0, "scope"), "selected_users", "fail"),
        (MFA, ("authentication_policies", 0, "enabled"), False, "fail"),
        (
            ENROLLMENT,
            ("enrollment_policy", "phishing_resistant_reauthentication_required"),
            False,
            "fail",
        ),
        (ENROLLMENT, ("enrollment_policy", "change_notifications_enabled"), False, "fail"),
        (OAUTH, ("user_consent",), "disabled", "pass"),
        (OAUTH, ("user_consent",), "enabled", "fail"),
        (OAUTH, ("admin_approval_required",), False, "fail"),
        (OAUTH, ("grants", 0, "admin_approved"), False, "fail"),
        (OAUTH, ("grants",), [], "inconclusive"),
        (OAUTH, ("approved_app_ids",), [], "fail"),
        (GUEST, ("permissions",), [], "inconclusive"),
        (GUEST, ("guest_ids",), [], "inconclusive"),
        (GUEST, ("sensitive_resource_ids",), [], "inconclusive"),
        (GUEST, ("permissions", 0, "export_allowed"), True, "fail"),
        (REVOCATION, ("probes",), [], "inconclusive"),
        (REVOCATION, ("synthetic",), False, "inconclusive"),
        (DETECTION, ("events",), [], "inconclusive"),
        (DETECTION, ("alerts",), [], "fail"),
        (DETECTION, ("synthetic",), False, "inconclusive"),
        (DETECTION, ("events", 0, "simulation_id"), "wrong-run", "inconclusive"),
    ],
)
def test_specific_policy_requirements_and_empty_inventories(scenario_id, path, value, expected):
    assert (
        evaluate_scenario(scenario_id, changed(scenario_id, path, value), now=NOW)["status"]
        == expected
    )


@pytest.mark.parametrize(
    "scenario_id,key,bad_row",
    [
        (
            MFA,
            "authentication_policies",
            {"enabled": True, "scope": "all_users", "allowed_methods": ["sms"], "exclusions": []},
        ),
        (OAUTH, "grants", {"app_id": "unapproved-app", "admin_approved": True}),
    ],
)
def test_all_policy_and_grant_rows_are_checked(scenario_id, key, bad_row):
    artifact = artifact_for(scenario_id)
    artifact["data"][key].append(bad_row)
    assert evaluate_scenario(scenario_id, artifact, now=NOW)["status"] == "fail"


@pytest.mark.parametrize(
    "change",
    ["missing_pair", "duplicate_pair", "extra_pair", "duplicate_guest", "duplicate_resource"],
)
def test_guest_matrix_must_be_complete_unique_and_exact(change):
    artifact = artifact_for(GUEST)
    data = artifact["data"]
    if change == "missing_pair":
        data["permissions"].pop()
    elif change == "duplicate_pair":
        data["permissions"][-1] = deepcopy(data["permissions"][0])
    elif change == "extra_pair":
        data["permissions"][0]["resource_id"] = "outside-declared-inventory"
    elif change == "duplicate_guest":
        data["guest_ids"].append(data["guest_ids"][0])
    else:
        data["sensitive_resource_ids"].append(data["sensitive_resource_ids"][0])
    assert evaluate_scenario(GUEST, artifact, now=NOW)["status"] == "inconclusive"


@pytest.mark.parametrize(
    "status,expected",
    [
        (100, "inconclusive"),
        (200, "fail"),
        (204, "fail"),
        (299, "fail"),
        (301, "inconclusive"),
        (302, "inconclusive"),
        (307, "inconclusive"),
        (400, "inconclusive"),
        (401, "pass"),
        (403, "pass"),
        (404, "inconclusive"),
        (429, "inconclusive"),
        (500, "inconclusive"),
        (503, "inconclusive"),
        (None, "inconclusive"),
    ],
)
def test_revocation_requires_explicit_http_denial(status, expected):
    artifact = changed(REVOCATION, ("probes", 0, "http_status"), status)
    assert evaluate_scenario(REVOCATION, artifact, now=NOW)["status"] == expected


@pytest.mark.parametrize(
    "path,value",
    [
        (("probes",), DATA[REVOCATION]["probes"][:1]),
        (("probes", 1, "category"), "session"),
        (("probes", 0, "observed_at"), "2026-09-05T11:00:00Z"),
        (("probes", 0, "observed_at"), "2026-09-05T10:59:59Z"),
        (("probes", 0, "observed_at"), "2026-09-05T12:00:00.000001Z"),
        (("revoked_at",), "2026-09-06T11:00:00Z"),
    ],
)
def test_revocation_requires_both_categories_and_consistent_after_timestamps(path, value):
    assert (
        evaluate_scenario(REVOCATION, changed(REVOCATION, path, value), now=NOW)["status"]
        == "inconclusive"
    )


@pytest.mark.parametrize(
    "detected_at,expected,reason",
    [
        ("2026-09-05T10:59:59Z", "fail", "matching_alert_missing"),
        ("2026-09-05T11:00:00Z", "pass", "supplied_requirements_satisfied"),
        ("2026-09-05T11:01:00Z", "pass", "supplied_requirements_satisfied"),
        ("2026-09-05T11:01:00.000001Z", "fail", "detection_latency_exceeded"),
        ("2026-09-05T11:02:00Z", "fail", "detection_latency_exceeded"),
        ("2026-09-05T12:00:01Z", "inconclusive", "observation_window_incomplete"),
    ],
)
def test_detection_exact_latency_and_timestamp_bounds(detected_at, expected, reason):
    artifact = changed(DETECTION, ("alerts", 0, "detected_at"), detected_at)
    result = evaluate_scenario(DETECTION, artifact, now=NOW)
    assert result["status"] == expected
    assert reason in result["reason_codes"]


@pytest.mark.parametrize(
    "path,value,expected",
    [
        (("observation_window", "complete"), False, "inconclusive"),
        (("observation_window", "ended_at"), "2026-09-05T11:00:59.999999Z", "inconclusive"),
        (("observation_window", "ended_at"), "2026-09-05T11:01:00Z", "pass"),
        (("observation_window", "ended_at"), "2026-09-05T12:00:01Z", "inconclusive"),
        (("observation_window", "started_at"), "2026-09-05T11:00:01Z", "inconclusive"),
        (("observation_window", "started_at"), "2026-09-05T12:01:00Z", "inconclusive"),
    ],
)
def test_detection_requires_a_finished_and_sufficient_observation_window(path, value, expected):
    assert (
        evaluate_scenario(DETECTION, changed(DETECTION, path, value), now=NOW)["status"] == expected
    )


def test_missing_alerts_or_window_are_not_negative_detection_evidence():
    for field in ("alerts", "observation_window", "max_detection_latency_seconds"):
        artifact = artifact_for(DETECTION)
        del artifact["data"][field]
        assert evaluate_scenario(DETECTION, artifact, now=NOW)["status"] == "inconclusive"
    for field in ("inventory_complete", "complete"):
        artifact = changed(DETECTION, ("alerts",), [])
        container = (
            artifact["data"]
            if field == "inventory_complete"
            else artifact["data"]["observation_window"]
        )
        container[field] = False
        assert evaluate_scenario(DETECTION, artifact, now=NOW)["status"] == "inconclusive"


def test_detection_does_not_reuse_an_earlier_alert_for_a_later_event():
    artifact = artifact_for(DETECTION)
    artifact["data"]["events"].append(
        {"simulation_id": "run-a", "occurred_at": "2026-09-05T11:03:00Z"}
    )
    result = evaluate_scenario(DETECTION, artifact, now=NOW)
    assert result["status"] == "fail" and "matching_alert_missing" in result["reason_codes"]
    artifact["data"]["alerts"].append(
        {"simulation_id": "run-b", "detected_at": "2026-09-05T11:03:30Z"}
    )
    assert evaluate_scenario(DETECTION, artifact, now=NOW)["status"] == "fail"
    artifact["data"]["alerts"][-1]["simulation_id"] = "run-a"
    assert evaluate_scenario(DETECTION, artifact, now=NOW)["status"] == "pass"


@pytest.mark.parametrize("scenario_id", DATA)
def test_evidence_kind_mismatch_and_normalized_attestation(scenario_id):
    artifact = artifact_for(scenario_id)
    artifact["evidence_kind"] = "operator_attestation"
    result = evaluate_scenario(scenario_id, artifact, now=NOW)
    assert result["status"] == "pass" and "not live control verification" in result["summary"]
    artifact["evidence_kind"] = (
        "policy_export" if scenario_id in (REVOCATION, DETECTION) else "simulation_log"
    )
    result = evaluate_scenario(scenario_id, artifact, now=NOW)
    assert result["status"] == "inconclusive" and "evidence_kind_mismatch" in result["reason_codes"]


@pytest.mark.parametrize("scenario_id", DATA)
def test_injected_freshness_boundary_and_timezone_equivalence(scenario_id):
    artifact = artifact_for(scenario_id)
    artifact["observed_at"] = "2026-09-05T08:00:00-04:00"
    boundary = NOW + timedelta(hours=168)
    expected = "inconclusive" if scenario_id in (REVOCATION, DETECTION) else "pass"
    result = evaluate_scenario(scenario_id, artifact, now=boundary)
    assert result["status"] == expected and result["freshness"]["status"] == "fresh"
    assert (
        evaluate_scenario(scenario_id, artifact, now=boundary + timedelta(microseconds=1))["status"]
        == "inconclusive"
    )
    assert (
        evaluate_scenario(scenario_id, artifact, now=NOW - timedelta(microseconds=1))["freshness"][
            "status"
        ]
        == "future"
    )
    assert (
        evaluate_scenario(scenario_id, artifact, now=NOW + timedelta(hours=2), max_age_hours=2)[
            "status"
        ]
        == expected
    )
    assert (
        evaluate_scenario(scenario_id, artifact, now=NOW + timedelta(hours=3), max_age_hours=2)[
            "freshness"
        ]["status"]
        == "stale"
    )


@pytest.mark.parametrize("scenario_id", ["unknown-private-scenario", "", None, [], 1])
def test_unknown_scenario_is_a_safe_named_error(scenario_id):
    with pytest.raises(ScenarioInputError, match="^unknown_scenario$"):
        evaluate_scenario(scenario_id, artifact_for(MFA), now=NOW)
    assert issubclass(ScenarioInputError, ValueError)


@pytest.mark.parametrize(
    "artifact", [None, [], "secret-raw-artifact", 1, {}, {"schema_version": 1}]
)
def test_malformed_envelope_is_rejected(artifact):
    with pytest.raises(ScenarioInputError, match="^invalid_envelope$"):
        evaluate_scenario(MFA, artifact, now=NOW)


@pytest.mark.parametrize(
    "field", ["schema_version", "asset", "observed_at", "evidence_kind", "data"]
)
def test_envelope_fields_cannot_be_omitted(field):
    artifact = artifact_for(MFA)
    del artifact[field]
    with pytest.raises(ScenarioInputError, match="^invalid_envelope$"):
        evaluate_scenario(MFA, artifact, now=NOW)


@pytest.mark.parametrize(
    "field,value,error",
    [
        ("schema_version", True, "invalid_schema_version"),
        ("schema_version", 1.0, "invalid_schema_version"),
        ("schema_version", "1", "invalid_schema_version"),
        ("schema_version", 2, "invalid_schema_version"),
        ("evidence_kind", "live_probe", "invalid_evidence_kind"),
        ("evidence_kind", [], "invalid_evidence_kind"),
        ("data", [], "invalid_data"),
        ("data", None, "invalid_data"),
    ],
)
def test_strict_envelope_values(field, value, error):
    artifact = artifact_for(MFA)
    artifact[field] = value
    with pytest.raises(ScenarioInputError, match=f"^{error}$"):
        evaluate_scenario(MFA, artifact, now=NOW)


@pytest.mark.parametrize(
    "value",
    [
        "2026-09-05",
        "2026-09-05T12:00:00",
        "2026-09-05 12:00:00Z",
        "2026-02-30T12:00:00Z",
        "2026-09-05T12:00:00+00:99",
        "2026-09-05T12:00:00+24:00",
        "0001-01-01T00:00:00+01:00",
        "not-a-time-private-value",
        None,
        NOW,
    ],
)
def test_timezone_iso8601_is_strict_and_errors_do_not_echo(value):
    artifact = artifact_for(MFA)
    artifact["observed_at"] = value
    with pytest.raises(ScenarioInputError, match="^invalid_observed_at$"):
        evaluate_scenario(MFA, artifact, now=NOW)
    artifact = changed(REVOCATION, ("probes", 0, "observed_at"), value)
    with pytest.raises(ScenarioInputError, match="^invalid_data$"):
        evaluate_scenario(REVOCATION, artifact, now=NOW)


@pytest.mark.parametrize("value", [True, False, 0, -1, 1.5, "168", None])
def test_max_age_must_be_a_positive_integer(value):
    with pytest.raises(ScenarioInputError, match="^invalid_max_age_hours$"):
        evaluate_scenario(MFA, artifact_for(MFA), now=NOW, max_age_hours=value)


@pytest.mark.parametrize("value", [NOW.replace(tzinfo=None), "2026-09-05T12:00:00Z", 0])
def test_now_requires_an_aware_datetime(value):
    with pytest.raises(ScenarioInputError, match="^invalid_now$"):
        evaluate_scenario(MFA, artifact_for(MFA), now=value)


@pytest.mark.parametrize("value", [True, "60", 0, -1, 1.5, None])
def test_detection_latency_must_be_a_positive_integer(value):
    with pytest.raises(ScenarioInputError, match="^invalid_data$"):
        evaluate_scenario(
            DETECTION, changed(DETECTION, ("max_detection_latency_seconds",), value), now=NOW
        )


@pytest.mark.parametrize("value", [True, "403", 99, 600, 401.0])
def test_http_status_must_be_a_strict_status_or_null(value):
    with pytest.raises(ScenarioInputError, match="^invalid_data$"):
        evaluate_scenario(
            REVOCATION, changed(REVOCATION, ("probes", 0, "http_status"), value), now=NOW
        )


@pytest.mark.parametrize(
    "value",
    [
        "https://private-user:private-password@saas.example.test/",
        "https://private-user@saas.example.test/",
        "https://saas.example.test/?token=private-token",
        "https://saas.example.test/?ordinary=private-value",
        "https://saas.example.test/#private-token",
        "https://saas.example.test/%3Ftoken%3Dprivate-token",
        "https://saas.example.test/%23private-token",
        "https://saas.example.test/token/private-token",
        "https://saas.example.test/%253Ftoken%253Dprivate-token",
        "https://saas.example.test/%74oken/private-token",
        "https://saas.example.test/ACCESS_TOKEN/private-token",
        "https://saas.example.test/api-key/private-key",
        "https://saas.example.test/password=private-password",
        "https://saas.example.test:99999/",
        "https://saas.example.test:private-port/",
        "https://saas.example.test:0/",
        "https://saas.example.test:/",
        "https://saas.example.test../",
        "https://[invalid]/",
        "https://saas%40example.test/",
        "https://",
        "http:///relative",
        "//saas.example.test/",
        "file:///private/path",
        "ftp://saas.example.test/",
        " https://saas.example.test/",
        "https://saas.example.test/\nprivate-token",
        "https://saas.example.test/\\private-token",
        "https://saas.example.test/%0aprivate-token",
        "https://saas.example.test/%5cprivate-token",
        "https://saas.example.test/%zz",
        None,
        7,
    ],
)
def test_invalid_or_secret_bearing_urls_are_rejected_without_echo(value):
    artifact = artifact_for(MFA)
    artifact["asset"] = value
    with pytest.raises(ScenarioInputError, match="^invalid_asset$"):
        evaluate_scenario(MFA, artifact, now=NOW)


@pytest.mark.parametrize(
    "asset,canonical",
    [
        ("HTTPS://SAAS.EXAMPLE.TEST", "https://saas.example.test/"),
        ("https://[2001:db8::1]:8443/tenant", "https://[2001:db8::1]:8443/tenant"),
        ("http://192.0.2.1:8080/tenant", "http://192.0.2.1:8080/tenant"),
    ],
)
def test_absolute_http_urls_are_canonical_without_requesting_them(asset, canonical):
    artifact = artifact_for(MFA)
    artifact["asset"] = asset
    assert evaluate_scenario(MFA, artifact, now=NOW)["asset"] == canonical


@pytest.mark.parametrize(
    "scenario_id,path,value",
    [
        (MFA, ("authentication_policies",), {}),
        (MFA, ("authentication_policies",), [None]),
        (MFA, ("authentication_policies", 0, "allowed_methods"), [False]),
        (MFA, ("authentication_policies", 0, "allowed_methods"), [""]),
        (OAUTH, ("user_consent",), "unknown"),
        (OAUTH, ("grants", 0, "app_id"), "private-user@example.test"),
        (REVOCATION, ("probes", 0, "category"), "unknown"),
    ],
)
def test_malformed_normalized_data_is_rejected(scenario_id, path, value):
    with pytest.raises(ScenarioInputError, match="^invalid_data$"):
        evaluate_scenario(scenario_id, changed(scenario_id, path, value), now=NOW)


def test_incomplete_rows_do_not_hide_invalid_values_later_in_the_artifact():
    artifact = artifact_for(MFA)
    artifact["data"]["authentication_policies"] = [{}, {"enabled": "true"}]
    with pytest.raises(ScenarioInputError, match="^invalid_data$"):
        evaluate_scenario(MFA, artifact, now=NOW)


@pytest.mark.parametrize(
    "location,error",
    [("envelope", "invalid_envelope"), ("data", "invalid_data"), ("row", "invalid_data")],
)
@pytest.mark.parametrize("field", ["headers", "tokens", "principals", "technique", "name"])
def test_raw_extra_fields_are_rejected_without_echo(location, error, field):
    artifact = artifact_for(DETECTION)
    target = (
        artifact
        if location == "envelope"
        else artifact["data"]
        if location == "data"
        else artifact["data"]["alerts"][0]
    )
    target[field] = "private-raw-value-never-echo"
    with pytest.raises(ScenarioInputError, match=f"^{error}$"):
        evaluate_scenario(DETECTION, artifact, now=NOW)


@pytest.mark.parametrize(
    "scenario_id,path,value",
    [
        (MFA, ("authentication_policies", 0, "exclusions"), ["private-principal-surrogate"]),
        (OAUTH, ("grants", 0, "app_id"), "private-app-surrogate"),
        (GUEST, ("permissions", 0, "guest_id"), "private-guest-surrogate"),
        (DETECTION, ("alerts", 0, "simulation_id"), "private-run-surrogate"),
    ],
)
def test_results_never_echo_artifact_fields_and_do_not_mutate_inputs(scenario_id, path, value):
    artifact = changed(scenario_id, path, value)
    original = deepcopy(artifact)
    result = evaluate_scenario(scenario_id, artifact, now=NOW)
    serialized = json.dumps(result, sort_keys=True)
    assert "private-" not in serialized
    assert "data" not in result
    assert (
        result["observed_at"]
        == datetime.fromisoformat(artifact["observed_at"]).astimezone(timezone.utc).isoformat()
    )
    assert artifact == original
    result["source_refs"][0]["url"] = "modified"
    assert evaluate_scenario(scenario_id, artifact, now=NOW)["source_refs"][0]["url"].startswith(
        "https://cloud.google.com/"
    )


def test_incomplete_approved_inventory_does_not_prove_a_grant_is_unapproved():
    artifact = changed(OAUTH, ("grants", 0, "app_id"), "not-yet-in-incomplete-inventory")
    artifact["data"]["inventory_complete"] = False
    assert evaluate_scenario(OAUTH, artifact, now=NOW)["status"] == "inconclusive"


@pytest.mark.parametrize("scenario_id", [REVOCATION, DETECTION])
def test_old_simulation_records_cannot_be_relabelled_as_fresh(scenario_id):
    artifact = artifact_for(scenario_id)
    for path, value in field_paths(artifact["data"]):
        if isinstance(value, str) and value.endswith("Z"):
            target = artifact["data"]
            for part in path[:-1]:
                target = target[part]
            target[path[-1]] = (datetime.fromisoformat(value) - timedelta(days=8)).isoformat()
    if scenario_id == REVOCATION:
        artifact["data"]["probes"][1]["observed_at"] = artifact["data"]["probes"][0]["observed_at"]
    result = evaluate_scenario(scenario_id, artifact, now=NOW)
    assert result["status"] == "inconclusive" and result["freshness"]["status"] == "fresh"


def test_public_interfaces_do_not_perform_io_network_or_process_operations(monkeypatch):
    artifacts = {sid: artifact_for(sid) for sid in DATA}

    def forbidden(*args, **kwargs):
        raise AssertionError("artifact-only interface attempted a forbidden side effect")

    with monkeypatch.context() as patch:
        for module, name in [
            (builtins, "open"),
            (io, "open"),
            (os, "open"),
            (os, "system"),
            (os, "popen"),
            (socket, "socket"),
            (socket, "create_connection"),
            (socket, "getaddrinfo"),
            (subprocess, "Popen"),
            (subprocess, "run"),
            (urllib.request, "urlopen"),
        ]:
            patch.setattr(module, name, forbidden)
        assert len(list_scenarios()["scenarios"]) == 6
        for scenario_id, artifact in artifacts.items():
            assert evaluate_scenario(scenario_id, artifact, now=NOW)["status"] == "pass"
            artifact["observed_at"] = datetime.now(timezone.utc).isoformat()
            assert (
                evaluate_scenario(scenario_id, artifact)["evaluation_mode"] == "supplied_artifact"
            )
        for scenario_id, path, value in BENCHMARK:
            assert (
                evaluate_scenario(scenario_id, changed(scenario_id, path, value), now=NOW)["status"]
                == "fail"
            )
