from __future__ import annotations

import builtins
import http.client
import importlib.util
import io
import json
import os
import socket
import subprocess
import sys
import urllib.request
from copy import deepcopy
from datetime import datetime, timedelta, timezone

import pytest

from buggy.sandbox_kernel import kev
from buggy.sandbox_kernel.kev import KEVInputError, prioritize_kev

NOW = datetime(2025, 6, 20, 12, tzinfo=timezone.utc)
SOURCE = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
SECRET = "synthetic-private-marker-do-not-echo"


def make_catalog(**changes):
    catalog = {
        "catalogVersion": "2025.06.19",
        "dateReleased": "2025-06-19T12:00:00Z",
        "count": 1,
        "vulnerabilities": [
            {
                "cveID": "CVE-2025-1000",
                "vendorProject": "Synthetic Vendor",
                "product": "Synthetic Product",
                "vulnerabilityName": "Synthetic vulnerability",
                "shortDescription": "Synthetic catalog fixture only.",
                "dateAdded": "2025-06-01",
                "requiredAction": "Review the supplied vendor advisory.",
                "dueDate": "2025-06-30",
                "knownRansomwareCampaignUse": "Unknown",
            }
        ],
    }
    return catalog | changes


def make_observation(records=None, **changes):
    observation = {
        "schema_version": 1,
        "asset": "https://app.example.test",
        "observed_at": "2025-06-20T10:00:00Z",
        "evidence_kind": "scanner_export",
        "vulnerabilities": records
        if records is not None
        else [{"cve_id": "CVE-2025-1000", "applicability": "affected", "basis": "scanner_result"}],
    }
    return observation | changes


@pytest.mark.parametrize(
    ("cve_id", "applicability", "status", "priority"),
    [
        ("CVE-2025-1000", "affected", "listed", "urgent"),
        ("CVE-2025-1000", "unknown", "listed", "investigate"),
        ("CVE-2025-1000", "not_affected", "listed", "not_applicable"),
        ("CVE-2025-2000", "affected", "not_listed", "normal"),
        ("CVE-2025-2000", "unknown", "not_listed", "investigate"),
        ("CVE-2025-2000", "not_affected", "not_listed", "not_applicable"),
    ],
)
def test_fresh_exact_cve_priority_matrix(cve_id, applicability, status, priority):
    observation = make_observation(
        [{"cve_id": cve_id, "applicability": applicability, "basis": "vendor_advisory"}]
    )
    result = prioritize_kev(make_catalog(), observation, now=NOW)
    record = result["records"][0]
    assert record["cve_id"] == cve_id
    assert record["kev_status"] == status
    assert record["applicability"] == applicability
    assert record["priority"] == priority
    assert record["basis"] == "vendor_advisory"
    assert record["intelligence_fresh"] is True
    assert record["observation_fresh"] is True
    assert record["reasons"]
    if status == "not_listed":
        assert "does not establish safety or non-exploitability" in " ".join(record["reasons"])
    if applicability == "not_affected":
        assert "supplied" in " ".join(record["reasons"]).lower()
        assert "not independently verified" in " ".join(record["reasons"])


def test_optional_cisa_ransomware_metadata_can_be_absent():
    catalog = make_catalog()
    catalog["vulnerabilities"][0].pop("knownRansomwareCampaignUse")
    result = prioritize_kev(catalog, make_observation(), now=NOW)
    assert result["records"][0]["priority"] == "urgent"


def test_public_envelope_is_explicitly_artifact_based_and_due_dates_are_context_only():
    result = prioritize_kev(make_catalog(), make_observation(), now=NOW)
    assert issubclass(KEVInputError, ValueError)
    assert result["schema_version"] == 1
    assert result["evaluation_mode"] == "supplied_artifact"
    assert result["evaluated_at"] == "2025-06-20T12:00:00+00:00"
    assert result["observed_at"] == "2025-06-20T10:00:00+00:00"
    assert result["evidence_kind"] == "scanner_export"
    assert result["catalog"] == {
        "version": "2025.06.19",
        "source": SOURCE,
        "released_at": "2025-06-19T12:00:00+00:00",
        "count": 1,
    }
    warnings = " ".join(result["warnings"])
    assert "not independent vulnerability verification" in warnings
    assert "FCEB context, not automatic client remediation SLAs" in warnings
    assert "does not establish safety or non-exploitability" in warnings
    assert result["records"][0]["cisa_due_date"] == "2025-06-30"
    past_due = make_catalog()
    past_due["vulnerabilities"][0]["dueDate"] = "2025-06-02"
    assert (
        prioritize_kev(past_due, make_observation(), now=NOW)["records"][0]["priority"] == "urgent"
    )


def test_missing_applicability_is_unknown_without_product_or_version_inference():
    observation = make_observation(
        [
            {"cve_id": "CVE-2025-1000", "basis": "manual_review", "version": "1.0"},
            {
                "cve_id": "CVE-2025-2000",
                "basis": "manual_review",
                "product": "Synthetic Product",
                "version": "1.0",
            },
        ]
    )
    records = prioritize_kev(make_catalog(), observation, now=NOW)["records"]
    assert [record["applicability"] for record in records] == ["unknown", "unknown"]
    assert [record["kev_status"] for record in records] == ["listed", "not_listed"]
    assert [record["priority"] for record in records] == ["investigate", "investigate"]


def test_case_normalization_preserves_every_record_and_input_order_without_mutation():
    catalog = make_catalog()
    catalog["vulnerabilities"][0]["cveID"] = "cve-2025-1000"
    observations = [
        {"cve_id": f"cVe-2025-{index}", "applicability": "affected", "basis": "scanner_result"}
        for index in reversed(range(1000, 1173))
    ]
    observation = make_observation(observations)
    before = deepcopy((catalog, observation))
    result = prioritize_kev(catalog, observation, now=NOW)
    assert len(result["records"]) == 173
    assert [record["cve_id"] for record in result["records"]] == [
        record["cve_id"].upper() for record in observations
    ]
    assert result["records"][-1]["kev_status"] == "listed"
    assert (catalog, observation) == before
    assert prioritize_kev(catalog, observation, now=NOW) == result


def test_output_omits_private_observation_fields_and_raw_provider_text():
    catalog = make_catalog(source=SECRET, title=SECRET, headers={"Authorization": SECRET})
    entry = catalog["vulnerabilities"][0]
    for field in ("vendorProject", "product", "vulnerabilityName", "requiredAction"):
        entry[field] = SECRET
    entry.update(shortDescription=SECRET, notes=SECRET, credentials={"token": SECRET})
    observation = make_observation(
        asset=f"https://app.example.test/private/{SECRET}?api_key={SECRET}#{SECRET}",
        credentials={"password": SECRET},
        headers={"Authorization": SECRET},
        provider=SECRET,
    )
    observation["vulnerabilities"][0].update(
        rationale=SECRET, evidence={"body": SECRET}, credential=SECRET
    )
    result = prioritize_kev(catalog, observation, now=NOW)
    encoded = json.dumps(result)
    assert SECRET not in encoded
    assert "app.example.test" not in encoded
    assert "api_key" not in encoded
    assert "Authorization" not in encoded
    assert "asset" not in result
    assert result["catalog"]["source"] == SOURCE
    assert set(result["records"][0]) == {
        "cve_id",
        "kev_status",
        "applicability",
        "basis",
        "priority",
        "intelligence_fresh",
        "observation_fresh",
        "reasons",
        "cisa_due_date",
    }


def test_prioritization_performs_no_file_network_process_or_console_io(monkeypatch, capsys):
    def forbidden(*args, **kwargs):
        pytest.fail("Pure prioritization attempted I/O")

    with monkeypatch.context() as blocked:
        for owner, name in (
            (builtins, "open"),
            (io, "open"),
            (os, "open"),
            (os, "system"),
            (socket, "socket"),
            (socket, "create_connection"),
            (socket, "getaddrinfo"),
            (urllib.request, "urlopen"),
            (http.client.HTTPConnection, "connect"),
            (subprocess, "Popen"),
        ):
            blocked.setattr(owner, name, forbidden)
        result = prioritize_kev(make_catalog(), make_observation(), now=NOW)
    assert result["records"][0]["priority"] == "urgent"
    assert capsys.readouterr() == ("", "")


def test_standalone_module_import_and_public_call_need_only_stdlib(monkeypatch):
    original_import = builtins.__import__

    def stdlib_only(name, *args, **kwargs):
        assert name.split(".")[0] in sys.stdlib_module_names
        return original_import(name, *args, **kwargs)

    spec = importlib.util.spec_from_file_location("standalone_kev", kev.__file__)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    with monkeypatch.context() as blocked:
        blocked.setattr(builtins, "__import__", stdlib_only)
        spec.loader.exec_module(module)
        result = module.prioritize_kev(make_catalog(), make_observation(), now=NOW)
    assert issubclass(module.KEVInputError, ValueError)
    assert result["records"][0]["priority"] == "urgent"


@pytest.mark.parametrize(
    "catalog", [None, [], {}, {"error": SECRET}, {"count": 0, "vulnerabilities": []}]
)
def test_malformed_catalog_is_never_an_empty_success(catalog):
    with pytest.raises(KEVInputError) as caught:
        prioritize_kev(catalog, make_observation(), now=NOW)
    assert SECRET not in str(caught.value)


@pytest.mark.parametrize("field", ["catalogVersion", "dateReleased", "count", "vulnerabilities"])
def test_catalog_metadata_is_required(field):
    catalog = make_catalog()
    del catalog[field]
    with pytest.raises(KEVInputError):
        prioritize_kev(catalog, make_observation(), now=NOW)


@pytest.mark.parametrize("count", [True, False, "1", None, -1, 0, 2, 1.0])
def test_catalog_count_must_be_an_exact_nonnegative_integer_matching_all_entries(count):
    with pytest.raises(KEVInputError):
        prioritize_kev(make_catalog(count=count), make_observation(), now=NOW)


@pytest.mark.parametrize("entries", [None, {}, (), SECRET, [None], [[]], [SECRET], [{}]])
def test_catalog_vulnerabilities_must_be_a_list_of_complete_objects(entries):
    with pytest.raises(KEVInputError):
        prioritize_kev(make_catalog(vulnerabilities=entries), make_observation(), now=NOW)


@pytest.mark.parametrize(
    "field",
    [
        "cveID",
        "vendorProject",
        "product",
        "vulnerabilityName",
        "dateAdded",
        "requiredAction",
        "dueDate",
        "shortDescription",
    ],
)
def test_cisa_entry_fields_are_required_even_for_unobserved_cves(field):
    catalog = make_catalog()
    del catalog["vulnerabilities"][0][field]
    observation = make_observation(
        [{"cve_id": "CVE-2025-2000", "basis": "manual_review", "applicability": "unknown"}]
    )
    with pytest.raises(KEVInputError):
        prioritize_kev(catalog, observation, now=NOW)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("cveID", None),
        ("cveID", "CVE-25-1000"),
        ("cveID", "CVE-2025-123"),
        ("cveID", "CVE-2025-١٢٣٤"),
        ("cveID", SECRET),
        ("cveID", "CVE-2025-" + "1" * 40),
        ("vendorProject", None),
        ("vendorProject", ""),
        ("vendorProject", " " * 3),
        ("product", []),
        ("product", "x" * 4097),
        ("product", "bad\x00text"),
        ("vulnerabilityName", 1),
        ("requiredAction", {}),
        ("dateAdded", "2025-02-29"),
        ("dateAdded", "2025-06-20"),
        ("dateAdded", "2025-6-1"),
        ("dateAdded", "2025-06-01T00:00:00Z"),
        ("dueDate", "2025-05-31"),
        ("dueDate", "2025-04-31"),
        ("dueDate", None),
        ("knownRansomwareCampaignUse", "Yes"),
        ("knownRansomwareCampaignUse", []),
    ],
)
def test_cisa_entry_values_and_date_order_are_validated(field, value):
    catalog = make_catalog()
    catalog["vulnerabilities"][0][field] = value
    with pytest.raises(KEVInputError) as caught:
        prioritize_kev(catalog, make_observation(), now=NOW)
    assert SECRET not in str(caught.value)


@pytest.mark.parametrize("duplicate", ["CVE-2025-1000", "cVe-2025-1000", " CVE-2025-1000 "])
def test_catalog_duplicate_ids_are_rejected_after_normalization(duplicate):
    catalog = make_catalog(count=2)
    catalog["vulnerabilities"].append(catalog["vulnerabilities"][0] | {"cveID": duplicate})
    with pytest.raises(KEVInputError, match="Duplicate"):
        prioritize_kev(catalog, make_observation(), now=NOW)


@pytest.mark.parametrize(
    "version", [None, {}, 1, "", SECRET, "2025.06.19?token=" + SECRET, "1" * 33]
)
def test_catalog_version_is_bounded_numeric_dotted_metadata_not_provider_prose(version):
    with pytest.raises(KEVInputError) as caught:
        prioritize_kev(make_catalog(catalogVersion=version), make_observation(), now=NOW)
    assert SECRET not in str(caught.value)


@pytest.mark.parametrize(
    "released",
    [
        None,
        [],
        SECRET,
        "2025-06-19",
        "2025-06-19T12:00:00",
        "2025-06-19 12:00:00Z",
        "2025-02-30T12:00:00Z",
        "2025-06-19T24:00:00Z",
        "2025-06-19T12:00:00+24:00",
        "2025-06-19T12:00:00+00:60",
        "2025-06-19T12:00:00+01:00:10",
        "2025-06-19T12:00:00.1234567Z",
        "2025-06-20T12:00:01Z",
        "9999-12-31T23:59:59-23:59",
    ],
)
def test_catalog_release_requires_a_real_aware_nonfuture_timestamp(released):
    with pytest.raises(KEVInputError) as caught:
        prioritize_kev(make_catalog(dateReleased=released), make_observation(), now=NOW)
    assert SECRET not in str(caught.value)


def test_catalog_is_fully_validated_even_when_the_observation_is_empty():
    catalog = make_catalog(count=2)
    catalog["vulnerabilities"].append(catalog["vulnerabilities"][0] | {"cveID": "CVE-2025-2000"})
    catalog["vulnerabilities"][-1]["dueDate"] = SECRET
    with pytest.raises(KEVInputError):
        prioritize_kev(catalog, make_observation([]), now=NOW)


@pytest.mark.parametrize("observation", [None, [], {}, {"error": SECRET}])
def test_malformed_observation_is_rejected(observation):
    with pytest.raises(KEVInputError):
        prioritize_kev(make_catalog(), observation, now=NOW)


@pytest.mark.parametrize(
    "field", ["schema_version", "asset", "observed_at", "evidence_kind", "vulnerabilities"]
)
def test_observation_metadata_is_required_even_when_no_vulnerabilities_are_supplied(field):
    observation = make_observation([])
    del observation[field]
    with pytest.raises(KEVInputError):
        prioritize_kev(make_catalog(), observation, now=NOW)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("schema_version", True),
        ("schema_version", "1"),
        ("schema_version", 1.0),
        ("schema_version", 0),
        ("schema_version", 2),
        ("schema_version", None),
        ("evidence_kind", None),
        ("evidence_kind", []),
        ("evidence_kind", SECRET),
        ("evidence_kind", "scanner_result"),
        ("vulnerabilities", None),
        ("vulnerabilities", {}),
        ("vulnerabilities", ()),
        ("vulnerabilities", SECRET),
    ],
)
def test_observation_envelope_shapes_are_strict(field, value):
    observation = make_observation() | {field: value}
    with pytest.raises(KEVInputError) as caught:
        prioritize_kev(make_catalog(), observation, now=NOW)
    assert SECRET not in str(caught.value)


@pytest.mark.parametrize(
    "record", [None, [], SECRET, {}, {"cve_id": "CVE-2025-1000"}, {"basis": "manual_review"}]
)
def test_observation_records_require_cve_ids_and_attributed_bases(record):
    with pytest.raises(KEVInputError):
        prioritize_kev(make_catalog(), make_observation([record]), now=NOW)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("cve_id", None),
        ("cve_id", []),
        ("cve_id", SECRET),
        ("cve_id", "CVE-2025-123"),
        ("applicability", None),
        ("applicability", []),
        ("applicability", "Affected"),
        ("applicability", "not_exploitable"),
        ("applicability", SECRET),
        ("basis", None),
        ("basis", []),
        ("basis", SECRET),
        ("basis", "product_match"),
    ],
)
def test_observation_record_values_are_validated_without_echoing_input(field, value):
    observation = make_observation()
    observation["vulnerabilities"][0][field] = value
    with pytest.raises(KEVInputError) as caught:
        prioritize_kev(make_catalog(), observation, now=NOW)
    assert SECRET not in str(caught.value)


@pytest.mark.parametrize("applicability", ["affected", "unknown", "not_affected"])
def test_observation_duplicates_are_rejected_after_normalization(applicability):
    observation = make_observation()
    observation["vulnerabilities"].append(
        {"cve_id": " cVe-2025-1000 ", "applicability": applicability, "basis": "manual_review"}
    )
    with pytest.raises(KEVInputError, match="Duplicate"):
        prioritize_kev(make_catalog(), observation, now=NOW)


@pytest.mark.parametrize(
    "evidence_kind", ["scanner_export", "vendor_advisory", "operator_attestation"]
)
@pytest.mark.parametrize("basis", ["scanner_result", "vendor_advisory", "manual_review"])
def test_not_affected_is_always_attributed_to_supplied_enumerated_evidence(evidence_kind, basis):
    observation = make_observation(
        [{"cve_id": "CVE-2025-1000", "applicability": "not_affected", "basis": basis}],
        evidence_kind=evidence_kind,
    )
    result = prioritize_kev(make_catalog(), observation, now=NOW)
    assert result["evidence_kind"] == evidence_kind
    assert result["records"][0]["basis"] == basis
    assert result["records"][0]["priority"] == "not_applicable"
    assert "not independently verified" in " ".join(result["records"][0]["reasons"])


@pytest.mark.parametrize(
    "asset",
    [
        None,
        1,
        {},
        "app.example.test",
        "//app.example.test",
        "ftp://app.example.test",
        "file:///synthetic",
        "https://",
        "https://user:" + SECRET + "@app.example.test",
        "https://user@app.example.test",
        "https://app.example.test:bad",
        "https://app.example.test:65536",
        "https://app.example.test:0",
        "https://app.example.test:",
        "https://bad host.example.test",
        "https://app.\nexample.test",
        "https:\\app.example.test",
        "https://app.example.test\\@other.example.test",
        "https://[invalid]/",
        "https://[::1]extra/",
        "https://%61pp.example.test",
        "https://app..example.test",
        "https://-app.example.test",
        "https://app.example.test/%xy",
        " https://app.example.test",
        "https://app.example.test/" + "x" * 8192,
    ],
    ids=lambda value: str(value)[:90],
)
def test_asset_requires_an_absolute_well_formed_http_url_without_userinfo(asset):
    with pytest.raises(KEVInputError) as caught:
        prioritize_kev(make_catalog(), make_observation(asset=asset), now=NOW)
    assert SECRET not in str(caught.value)


@pytest.mark.parametrize(
    "asset",
    [
        "https://app.example.test",
        "http://app.example.test:8080/path?token=" + SECRET + "#fragment",
        "https://[2001:db8::1]:443/path",
        "HTTP://APP.EXAMPLE.TEST./",
        "https://127.0.0.1:65535",
        "https://app.example.test/%20safe",
    ],
)
def test_asset_parsing_is_syntax_only_and_never_echoes_any_asset_components(asset):
    result = prioritize_kev(make_catalog(), make_observation(asset=asset), now=NOW)
    assert result["records"][0]["priority"] == "urgent"
    assert "app.example.test" not in json.dumps(result)
    assert SECRET not in json.dumps(result)


@pytest.mark.parametrize(
    "observed",
    [
        None,
        [],
        SECRET,
        "2025-06-20",
        "2025-06-20T10:00:00",
        "2025-06-20 10:00:00Z",
        "2025-02-30T10:00:00Z",
        "2025-06-20T24:00:00Z",
        "2025-06-20T10:00:00+24:00",
        "2025-06-20T10:00:00+00:60",
        "2025-06-20T10:00:00+01:00:10",
        "2025-06-20T10:00:00.1234567Z",
        "2025-06-20T12:00:00.000001Z",
        "0001-01-01T00:00:00+01:00",
    ],
)
def test_observation_requires_a_real_aware_nonfuture_timestamp(observed):
    with pytest.raises(KEVInputError) as caught:
        prioritize_kev(make_catalog(), make_observation(observed_at=observed), now=NOW)
    assert SECRET not in str(caught.value)


@pytest.mark.parametrize(
    "old_catalog,old_observation", [(True, False), (False, True), (True, True)]
)
@pytest.mark.parametrize("cve_id", ["CVE-2025-1000", "CVE-2025-2000"])
@pytest.mark.parametrize("applicability", ["affected", "unknown", "not_affected"])
def test_stale_artifacts_require_investigation_even_for_not_affected_assertions(
    old_catalog, old_observation, cve_id, applicability
):
    catalog = make_catalog()
    observation = make_observation(
        [{"cve_id": cve_id, "applicability": applicability, "basis": "manual_review"}]
    )
    if old_catalog:
        catalog["dateReleased"] = "2025-06-05T12:00:00Z"
    if old_observation:
        observation["observed_at"] = "2025-06-05T12:00:00Z"
    result = prioritize_kev(catalog, observation, now=NOW)
    record = result["records"][0]
    assert record["priority"] == "investigate"
    assert record["applicability"] == applicability
    assert result["intelligence_fresh"] is record["intelligence_fresh"] is (not old_catalog)
    assert result["observation_fresh"] is record["observation_fresh"] is (not old_observation)
    warnings = " ".join(result["warnings"]).lower()
    if old_catalog:
        assert "catalog is stale" in warnings
    if old_observation:
        assert "snapshot is stale" in warnings


@pytest.mark.parametrize("applicability", ["affected", "unknown", "not_affected"])
def test_zero_catalog_is_explicitly_missing_intelligence_not_a_clean_result(applicability):
    observation = make_observation(
        [{"cve_id": "CVE-2025-1000", "applicability": applicability, "basis": "manual_review"}]
    )
    result = prioritize_kev(make_catalog(count=0, vulnerabilities=[]), observation, now=NOW)
    record = result["records"][0]
    assert record["kev_status"] == "not_listed"
    assert record["priority"] == "investigate"
    assert record["intelligence_fresh"] is result["intelligence_fresh"] is False
    assert "catalog is empty" in " ".join(result["warnings"]).lower()


def test_zero_observation_is_explicitly_no_assessment_and_not_a_clean_result():
    result = prioritize_kev(make_catalog(), make_observation([]), now=NOW)
    assert result["records"] == []
    assert "snapshot is empty" in " ".join(result["warnings"]).lower()
    assert "no asset assessment" in " ".join(result["warnings"]).lower()


@pytest.mark.parametrize(
    ("timestamp", "fresh"),
    [("2025-06-06T12:00:00Z", True), ("2025-06-06T11:59:59.999999Z", False)],
)
def test_freshness_boundary_is_inclusive_and_uses_exact_elapsed_time(timestamp, fresh):
    result = prioritize_kev(
        make_catalog(dateReleased=timestamp), make_observation(observed_at=timestamp), now=NOW
    )
    assert result["intelligence_fresh"] is result["observation_fresh"] is fresh
    assert result["records"][0]["priority"] == ("urgent" if fresh else "investigate")


def test_max_age_days_applies_to_both_catalog_and_snapshot():
    result = prioritize_kev(
        make_catalog(dateReleased="2025-06-18T12:00:00Z"),
        make_observation(observed_at="2025-06-18T12:00:00Z"),
        now=NOW,
        max_age_days=1,
    )
    assert result["intelligence_fresh"] is False
    assert result["observation_fresh"] is False
    assert result["records"][0]["priority"] == "investigate"


def test_offset_timestamps_and_injected_clock_are_canonical_and_deterministic():
    expected = prioritize_kev(make_catalog(), make_observation(), now=NOW)
    result = prioritize_kev(
        make_catalog(dateReleased="2025-06-19T07:00:00-05:00"),
        make_observation(observed_at="2025-06-20T15:30:00+05:30"),
        now=NOW.astimezone(timezone(timedelta(hours=-7))),
    )
    assert result == expected


def test_timestamps_equal_to_now_are_valid_and_default_clock_is_aware_utc():
    result = prioritize_kev(
        make_catalog(dateReleased=NOW.isoformat()),
        make_observation(observed_at=NOW.isoformat()),
        now=NOW,
    )
    assert result["records"][0]["priority"] == "urgent"
    before = datetime.now(timezone.utc)
    default = prioritize_kev(make_catalog(), make_observation())
    after = datetime.now(timezone.utc)
    evaluated = datetime.fromisoformat(default["evaluated_at"])
    assert evaluated.tzinfo == timezone.utc
    assert before <= evaluated <= after


@pytest.mark.parametrize("max_age_days", [None, True, False, 0, -1, 1.5, "14", 3651, 10**100])
def test_age_limit_requires_a_bounded_positive_nonboolean_integer(max_age_days):
    with pytest.raises(KEVInputError):
        prioritize_kev(make_catalog(), make_observation(), now=NOW, max_age_days=max_age_days)


@pytest.mark.parametrize(
    "now",
    [
        True,
        1,
        SECRET,
        datetime(2025, 6, 20, 12),
        datetime(1, 1, 1, tzinfo=timezone(timedelta(hours=1))),
        datetime.max.replace(tzinfo=timezone(timedelta(hours=-1))),
    ],
)
def test_clock_must_be_a_real_timezone_aware_datetime(now):
    with pytest.raises(KEVInputError) as caught:
        prioritize_kev(make_catalog(), make_observation(), now=now)
    assert SECRET not in str(caught.value)


@pytest.mark.parametrize("artifact", ["catalog", "observation"])
def test_oversized_lists_raise_a_named_limit_error_instead_of_silently_truncating(artifact):
    catalog, observation = make_catalog(), make_observation()
    if artifact == "catalog":
        catalog["vulnerabilities"] *= 50_001
        catalog["count"] = 50_001
    else:
        observation["vulnerabilities"] *= 50_001
    with pytest.raises(KEVInputError, match="record limit"):
        prioritize_kev(catalog, observation, now=NOW)


def test_invalid_observation_after_a_large_valid_prefix_is_not_ignored():
    records = [
        {"cve_id": f"CVE-2025-{index}", "applicability": "unknown", "basis": "manual_review"}
        for index in range(1000, 1300)
    ]
    records.append({"cve_id": "CVE-2025-1300", "applicability": "affected", "basis": SECRET})
    with pytest.raises(KEVInputError):
        prioritize_kev(make_catalog(), make_observation(records), now=NOW)
