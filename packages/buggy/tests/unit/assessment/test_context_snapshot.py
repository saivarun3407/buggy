"""Exercise the pure, defensive engagement metadata projection boundary."""

from __future__ import annotations

import builtins
import hashlib
import inspect
import io
import json
import os
import socket
import sqlite3
import subprocess
import urllib.request
from copy import deepcopy
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path
from typing import Any, NoReturn

import pytest

from buggy.sandbox_kernel.context_snapshot import (
    ContextSnapshotError,
    Snapshot,
    SourceEnvelope,
    render_snapshot,
)

ENGAGEMENT = "local-review_1"
NOW = datetime(2025, 1, 2, 3, 4, 5, tzinfo=UTC)
SOURCES = ("scope", "coverage", "inventory", "findings", "objectives", "skills", "runtime", "asvs")
SECRET = "PRIVATE-SENTINEL-do-not-export-82a54c"
KINDS = (
    "Host",
    "Service",
    "Endpoint",
    "Finding",
    "Vulnerability",
    "CVE",
    "Misconfiguration",
    "Weakness",
)


def envelope(data: Any, *, total: int | None = None, status: str = "ok") -> dict[str, Any]:
    result = {"engagement": ENGAGEMENT, "status": status, "data": data}
    if total is not None:
        result["total"] = total
    return result


def statistics() -> dict[str, Any]:
    return {
        "status_counts": {
            "untested": 0,
            "pass": 1,
            "fail": 0,
            "blocked": 0,
            "inconclusive": 0,
            "not_applicable": 0,
        },
        "coverage": {
            "applicable": 1,
            "assessed": 1,
            "remaining": 0,
            "not_applicable": 0,
            "percent": 100.0,
        },
        "complete": True,
    }


def complete_sources() -> dict[str, dict]:
    return {
        "scope": envelope(
            {"allowed_hosts": ["api.example.test"], "denied_hosts": ["private.example.test"]}
        ),
        "coverage": envelope(
            statistics()
            | {
                "baseline": "web-api-minimum-v1",
                "revision": 4,
                "total_operations": 1,
                "total_cases": 1,
            }
        ),
        "inventory": envelope(
            [
                {
                    "operation_id": "operation-1",
                    "url": "https://api.example.test/items",
                    "method": "GET",
                }
            ],
            total=1,
        ),
        "findings": envelope(
            [
                {
                    "id": "node-1",
                    "kind": "Finding",
                    "cve_id": "CVE-2025-12345",
                    "cwe_id": "CWE-79",
                    "severity": "high",
                    "status": "open",
                    "host": "api.example.test",
                    "port": 443,
                    "protocol": "https",
                }
            ],
            total=1,
        ),
        "objectives": envelope(
            [{"id": "objective-1", "status": "in-progress", "phase": "recon"}], total=1
        ),
        "skills": envelope(
            [{"name_or_path": "/skills/web-review/SKILL.md", "status": "loaded"}], total=1
        ),
        "runtime": envelope([{"service": "sandbox", "status": "healthy"}], total=1),
        "asvs": envelope(
            [
                statistics()
                | {"plan_id": "plan-1", "asset": "api.example.test", "level": 2, "version": "5.0.0"}
            ],
            total=1,
        ),
    }


def section(markdown: str, source: str) -> str:
    return markdown.split(f"## {source}\n", 1)[1].split("\n## ", 1)[0]


def opaque(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode()).hexdigest()


def test_public_contract_and_deterministic_immutable_result() -> None:
    assert issubclass(ContextSnapshotError, ValueError)
    assert {"engagement", "status", "data", "total"} == set(SourceEnvelope.__annotations__)
    assert set(Snapshot.__annotations__) == {
        "engagement",
        "generated_at",
        "partial",
        "source_status",
        "markdown",
        "sha256",
    }
    signature = inspect.signature(render_snapshot)
    assert list(signature.parameters) == ["engagement", "sources", "now", "max_rows"]
    assert signature.parameters["now"].default is None
    assert signature.parameters["max_rows"].default == 1000
    for name in ("now", "max_rows"):
        assert signature.parameters[name].kind is inspect.Parameter.KEYWORD_ONLY
    sources = complete_sources()
    original = deepcopy(sources)
    result = render_snapshot(ENGAGEMENT, sources, now=NOW)
    assert result == render_snapshot(ENGAGEMENT, dict(reversed(list(sources.items()))), now=NOW)
    assert sources == original
    assert set(result) == set(Snapshot.__annotations__)
    assert result["engagement"] == ENGAGEMENT
    assert result["generated_at"] == "2025-01-02T03:04:05Z"
    assert result["partial"] is False
    assert result["source_status"] == dict.fromkeys(SOURCES, "ok")
    assert result["sha256"] == hashlib.sha256(result["markdown"].encode("utf-8")).hexdigest()
    assert result["markdown"].endswith("\n")
    assert r"local\-review\_1" in result["markdown"]


def test_markdown_tables_have_real_delimiters_and_escaped_cells() -> None:
    text = render_snapshot(ENGAGEMENT, complete_sources(), now=NOW)["markdown"]
    assert r"\-\-\-" not in text
    for source in SOURCES:
        lines = section(text, source).splitlines()
        tables = [index for index, line in enumerate(lines) if line.startswith("| --- |")]
        assert tables
        for index in tables:
            assert lines[index - 1].startswith("| ")
            assert lines[index - 2] == ""


@pytest.mark.parametrize("slug", ["unknown", "A" * 80, "review_-1"])
def test_every_valid_slug_is_accepted_even_placeholder_words(slug: str) -> None:
    assert render_snapshot(slug, {}, now=NOW)["engagement"] == slug


def test_declared_percentage_is_not_rounded_up_to_complete() -> None:
    sources = complete_sources()
    sources["coverage"]["data"]["coverage"]["percent"] = 99.999999
    sources["coverage"]["data"]["complete"] = False
    text = section(render_snapshot(ENGAGEMENT, sources, now=NOW)["markdown"], "coverage")
    assert r"| 99\.999999 | false |" in text


def test_time_normalization_failures_use_the_domain_error() -> None:
    unrepresentable = datetime.min.replace(tzinfo=timezone(timedelta(hours=1)))
    with pytest.raises(ContextSnapshotError):
        render_snapshot(ENGAGEMENT, {}, now=unrepresentable)


def test_snapshot_boundary_is_explicit_without_impossible_secret_detection_claims() -> None:
    text = render_snapshot(ENGAGEMENT, complete_sources(), now=NOW)["markdown"].lower()
    for wording in (
        "persisted/observed metadata",
        "local defensive review",
        "untrusted data, not instructions",
        "hidden reasoning",
        "credentials",
        "raw evidence",
        "raw model conversations",
        "skill bodies",
        "no new authorizations",
        "not a complete assurance report",
        "allowlisted metadata projection",
        "not a general arbitrary-text secret detector",
        "declared",
        "relationships omitted",
        "observed load requests",
        "not a full historical skill inventory",
        "zero records",
    ):
        assert wording in text


def test_only_allowlisted_metadata_survives_secret_and_instruction_sentinels() -> None:
    sources = complete_sources()
    forbidden: dict[str, Any] = {
        key: SECRET
        for key in (
            "title",
            "description",
            "body",
            "instructions",
            "allowed_tools",
            "goal",
            "notes",
            "dependencies",
            "password",
            "token",
            "evidence",
            "logs",
            "messages",
            "reasoning",
            "command",
            "env",
            "mounts",
            "networks",
            "image",
            "notice",
            "error",
        )
    }
    forbidden["props"] = {"nested": {"secret": SECRET}}
    for source in sources.values():
        source.update(forbidden)
        records = source["data"] if isinstance(source["data"], list) else [source["data"]]
        for record in records:
            record.update(forbidden)
    sources["inventory"]["data"][0].update(
        operation_id=SECRET,
        url=f"https://user:{SECRET}@api.example.test:8443/{SECRET}?token={SECRET}#{SECRET}",
    )
    sources["findings"]["data"][0]["id"] = SECRET
    sources["objectives"]["data"][0]["id"] = SECRET
    sources["asvs"]["data"][0].update(
        plan_id=SECRET, asset=f"https://user:{SECRET}@api.example.test/{SECRET}?{SECRET}#{SECRET}"
    )
    sources[SECRET] = envelope({"conversation": SECRET})
    result = render_snapshot(ENGAGEMENT, sources, now=NOW)
    assert SECRET not in json.dumps(result)
    assert r"https://api\.example\.test:8443" in section(result["markdown"], "inventory")
    assert opaque(SECRET) in result["markdown"]
    assert set(result["source_status"]) == set(SOURCES)


@pytest.mark.parametrize("source", SOURCES)
@pytest.mark.parametrize("label", [None, "other-engagement", "LOCAL-REVIEW_1"])
def test_ok_envelopes_must_bind_the_exact_selected_engagement(source: str, label: Any) -> None:
    sources = complete_sources()
    if label is None:
        sources[source].pop("engagement")
    else:
        sources[source]["engagement"] = label
    with pytest.raises(ContextSnapshotError) as caught:
        render_snapshot(ENGAGEMENT, sources, now=NOW)
    assert "other-engagement" not in str(caught.value)


@pytest.mark.parametrize("source", SOURCES)
@pytest.mark.parametrize("field", ["engagement", "engagement_name"])
def test_explicit_record_scope_conflicts_are_rejected_even_beyond_the_limit(
    source: str, field: str
) -> None:
    sources = complete_sources()
    data = sources[source]["data"]
    if isinstance(data, list):
        data.append(data[0] | {field: SECRET})
        sources[source]["total"] = len(data)
    else:
        data[field] = SECRET
    with pytest.raises(ContextSnapshotError) as caught:
        render_snapshot(ENGAGEMENT, sources, now=NOW, max_rows=1)
    assert SECRET not in str(caught.value)


@pytest.mark.parametrize("status", ["unavailable", "not_requested", "error"])
def test_unavailable_sources_ignore_payloads_and_use_only_fixed_status_codes(status: str) -> None:
    sources = complete_sources()
    sources["asvs"] = {
        "engagement": SECRET,
        "status": status,
        "data": SECRET,
        "error": SECRET,
        "total": SECRET,
    }
    result = render_snapshot(ENGAGEMENT, sources, now=NOW)
    assert result["partial"] is True
    assert result["source_status"]["asvs"] == status
    assert status in section(result["markdown"], "asvs")
    assert SECRET not in json.dumps(result)
    assert "No records exported" in section(result["markdown"], "asvs")


def test_missing_sources_are_explicit_and_optional_asvs_is_not_requested() -> None:
    result = render_snapshot(ENGAGEMENT, {}, now=NOW)
    assert result["partial"] is True
    assert result["source_status"] == dict.fromkeys(SOURCES[:-1], "unavailable") | {
        "asvs": "not_requested"
    }
    for source in SOURCES:
        assert "No records exported" in section(result["markdown"], source)
    assert "zero records" in result["markdown"]


def test_ok_zero_rows_and_missing_totals_do_not_assert_clean_or_complete() -> None:
    sources = complete_sources()
    for source in SOURCES[2:]:
        sources[source] = envelope([], total=0)
    sources["coverage"]["data"]["complete"] = False
    result = render_snapshot(ENGAGEMENT, sources, now=NOW)
    for source in SOURCES[2:]:
        text = section(result["markdown"], source)
        assert "available=0; exported=0; declared_total=0" in text
        assert "No rows projected" in text
    assert "complete" in section(result["markdown"], "coverage")
    assert "false" in section(result["markdown"], "coverage")
    sources["inventory"].pop("total")
    unknown = render_snapshot(ENGAGEMENT, sources, now=NOW)
    assert unknown["partial"] is True
    assert "declared_total=unknown" in section(unknown["markdown"], "inventory")
    assert "unknown total" in section(unknown["markdown"], "inventory")


def test_limits_and_page_omissions_are_disclosed_independently_for_each_list() -> None:
    sources = complete_sources()
    sources["scope"]["data"] = {
        "allowed_hosts": [f"allowed{index}.example.test" for index in range(3)],
        "denied_hosts": [f"denied{index}.example.test" for index in range(3)],
    }
    for source in SOURCES[2:]:
        sources[source]["data"] *= 3
        sources[source]["total"] = 5
    result = render_snapshot(ENGAGEMENT, sources, now=NOW, max_rows=1)
    assert result["partial"] is True
    for source in SOURCES[2:]:
        text = section(result["markdown"], source)
        assert "available=3; exported=1; declared_total=5" in text
        assert "omitted_by_limit=2; unavailable_rows=2" in text
    scope = section(result["markdown"], "scope")
    assert scope.count("available=3; exported=1; declared_total=3") == 2
    assert r"allowed0\.example\.test" in scope
    assert r"denied0\.example\.test" in scope
    assert "allowed1" not in scope and "denied1" not in scope


@pytest.mark.parametrize("source", ["scope", "coverage"])
def test_summary_envelope_total_cannot_silently_hide_other_pages(source: str) -> None:
    sources = complete_sources()
    sources[source]["total"] = 3
    result = render_snapshot(ENGAGEMENT, sources, now=NOW)
    assert result["partial"] is True
    assert "unavailable_rows=2" in section(result["markdown"], source)


def test_eligible_findings_keep_one_row_without_classified_ids() -> None:
    records = [{"id": f"opaque-{index}", "kind": kind} for index, kind in enumerate(KINDS)]
    result = render_snapshot(ENGAGEMENT, {"findings": envelope(records, total=8)}, now=NOW)
    text = section(result["markdown"], "findings")
    assert text.count("sha256:") == 8
    for index, kind in enumerate(KINDS):
        assert opaque(f"opaque-{index}") in text
        assert f"| {kind} |" in text
        assert f"opaque-{index}" not in text
    assert "available=8; exported=8; declared_total=8" in text


@pytest.mark.parametrize(
    "kind",
    ["Credential", "Secret", "Session", "User", "Account", "Token", "Password", [], {}, None],
)
def test_unsafe_node_kinds_are_omitted_without_values(kind: Any) -> None:
    sources = {"findings": envelope([{"id": SECRET, "kind": kind, "host": SECRET}], total=1)}
    result = render_snapshot(ENGAGEMENT, sources, now=NOW)
    text = section(result["markdown"], "findings")
    assert "available=1; exported=0; declared_total=1" in text
    assert "unsafe_or_invalid_rows=1" in text
    assert opaque(SECRET) not in text
    assert SECRET not in json.dumps(result)
    assert result["partial"] is True


def test_filtering_does_not_consume_the_eligible_finding_row_budget() -> None:
    records = [{"id": SECRET, "kind": "Credential"}]
    records += [{"id": f"safe-{index}", "kind": "Finding"} for index in range(2)]
    result = render_snapshot(
        ENGAGEMENT, {"findings": envelope(records, total=3)}, now=NOW, max_rows=1
    )
    text = section(result["markdown"], "findings")
    assert opaque("safe-0") in text and opaque("safe-1") not in text
    assert "unsafe_or_invalid_rows=1; omitted_by_limit=1" in text


@pytest.mark.parametrize(
    ("url", "origin"),
    [
        ("https://api.example.test/a?token=x#part", r"https://api\.example\.test"),
        ("HTTP://USER:PASS@API.EXAMPLE.TEST:8080/private", r"http://api\.example\.test:8080"),
        ("https://[2001:db8::1]:8443/private?q=s#s", r"https://\[2001:db8::1\]:8443"),
        ("http://[::1]/private", r"http://\[::1\]"),
        ("https://192.0.2.1:443/private", r"https://192\.0\.2\.1:443"),
    ],
)
def test_inventory_exports_valid_origins_only(url: str, origin: str) -> None:
    source = envelope([{"operation_id": "operation", "url": url, "method": "get"}], total=1)
    result = render_snapshot(ENGAGEMENT, {"inventory": source}, now=NOW)
    text = section(result["markdown"], "inventory")
    assert f"| {origin} |" in text
    assert "| GET |" in text
    for value in ("private", "USER", "PASS", "token=", "?q=", "#part"):
        assert value not in text


@pytest.mark.parametrize(
    "url",
    [
        "file:///etc/passwd",
        "javascript:alert(1)",
        "ftp://api.example.test/private",
        "//api.example.test/private",
        "https://-bad.example.test/",
        "https://bad_.example.test/",
        "https://api..example.test/",
        "https://api.example.test:0/",
        "https://api.example.test:65536/",
        "https://api.example.test:/",
        "https://api.example.test:notaport/",
        "https://api.example.test:-1/",
        "https://api.example.test:000000443/",
        "https://api.example.test\\@other.example.test/",
        "https://[fe80::1%25secret]/",
        "https://2001:db8::1/",
        "https://[v1.test]/",
        "https://127.1/",
        "https://0x7f000001/",
        "https://api.example.123/",
        "https://user@other@api.example.test/",
        "https://010.0.0.1/",
        "https://%65xample.test/",
        "https://éxample.test/",
        " https://api.example.test/",
        "https://api.example.test/\n",
        "https://api.\ttest/",
        "https://api.example.test/\x00",
        "https://api.example.test/\x7f",
    ],
)
def test_invalid_origins_remain_unknown_without_echoing_input(url: str) -> None:
    result = render_snapshot(
        ENGAGEMENT,
        {
            "inventory": envelope(
                [{"operation_id": "operation", "url": url, "method": "GET"}], total=1
            )
        },
        now=NOW,
    )
    text = section(result["markdown"], "inventory")
    assert "| GET | unknown |" in text
    assert "exported=1" in text


def test_scope_uses_only_valid_policy_labels_and_discloses_rejections() -> None:
    labels = ["API.EXAMPLE.TEST", "*.example.test", "192.0.2.0/24", "2001:db8::/32", "::1"]
    bad = [f"https://{SECRET}/", f"# {SECRET}", f"<b>{SECRET}</b>", "../private", "a_b", "*"]
    sources = {"scope": envelope({"allowed_hosts": labels + bad, "denied_hosts": []})}
    result = render_snapshot(ENGAGEMENT, sources, now=NOW)
    text = section(result["markdown"], "scope")
    for value in (
        r"api\.example\.test",
        r"\*\.example\.test",
        r"192\.0\.2\.0/24",
        "2001:db8::/32",
        "::1",
    ):
        assert value in text
    assert "unsafe_or_invalid_rows=6" in text
    assert "available=0; exported=0; declared_total=0" in text
    assert SECRET not in json.dumps(result)
    assert result["partial"] is True


def test_missing_scope_lists_are_unknown_not_empty_policy() -> None:
    result = render_snapshot(ENGAGEMENT, {"scope": envelope({})}, now=NOW)
    text = section(result["markdown"], "scope")
    assert "allowed_hosts: unavailable" in text
    assert "denied_hosts: unavailable" in text
    assert "available=0" not in text
    assert result["partial"] is True


def test_unrecognized_enums_and_standard_ids_cannot_inject_markdown() -> None:
    injection = f"\n# {SECRET}\n```\n<script>{SECRET}</script>\x00\u202e"
    sources = complete_sources()
    sources["inventory"]["data"][0]["method"] = injection
    sources["findings"]["data"][0].update(
        cve_id=f"CVE-2025-1234{injection}",
        cwe_id="CWE-0",
        severity=injection,
        status=injection,
        host=injection,
        port=True,
        protocol=injection,
    )
    sources["objectives"]["data"][0].update(status=injection, phase=injection)
    sources["asvs"]["data"][0].update(version=injection, level=True, asset=injection)
    sources["coverage"]["data"].update(baseline=injection, revision=True)
    result = render_snapshot(ENGAGEMENT, sources, now=NOW)
    text = result["markdown"]
    for value in (SECRET, "```", "<script>", "\x00", "\u202e", "CWE-0"):
        assert value not in text
    assert text.count("\n## ") == len(SOURCES)
    assert "unknown" in section(text, "findings")


@pytest.mark.parametrize("field", ["total_operations", "total_cases", "revision"])
@pytest.mark.parametrize("value", [True, -1, "0", 1.2, float("nan"), float("inf"), 10**100])
def test_declared_counts_are_bounded_strict_integers(field: str, value: Any) -> None:
    sources = complete_sources()
    sources["coverage"]["data"][field] = value
    result = render_snapshot(ENGAGEMENT, sources, now=NOW)
    assert "unknown" in section(result["markdown"], "coverage")
    assert result["partial"] is True


@pytest.mark.parametrize("source", ["coverage", "asvs"])
def test_missing_or_malformed_declared_coverage_never_becomes_complete(source: str) -> None:
    sources = complete_sources()
    record = sources[source]["data"] if source == "coverage" else sources[source]["data"][0]
    record["status_counts"] = {SECRET: 991122, "pass": True}
    record["coverage"] = {SECRET: 991122, "percent": float("nan"), "assessed": -1}
    record["complete"] = "true"
    result = render_snapshot(ENGAGEMENT, sources, now=NOW)
    text = section(result["markdown"], source)
    assert result["partial"] is True
    assert "unknown" in text
    assert "true" not in text
    assert "991122" not in text and SECRET not in json.dumps(result)


@pytest.mark.parametrize("percent", [-1, 101, True, "100", float("nan"), float("inf")])
def test_coverage_percent_is_finite_and_bounded(percent: Any) -> None:
    sources = complete_sources()
    sources["coverage"]["data"]["coverage"]["percent"] = percent
    assert "unknown" in section(
        render_snapshot(ENGAGEMENT, sources, now=NOW)["markdown"], "coverage"
    )


@pytest.mark.parametrize(
    "name", ["web-review", "/skills/web-review/SKILL.md", "skills/standard/web_review/SKILL.md"]
)
def test_skills_export_safe_observed_identifiers_only(name: str) -> None:
    source = envelope([{"name_or_path": name, "status": "requested", "body": SECRET}], total=1)
    result = render_snapshot(ENGAGEMENT, {"skills": source}, now=NOW)
    text = section(result["markdown"], "skills")
    assert "exported=1" in text and "requested" in text
    assert SECRET not in json.dumps(result)


@pytest.mark.parametrize(
    "name",
    [
        f"https://{SECRET}",
        "../private",
        "/etc/passwd",
        "/skills/../private",
        "/skills/a/../../private",
        "/skills/%2e%2e/private",
        "/skills/a\\private",
        "/skills/a\nprivate",
        "/skills//private",
        "a/b",
        "a" * 201,
        "<b>private</b>",
    ],
)
def test_invalid_skill_names_are_omitted_not_sanitized_into_different_paths(name: str) -> None:
    source = envelope([{"name_or_path": name, "status": "loaded"}], total=1)
    result = render_snapshot(ENGAGEMENT, {"skills": source}, now=NOW)
    text = section(result["markdown"], "skills")
    assert "exported=0" in text and "unsafe_or_invalid_rows=1" in text
    assert SECRET not in json.dumps(result)


def test_runtime_only_projects_fixed_service_kinds_without_host_wide_details() -> None:
    records = [
        {"service": service, "status": "healthy", "image": SECRET, "env": {"TOKEN": SECRET}}
        for service in ("sandbox", "knowledge_graph", "llm_proxy", "skillogy", SECRET)
    ]
    result = render_snapshot(ENGAGEMENT, {"runtime": envelope(records, total=5)}, now=NOW)
    text = section(result["markdown"], "runtime")
    assert "exported=4" in text and "unsafe_or_invalid_rows=1" in text
    assert SECRET not in json.dumps(result)
    assert "image" not in text


@pytest.mark.parametrize(
    "engagement", ["", ".", "..", "a/b", "a b", "-a", "a\n", "é", "a" * 81, None, 7]
)
def test_invalid_engagements_raise_domain_error_without_echo(engagement: Any) -> None:
    with pytest.raises(ContextSnapshotError):
        render_snapshot(engagement, {}, now=NOW)


@pytest.mark.parametrize("limit", [False, True, 0, -1, 1001, 1.0, "1", None])
def test_invalid_max_rows_raise_domain_error(limit: Any) -> None:
    with pytest.raises(ContextSnapshotError):
        render_snapshot(ENGAGEMENT, {}, now=NOW, max_rows=limit)


def test_max_rows_rejects_integer_subclasses() -> None:
    class RowLimit(int):
        pass

    with pytest.raises(ContextSnapshotError):
        render_snapshot(ENGAGEMENT, {}, now=NOW, max_rows=RowLimit(1))


@pytest.mark.parametrize("now", [datetime(2025, 1, 2), "2025-01-02T00:00:00Z", 1, False])
def test_invalid_times_raise_domain_error(now: Any) -> None:
    with pytest.raises(ContextSnapshotError):
        render_snapshot(ENGAGEMENT, {}, now=now)


def test_aware_time_is_normalized_and_default_time_is_aware() -> None:
    now = NOW.astimezone(timezone(timedelta(hours=5, minutes=30)))
    assert render_snapshot(ENGAGEMENT, {}, now=now) == render_snapshot(ENGAGEMENT, {}, now=NOW)
    before = datetime.now(UTC)
    result = render_snapshot(ENGAGEMENT, {})
    after = datetime.now(UTC)
    assert before <= datetime.fromisoformat(result["generated_at"]) <= after


@pytest.mark.parametrize(
    "sources", [None, [], "private", {"scope": None}, {"scope": {"status": SECRET}}]
)
def test_invalid_source_arguments_raise_fixed_domain_errors(sources: Any) -> None:
    with pytest.raises(ContextSnapshotError) as caught:
        render_snapshot(ENGAGEMENT, sources, now=NOW)
    assert SECRET not in str(caught.value)


def test_source_status_cannot_supply_custom_formatting() -> None:
    class UnsafeStatus(str):
        def __str__(self) -> str:
            return SECRET

    sources = complete_sources()
    sources["inventory"]["status"] = UnsafeStatus("ok")
    with pytest.raises(ContextSnapshotError):
        render_snapshot(ENGAGEMENT, sources, now=NOW)


def test_datetime_subclasses_cannot_supply_generated_text() -> None:
    class UnsafeTime(datetime):
        def isoformat(self, sep: str = "T", timespec: str = "auto") -> str:
            return SECRET

    with pytest.raises(ContextSnapshotError):
        render_snapshot(ENGAGEMENT, {}, now=UnsafeTime(2025, 1, 2, tzinfo=UTC))


@pytest.mark.parametrize("total", [False, -1, "1", 1.0, 10**100, 0, None])
def test_invalid_or_underreported_source_totals_are_rejected(total: Any) -> None:
    sources = complete_sources()
    sources["inventory"]["total"] = total
    with pytest.raises(ContextSnapshotError):
        render_snapshot(ENGAGEMENT, sources, now=NOW)


@pytest.mark.parametrize("source", SOURCES)
def test_wrong_ok_data_shapes_raise_domain_errors(source: str) -> None:
    sources = complete_sources()
    sources[source]["data"] = [] if source in ("scope", "coverage") else {}
    with pytest.raises(ContextSnapshotError):
        render_snapshot(ENGAGEMENT, sources, now=NOW)


def test_malformed_rows_are_disclosed_and_objects_are_never_stringified() -> None:
    class NotText:
        def __str__(self) -> NoReturn:
            raise AssertionError("Arbitrary objects must not be stringified")

    sources = complete_sources()
    sources["inventory"]["data"] = [
        None,
        12,
        [SECRET],
        {"operation_id": NotText(), "url": NotText()},
    ]
    sources["inventory"]["total"] = 4
    sources["inventory"]["ignored"] = NotText()
    result = render_snapshot(ENGAGEMENT, sources, now=NOW)
    text = section(result["markdown"], "inventory")
    assert "available=4; exported=1; declared_total=4" in text
    assert "unsafe_or_invalid_rows=3" in text


def test_output_is_bounded_and_the_default_limit_is_disclosed() -> None:
    records = [
        {"operation_id": f"operation-{index}", "method": "GET", "url": "https://example.test/"}
        for index in range(1001)
    ]
    records[0]["unknown"] = SECRET * 100_000
    result = render_snapshot(ENGAGEMENT, {"inventory": envelope(records, total=1001)}, now=NOW)
    text = section(result["markdown"], "inventory")
    assert "available=1001; exported=1000; declared_total=1001" in text
    assert "omitted_by_limit=1" in text
    assert len(result["markdown"]) < 200_000
    assert SECRET not in result["markdown"]


def test_public_call_cannot_use_files_network_processes_or_database(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sources = complete_sources()

    def forbidden(*args: Any, **kwargs: Any) -> NoReturn:
        raise AssertionError("Snapshot rendering must be pure")

    with monkeypatch.context() as guard:
        for owner, attribute in (
            (builtins, "open"),
            (io, "open"),
            (os, "open"),
            (Path, "open"),
            (Path, "read_text"),
            (Path, "read_bytes"),
            (Path, "write_text"),
            (Path, "write_bytes"),
            (socket, "socket"),
            (socket, "create_connection"),
            (socket, "getaddrinfo"),
            (urllib.request, "urlopen"),
            (subprocess, "Popen"),
            (subprocess, "run"),
            (os, "system"),
            (os, "popen"),
            (sqlite3, "connect"),
        ):
            guard.setattr(owner, attribute, forbidden)
        result = render_snapshot(ENGAGEMENT, sources, now=NOW)
    assert result["source_status"] == dict.fromkeys(SOURCES, "ok")
