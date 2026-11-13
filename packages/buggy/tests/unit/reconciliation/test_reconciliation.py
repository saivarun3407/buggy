"""Tests for the Phase 4 white-box reconciliation subsystem
(``buggy/reconciliation``).

No network / proxy / Neo4j: SARIF is built in-memory, observations are
synthetic, and the proof-gate round-trip uses a mock Caido client plus a
patched ``publish_finding_node``.

Covers the matrix the phase calls for:
  (a) SARIF parses to observations with the correct class via CWE
  (b) a SAST + dynamic observation for the same class/location merge into ONE
      task with the SAST file:line:rule as the primary provenance
  (c) ungroupable observations each become their own task (singleton fallback,
      none dropped) — including when the grouper itself fails
  (d) exploitation_queue entries materialize with provenance attached
  (e) an empty / unbacked queue entry is not actionable (the exploit gate)
  (f) a reconciled task's provenance threads into a proof-gate finding dict so
      file:line:rule and a live PoC coexist on one published finding
"""

from __future__ import annotations

import json
from unittest.mock import patch

import pytest

from buggy.reconciliation import (
    Observation,
    SastSourceLocation,
    combine_observations,
    form_tasks,
    is_actionable,
    materialize_queue,
    parse_sarif_content,
    provenance_to_finding,
    queue_is_actionable,
)
from buggy.reconciliation.contracts import ExploitationQueueEntry
from buggy.reconciliation.form import DuplicateProducerError, default_grouper
from buggy.reconciliation.sast_intake import SarifDocumentError, parse_sarif_document
from buggy.tools.reporting.proof_gate import verify_finding

# ── Fixtures / helpers ─────────────────────────────────────────────────


def _sarif_result(
    rule_id: str,
    cwe: str | None,
    uri: str,
    line: int,
    *,
    level: str = "error",
    severity: str = "High",
    with_location: bool = True,
) -> dict:
    result: dict = {
        "ruleId": rule_id,
        "level": level,
        "message": {"text": f"{rule_id} finding"},
        "properties": {"severity": severity},
    }
    if cwe is not None:
        result["properties"]["cwe"] = cwe
    if with_location:
        result["locations"] = [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": uri},
                    "region": {
                        "startLine": line,
                        "startColumn": 5,
                        "snippet": {"text": f"line {line} source"},
                    },
                }
            }
        ]
    return result


def _sarif_document(results: list[dict], rules: list[dict] | None = None) -> dict:
    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {"driver": {"name": "Semgrep", "rules": rules or []}},
                "results": results,
            }
        ],
    }


def _sast_obs(
    producer_id: str,
    vuln_class: str,
    file: str,
    line: int,
    *,
    cwe: str = "CWE-89",
    rule_id: str = "sql-injection",
    priority: str = "P1",
    confidence: str = "high",
) -> Observation:
    return Observation(
        producer_id=producer_id,
        scan_source="sast",
        vuln_class=vuln_class,  # type: ignore[arg-type]
        title="SQL Injection",
        source_location=SastSourceLocation(
            file=file, line=line, rule_id=rule_id, cwe=cwe, column=5, snippet="q = f'...'"
        ),
        priority=priority,  # type: ignore[arg-type]
        confidence=confidence,  # type: ignore[arg-type]
        severity="high",
    )


def _dynamic_obs(
    producer_id: str,
    vuln_class: str,
    *,
    correlation_key: str | None = None,
    http_exchange_ids: tuple[str, ...] = (),
    evidence: str = "",
) -> Observation:
    return Observation(
        producer_id=producer_id,
        scan_source="dynamic",
        vuln_class=vuln_class,  # type: ignore[arg-type]
        title="Live injection",
        correlation_key=correlation_key,
        http_exchange_ids=http_exchange_ids,
        evidence=evidence,
        confidence="medium",
    )


class FakeCaido:
    """Mock proxy: ``existing`` ids confirm; ``unreachable`` ids raise."""

    def __init__(self, existing: set[str] | None = None) -> None:
        self.existing = existing or set()

    def view_request(self, request_id: str) -> dict[str, object]:
        if request_id in self.existing:
            return {"id": request_id, "request": {"method": "GET"}}
        return {}


# ── (a) SARIF → observations with class via CWE ────────────────────────


def test_sarif_parses_to_observations_with_class_via_cwe() -> None:
    doc = _sarif_document(
        results=[
            _sarif_result("sql-injection", "CWE-89", "app/db.py", 42),
            _sarif_result("ssrf-rule", "CWE-918", "app/net.py", 7),
            _sarif_result("xss-rule", "CWE-79", "app/view.py", 13),
        ]
    )
    intake = parse_sarif_document(doc)

    assert intake.declared_results == 3
    assert len(intake.observations) == 3
    by_class = {o.vuln_class: o for o in intake.observations}
    assert set(by_class) == {"injection", "ssrf", "xss"}

    sqli = by_class["injection"]
    assert sqli.scan_source == "sast"
    assert sqli.source_location is not None
    assert sqli.source_location.file == "app/db.py"
    assert sqli.source_location.line == 42
    assert sqli.source_location.cwe == "CWE-89"
    assert sqli.source_location.rule_id == "sql-injection"
    assert sqli.confidence == "high"  # SARIF level 'error'


def test_sarif_cwe_discovered_from_rule_tags_when_result_lacks_it() -> None:
    doc = _sarif_document(
        results=[_sarif_result("ssrf-rule", None, "app/net.py", 9)],
        rules=[{"id": "ssrf-rule", "properties": {"tags": ["security", "CWE-918"]}}],
    )
    intake = parse_sarif_document(doc)
    assert len(intake.observations) == 1
    assert intake.observations[0].vuln_class == "ssrf"


def test_sarif_drops_unusable_results_without_crashing() -> None:
    doc = _sarif_document(
        results=[
            _sarif_result("sql-injection", "CWE-89", "app/db.py", 42),  # good
            _sarif_result("no-cwe-rule", None, "app/x.py", 1),  # no CWE anywhere
            _sarif_result("no-loc", "CWE-79", "app/y.py", 1, with_location=False),
        ]
    )
    intake = parse_sarif_document(doc)
    assert intake.declared_results == 3
    assert len(intake.observations) == 1
    assert intake.drop_counts == {"no-cwe": 1, "no-location": 1}


def test_non_sarif_document_raises() -> None:
    with pytest.raises(SarifDocumentError):
        parse_sarif_content("not json at all {")
    with pytest.raises(SarifDocumentError):
        parse_sarif_document({"version": "1.0.0", "runs": []})


# ── (b) same class/location: SAST becomes primary provenance ───────────


def test_sast_and_dynamic_same_bug_merge_into_one_task_sast_primary() -> None:
    sast = _sast_obs("sast:0", "injection", "app/db.py", 42)
    dynamic = _dynamic_obs(
        "dynamic:0",
        "injection",
        correlation_key="app/db.py:42",
        http_exchange_ids=("1001",),
        evidence="500 on payload",
    )
    observations = combine_observations([sast], [dynamic])
    tasks_by_class = form_tasks(observations)

    assert set(tasks_by_class) == {"injection"}
    injection_tasks = tasks_by_class["injection"]
    assert len(injection_tasks) == 1  # merged into ONE task

    task = injection_tasks[0]
    assert task.task_id == "INJ-01"
    # SAST evidence is the primary record...
    assert task.primary.producer_id == "sast:0"
    assert task.primary.scan_source == "sast"
    # ...and the dynamic finding survives as corroboration.
    assert len(task.merged_from) == 1
    assert task.merged_from[0].producer_id == "dynamic:0"
    # Authoritative provenance is the SAST file:line:rule, verbatim.
    assert task.provenance is not None
    assert (task.provenance.file, task.provenance.line, task.provenance.rule_id) == (
        "app/db.py",
        42,
        "sql-injection",
    )
    # Live corroboration is carried onto the task.
    assert task.http_exchange_ids == ("1001",)


def test_sast_stays_primary_even_when_dynamic_seen_first() -> None:
    dynamic = _dynamic_obs("dynamic:0", "injection", correlation_key="app/db.py:42")
    sast = _sast_obs("sast:0", "injection", "app/db.py", 42)
    # dynamic first in the batch — primary selection is by preference, not order.
    tasks = form_tasks(combine_observations([dynamic], [sast]))["injection"]
    assert len(tasks) == 1
    assert tasks[0].primary.producer_id == "sast:0"


def test_strongest_priority_and_confidence_win_across_group() -> None:
    strong = _sast_obs("sast:0", "injection", "app/db.py", 42, priority="P1", confidence="high")
    weak = _sast_obs(
        "sast:1",
        "injection",
        "app/db.py",
        42,
        priority="P3",
        confidence="low",
        rule_id="weak-rule",
        cwe="CWE-89",
    )
    # Same file:line → one group of two SAST members.
    tasks = form_tasks(combine_observations([weak, strong]))["injection"]
    assert len(tasks) == 1
    assert tasks[0].priority == "P1"
    assert tasks[0].confidence == "high"


# ── (c) ungroupable observations → singleton fallback, none dropped ────


def test_distinct_locations_each_become_own_task() -> None:
    a = _sast_obs("sast:0", "injection", "app/a.py", 1)
    b = _sast_obs("sast:1", "injection", "app/b.py", 2, rule_id="r2")
    c = _sast_obs("sast:2", "injection", "app/c.py", 3, rule_id="r3")
    tasks = form_tasks(combine_observations([a, b, c]))["injection"]
    assert len(tasks) == 3
    # every input survives as exactly one task primary — none dropped
    primaries = {t.primary.producer_id for t in tasks}
    assert primaries == {"sast:0", "sast:1", "sast:2"}


def test_singleton_fallback_when_grouper_raises_drops_nothing() -> None:
    def broken_grouper(_observations):  # type: ignore[no-untyped-def]
        raise RuntimeError("grouper exploded")

    obs = [
        _sast_obs("sast:0", "injection", "app/a.py", 1),
        _sast_obs("sast:1", "injection", "app/b.py", 2, rule_id="r2"),
    ]
    tasks = form_tasks(obs, grouper=broken_grouper)["injection"]
    assert len(tasks) == 2
    assert {t.primary.producer_id for t in tasks} == {"sast:0", "sast:1"}


def test_singleton_fallback_when_grouper_drops_an_observation() -> None:
    def dropping_grouper(observations):  # type: ignore[no-untyped-def]
        # returns a partition missing the last observation → invalid → fallback
        return [(observations[0],)]

    obs = [
        _sast_obs("sast:0", "injection", "app/a.py", 1),
        _sast_obs("sast:1", "injection", "app/b.py", 2, rule_id="r2"),
    ]
    tasks = form_tasks(obs, grouper=dropping_grouper)["injection"]
    # fallback restores every observation as its own task
    assert {t.primary.producer_id for t in tasks} == {"sast:0", "sast:1"}


def test_duplicate_producer_id_is_rejected() -> None:
    a = _sast_obs("sast:0", "injection", "app/a.py", 1)
    b = _sast_obs("sast:0", "xss", "app/b.py", 2)  # same producer_id
    with pytest.raises(DuplicateProducerError):
        combine_observations([a], [b])


# ── (d) exploitation_queue entries materialize with provenance ─────────


def test_queue_entries_materialize_with_provenance() -> None:
    sast = _sast_obs("sast:0", "injection", "app/db.py", 42)
    dynamic = _dynamic_obs(
        "dynamic:0", "injection", correlation_key="app/db.py:42", http_exchange_ids=("7",)
    )
    tasks_by_class = form_tasks(combine_observations([sast], [dynamic]))
    queue = materialize_queue(tasks_by_class)

    assert set(queue) == {"injection"}
    entries = queue["injection"]
    assert len(entries) == 1
    entry = entries[0]
    assert entry.task_id == "INJ-01"
    assert entry.provenance is not None
    assert entry.provenance.file == "app/db.py"
    assert entry.provenance.line == 42
    assert entry.provenance.rule_id == "sql-injection"
    assert entry.corroboration_count == 1
    assert entry.http_exchange_ids == ("7",)
    assert is_actionable(entry) is True
    assert queue_is_actionable(entries) is True


# ── (e) empty / unbacked queue entry is not actionable ─────────────────


def test_unbacked_entry_is_not_actionable() -> None:
    # dynamic-only finding with no provenance, no exchange ids, no evidence
    bare = _dynamic_obs("dynamic:0", "xss")
    queue = materialize_queue(form_tasks([bare]))
    entry = queue["xss"][0]
    assert entry.provenance is None
    assert entry.validated is False
    assert is_actionable(entry) is False
    assert queue_is_actionable(queue["xss"]) is False


def test_empty_queue_is_not_actionable() -> None:
    assert queue_is_actionable([]) is False


def test_invalid_entry_fields_fail_validation() -> None:
    # hand-built entry with a backing location but a blank task id → not valid
    entry = ExploitationQueueEntry(
        task_id="",
        vuln_class="injection",
        title="x",
        priority="P1",
        confidence="high",
        severity="high",
        provenance=SastSourceLocation("app/db.py", 42, "r", "CWE-89"),
        corroboration_count=0,
    )
    assert entry.validated is False


# ── (f) provenance threads into a proof-gate finding (file:line:rule + PoC) ──


def test_provenance_threads_into_proof_gate_finding_with_live_poc() -> None:
    sast = _sast_obs("sast:0", "injection", "app/db.py", 42)
    dynamic = _dynamic_obs("dynamic:0", "injection", correlation_key="app/db.py:42")
    task = form_tasks(combine_observations([sast], [dynamic]))["injection"][0]

    # The exploit lane supplies the live PoC; provenance is threaded from the task.
    finding = provenance_to_finding(
        task,
        poc_script_code="curl -X POST --data \"id=1' OR '1'='1\" http://t/x",
        poc_description="Inject via id param; observe boolean-based extraction.",
        evidence="Response differs on ' OR '1'='1 vs ' OR '1'='2",
        http_exchange_ids=["1001"],
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        target="http://t/x",
    )

    # Provenance (static) and PoC (dynamic) coexist on the same dict.
    assert finding["file"] == "app/db.py"
    assert finding["line"] == 42
    assert finding["rule_id"] == "sql-injection"
    assert finding["cwe"] == ["CWE-89"]
    assert finding["provenance_source"] == "sast"
    assert finding["poc_script_code"].startswith("curl")
    assert finding["http_exchange_ids"] == ["1001"]

    # The proof gate (strict) accepts it against a proxy that holds the cited id,
    # and never strips the provenance fields.
    result = verify_finding(finding, client=FakeCaido(existing={"1001"}), strict=True)
    assert result.accepted is True
    assert result.http_exchange_ids == ["1001"]

    # Simulate the publish seam: the node props carry file:line:rule alongside PoC.
    captured: dict = {}

    def fake_publish(engagement, node_fields, **_kwargs):  # type: ignore[no-untyped-def]
        captured.update(node_fields)
        return ("FIND-1", True)

    with patch("buggy.tools.reporting.kg_adapter.publish_finding_node", fake_publish):
        from buggy.tools.reporting import kg_adapter

        node_fields = {k: v for k, v in finding.items() if v not in (None, "")}
        node_fields["http_exchange_ids"] = result.http_exchange_ids or []
        kg_adapter.publish_finding_node("engagement-1", node_fields)

    assert captured["file"] == "app/db.py"
    assert captured["line"] == 42
    assert captured["rule_id"] == "sql-injection"
    assert captured["cwe"] == ["CWE-89"]
    assert captured["poc_script_code"].startswith("curl")  # PoC coexists
    assert captured["reconciliation_task_id"] == "INJ-01"


def test_dynamic_only_task_threads_without_provenance() -> None:
    dynamic = _dynamic_obs(
        "dynamic:0", "ssrf", http_exchange_ids=("9",), evidence="internal 169.254 hit"
    )
    task = form_tasks([dynamic])["ssrf"][0]
    finding = provenance_to_finding(
        task,
        poc_script_code="curl http://t/fetch?url=http://169.254.169.254/",
        poc_description="SSRF to metadata endpoint",
        evidence="Got IMDS response",
        http_exchange_ids=["9"],
    )
    assert "file" not in finding
    assert finding["provenance_source"] == "dynamic"
    assert finding["poc_script_code"].startswith("curl")


# ── default grouper sanity ─────────────────────────────────────────────


def test_reconcile_tool_end_to_end(tmp_path) -> None:  # type: ignore[no-untyped-def]
    from buggy.reconciliation import reconcile_sast_to_queue

    doc = _sarif_document(
        results=[
            _sarif_result("sql-injection", "CWE-89", "app/db.py", 42),
            _sarif_result("ssrf-rule", "CWE-918", "app/net.py", 7),
        ]
    )
    sarif_path = tmp_path / "scan.sarif"
    sarif_path.write_text(json.dumps(doc), encoding="utf-8")
    dynamic = json.dumps(
        [
            {
                "vuln_class": "injection",
                "title": "live sqli",
                "correlation_key": "app/db.py:42",
                "http_exchange_ids": ["1001"],
                "evidence": "boolean-based diff",
            }
        ]
    )

    raw = reconcile_sast_to_queue.invoke(
        {"sarif_path": str(sarif_path), "dynamic_findings_json": dynamic}
    )
    payload = json.loads(raw)
    assert payload["success"] is True
    # injection merged (1 entry, corroborated); ssrf stands alone.
    injection = payload["classes"]["injection"]
    assert injection["entries"] == 1
    assert injection["actionable"] == 1
    item = injection["items"][0]
    assert item["corroboration_count"] == 1
    assert item["provenance"] == {
        "file": "app/db.py",
        "line": 42,
        "rule_id": "sql-injection",
        "cwe": "CWE-89",
    }
    assert payload["classes"]["ssrf"]["entries"] == 1


def test_reconcile_tool_reports_bad_sarif(tmp_path) -> None:  # type: ignore[no-untyped-def]
    from buggy.reconciliation import reconcile_sast_to_queue

    bad = tmp_path / "bad.sarif"
    bad.write_text("{not json", encoding="utf-8")
    payload = json.loads(reconcile_sast_to_queue.invoke({"sarif_path": str(bad)}))
    assert payload["success"] is False
    assert "invalid SARIF" in payload["error"]


def test_default_grouper_merges_only_matching_keys() -> None:
    a = _sast_obs("sast:0", "injection", "app/a.py", 1)
    b = _dynamic_obs("dynamic:0", "injection", correlation_key="app/a.py:1")
    c = _dynamic_obs("dynamic:1", "injection", correlation_key="app/other.py:9")
    groups = default_grouper([a, b, c])
    sizes = sorted(len(g) for g in groups)
    assert sizes == [1, 2]
