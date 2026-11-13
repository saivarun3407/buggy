"""Exploitation queue: materialize reconciled tasks and gate the exploit lane.

Two jobs:

1. **Materialize.** Turn per-class reconciled tasks into
   :class:`ExploitationQueueEntry` records, each backed by its correlated
   provenance, keyed by class — the shape the exploit lane consumes.
2. **Thread provenance into the proof gate.** :func:`provenance_to_finding`
   builds the finding dict the exploit flow hands to Phase 3's
   ``proof_gate.verify_finding`` / ``kg_adapter.publish_finding_node`` so the
   authoritative ``file:line:rule`` is recorded *alongside* the mandatory live
   PoC — static provenance and dynamic proof coexist on one published finding.

The provenance keys (``file``, ``line``, ``cwe``) match
``tools/reporting/sarif.py`` exactly, so a published finding round-trips back
out through the spine's SARIF emitter with its source location intact.

Gating mirrors the donor's rule: the exploit lane runs a class only on a
non-empty, validated reconciled queue (:func:`queue_is_actionable`).

Clean-room queue design.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from langchain_core.tools import tool

from buggy.reconciliation.contracts import (
    ExploitationQueueEntry,
    Observation,
    ReconciliationTask,
    SastSourceLocation,
    VulnClass,
)
from buggy.reconciliation.cwe_map import class_for_cwe
from buggy.reconciliation.form import combine_observations, form_tasks
from buggy.reconciliation.sast_intake import parse_sarif_content

# ── Materialize ────────────────────────────────────────────────────────


def entry_from_task(task: ReconciliationTask) -> ExploitationQueueEntry:
    """Build one queue entry, carrying the task's correlated provenance."""
    return ExploitationQueueEntry(
        task_id=task.task_id,
        vuln_class=task.vuln_class,
        title=task.primary.title,
        priority=task.priority,
        confidence=task.confidence,
        severity=task.primary.severity,
        provenance=task.provenance,
        corroboration_count=len(task.merged_from),
        http_exchange_ids=task.http_exchange_ids,
        evidence=task.primary.evidence,
    )


def materialize_queue(
    tasks_by_class: dict[VulnClass, list[ReconciliationTask]],
) -> dict[VulnClass, list[ExploitationQueueEntry]]:
    """Materialize every class's tasks into exploitation-queue entries."""
    return {
        vuln_class: [entry_from_task(task) for task in tasks]
        for vuln_class, tasks in tasks_by_class.items()
    }


# ── Gate ───────────────────────────────────────────────────────────────


def is_actionable(entry: ExploitationQueueEntry) -> bool:
    """An entry is actionable only when it is validated (backed by evidence)."""
    return entry.validated


def actionable_entries(
    entries: list[ExploitationQueueEntry],
) -> list[ExploitationQueueEntry]:
    return [entry for entry in entries if is_actionable(entry)]


def queue_is_actionable(entries: list[ExploitationQueueEntry]) -> bool:
    """The exploit lane runs a class only on a non-empty, validated queue."""
    return any(is_actionable(entry) for entry in entries)


# ── Thread provenance into a proof-gate finding ────────────────────────


def provenance_to_finding(
    task: ReconciliationTask,
    *,
    poc_script_code: str = "",
    poc_description: str = "",
    evidence: str = "",
    http_exchange_ids: list[str] | None = None,
    severity: str | None = None,
    cvss_vector: str = "",
    target: str = "",
    summary: str = "",
) -> dict[str, Any]:
    """Build the finding dict the exploit flow passes to the proof gate.

    The live PoC fields (``poc_script_code`` / ``poc_description`` /
    ``evidence`` / ``http_exchange_ids``) are supplied by the exploit lane once
    it has actually exercised the bug; the SAST provenance
    (``file``/``line``/``rule_id``/``cwe``) is threaded in from the reconciled
    task. The proof gate validates the live proof and leaves the provenance
    untouched, so a gate-approved finding carries *both*, and
    ``publish_finding_node`` persists the location as node props the SARIF
    emitter reads back.

    When the exploit lane cites no live exchange ids of its own, the task's
    correlated ids are used so corroboration is not lost.
    """
    finding: dict[str, Any] = {
        "title": task.primary.title,
        "severity": severity if severity is not None else (task.primary.severity or "info"),
        "poc_script_code": poc_script_code,
        "poc_description": poc_description,
        "evidence": evidence or task.primary.evidence,
        "http_exchange_ids": (
            http_exchange_ids if http_exchange_ids is not None else list(task.http_exchange_ids)
        ),
        "cvss_vector": cvss_vector,
        "target": target,
        "summary": summary,
        # ── reconciliation provenance (round-trips through sarif.py) ──
        "reconciliation_task_id": task.task_id,
        "vuln_class": task.vuln_class,
        "corroboration_count": len(task.merged_from),
    }

    provenance: SastSourceLocation | None = task.provenance
    if provenance is not None:
        finding["file"] = provenance.file
        finding["line"] = provenance.line
        finding["column"] = provenance.column
        finding["rule_id"] = provenance.rule_id
        finding["cwe"] = [provenance.cwe]
        finding["provenance_source"] = "sast"
        if provenance.snippet:
            finding["code_snippet"] = provenance.snippet
    else:
        finding["provenance_source"] = "dynamic"

    return finding


# ── Dynamic-lane intake helper ─────────────────────────────────────────


def dynamic_observations_from_dicts(
    raw: list[dict[str, Any]],
    *,
    producer_prefix: str = "dynamic",
) -> list[Observation]:
    """Normalize live-lane finding dicts into :class:`Observation`.

    Each dict may declare ``vuln_class`` directly or a ``cwe`` to route from;
    ``correlation_key`` (e.g. a ``file:line`` the dynamic lane resolved, or an
    endpoint signature) lets a live finding join a static one in task
    formation. Findings with neither a class nor a resolvable CWE are skipped.
    """
    observations: list[Observation] = []
    index = 0
    for item in raw:
        if not isinstance(item, dict):
            continue
        vuln_class = item.get("vuln_class")
        if vuln_class not in {"injection", "xss", "auth", "authz", "ssrf", "miscellaneous"}:
            cwe = item.get("cwe")
            route = class_for_cwe(cwe) if isinstance(cwe, str) else None
            if route is None:
                continue
            vuln_class = route.vuln_class
        exchange_ids = item.get("http_exchange_ids")
        if not isinstance(exchange_ids, list):
            exchange_ids = []
        observations.append(
            Observation(
                producer_id=f"{producer_prefix}:{index}",
                scan_source="dynamic",
                vuln_class=vuln_class,  # type: ignore[arg-type]
                title=str(item.get("title") or vuln_class),
                severity=item.get("severity") if isinstance(item.get("severity"), str) else None,
                message=str(item.get("message") or ""),
                correlation_key=(
                    str(item["correlation_key"]) if item.get("correlation_key") else None
                ),
                http_exchange_ids=tuple(str(x) for x in exchange_ids),
                evidence=str(item.get("evidence") or ""),
            )
        )
        index += 1
    return observations


# ── @tool entry for the exploit flow ───────────────────────────────────


@tool
def reconcile_sast_to_queue(sarif_path: str, dynamic_findings_json: str = "") -> str:
    """Reconcile a SAST SARIF report with live findings into exploitation queues.

    Parses the SARIF at ``sarif_path`` into static observations, optionally
    merges live findings from ``dynamic_findings_json`` (a JSON array of
    ``{vuln_class|cwe, title, correlation_key?, http_exchange_ids?, evidence?}``
    objects), forms per-class reconciled tasks (SAST ``file:line:rule`` as the
    primary provenance), and materializes per-class exploitation queues.

    Returns a JSON summary: per-class entry counts, how many are actionable
    (gate), and each entry's task id + provenance. Each item also carries a
    ``finding_template``: the proof-gate finding dict pre-seeded with the
    SAST ``file``/``line``/``cwe`` provenance — the exploit lane fills the
    live PoC fields (``poc_script_code``/``poc_description``/``evidence``/
    ``http_exchange_ids``) after exercising the bug and hands the dict to
    the proof gate. The exploit lane runs a class only when its queue is
    actionable.

    Args:
        sarif_path: Path to a SARIF 2.1.0 log from the SAST lane.
        dynamic_findings_json: Optional JSON array of live-lane findings to
            correlate; empty string means SAST-only reconciliation.

    Returns:
        JSON. On success: ``{success: true, classes: {<class>: {entries,
        actionable, items: [...]}}, dropped: {...}}``. On a SARIF document
        error: ``{success: false, error: "..."}``.
    """
    try:
        content = Path(sarif_path).read_text(encoding="utf-8")
    except OSError as exc:
        return json.dumps({"success": False, "error": f"cannot read SARIF: {exc}"})

    try:
        intake = parse_sarif_content(content)
    except Exception as exc:  # noqa: BLE001 — surfaced to the agent in-band
        return json.dumps({"success": False, "error": f"invalid SARIF: {exc}"})

    dynamic: list[Observation] = []
    if dynamic_findings_json.strip():
        try:
            raw = json.loads(dynamic_findings_json)
            if isinstance(raw, list):
                dynamic = dynamic_observations_from_dicts(raw)
        except (json.JSONDecodeError, ValueError):
            dynamic = []

    observations = combine_observations(intake.observations, dynamic)
    tasks_by_class = form_tasks(observations)
    queue = materialize_queue(tasks_by_class)

    # materialize_queue maps tasks to entries 1:1, preserving order — the
    # per-item finding_template threads each task's provenance into a
    # proof-gate-ready finding dict (provenance_to_finding) the exploit
    # lane fills with live PoC fields and hands to verify_finding.
    classes_payload: dict[str, Any] = {}
    for vuln_class, entries in queue.items():
        tasks = tasks_by_class.get(vuln_class, [])
        items = []
        for index, entry in enumerate(entries):
            task = tasks[index] if index < len(tasks) else None
            items.append(
                {
                    "task_id": entry.task_id,
                    "title": entry.title,
                    "priority": entry.priority,
                    "confidence": entry.confidence,
                    "corroboration_count": entry.corroboration_count,
                    "provenance": (
                        {
                            "file": entry.provenance.file,
                            "line": entry.provenance.line,
                            "rule_id": entry.provenance.rule_id,
                            "cwe": entry.provenance.cwe,
                        }
                        if entry.provenance is not None
                        else None
                    ),
                    "actionable": is_actionable(entry),
                    "finding_template": (provenance_to_finding(task) if task is not None else None),
                }
            )
        classes_payload[vuln_class] = {
            "entries": len(entries),
            "actionable": len(actionable_entries(entries)),
            "queue_actionable": queue_is_actionable(entries),
            "items": items,
        }

    return json.dumps(
        {
            "success": True,
            "classes": classes_payload,
            "dropped": intake.drop_counts,
            "declared_results": intake.declared_results,
        },
        default=str,
    )


# The reconciliation tool is exported as its own bundle rather than folded into
# any existing agent surface. Phase 5 attaches it: ``RECONCILIATION_TOOLS`` is
# wired onto the exploit agent's standard tool set
# (``agents/standard/exploit.py``), so the exploit lane calls
# ``reconcile_sast_to_queue`` — which runs ``form_tasks`` between the SAST lane
# and the exploit lane — and reads the per-class ``queue_is_actionable`` gate
# from its output before acting on a class.
RECONCILIATION_TOOLS = [reconcile_sast_to_queue]


__all__ = [
    "RECONCILIATION_TOOLS",
    "actionable_entries",
    "dynamic_observations_from_dicts",
    "entry_from_task",
    "is_actionable",
    "materialize_queue",
    "provenance_to_finding",
    "queue_is_actionable",
    "reconcile_sast_to_queue",
]
