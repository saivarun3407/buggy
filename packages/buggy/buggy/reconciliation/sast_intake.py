"""SAST lane intake: SARIF 2.1.0 → normalized :class:`Observation` list.

This is the static half of reconciliation. It reads a standard SARIF 2.1.0 log
(as emitted by Semgrep, CodeQL, the spine's own
``tools/reporting/sarif.py``, or any SARIF-conformant engine), resolves each
result's vulnerability class from its CWE, and copies the exact
``file:line:column:rule`` into an authoritative :class:`SastSourceLocation`.

Design choices, clean-room:

* **Drop, don't crash.** A result the parser cannot normalize (no CWE, no
  usable location, bad level) is dropped with a recorded reason; one bad
  result never discards the rest. Only a document that is not SARIF at all
  raises :class:`SarifDocumentError`.
* **Generic contract, not a proprietary profile.** Unlike the donor's single
  in-house SARIF shape, this accepts ordinary SARIF: CWE is discovered from
  the result or its rule (``properties.cwe``, ``tags`` of the ``CWE-NNN``
  form, or a CWE-shaped ``ruleId``), and ``codeFlows`` are optional.
* **Spine alignment.** The SARIF version is pinned to the spine's own
  ``SARIF_VERSION`` and the location field names (``file``/``line``/``cwe``)
  mirror ``tools/reporting/sarif.py`` so provenance round-trips back out
  through the same emitter unchanged.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, TypeGuard

from buggy.reconciliation.contracts import (
    Confidence,
    Observation,
    SastSourceLocation,
)
from buggy.reconciliation.cwe_map import class_for_cwe, normalize_cwe
from buggy.tools.reporting.sarif import SARIF_VERSION

#: SARIF ``level`` → confidence band. A static engine's ``error`` is a stronger
#: signal than a ``note``; this feeds the merge's strongest-wins selection.
_LEVEL_TO_CONFIDENCE: dict[str, Confidence] = {
    "error": "high",
    "warning": "medium",
    "note": "low",
    "none": "low",
}

_VALID_LEVELS = frozenset(_LEVEL_TO_CONFIDENCE)

#: Drop reasons, kept as a small closed set for the intake report.
DropReason = str  # one of: "no-cwe", "no-location", "bad-level", "malformed"


class SarifDocumentError(ValueError):
    """The supplied bytes are not a usable SARIF 2.1.0 log at all."""


@dataclass(frozen=True, slots=True)
class DroppedResult:
    """One SARIF result that could not be normalized, and why."""

    reason: DropReason
    rule_id: str | None = None


@dataclass(frozen=True, slots=True)
class SastIntake:
    """Outcome of parsing one SARIF log."""

    observations: tuple[Observation, ...]
    dropped: tuple[DroppedResult, ...] = field(default_factory=tuple)
    declared_results: int = 0

    @property
    def drop_counts(self) -> dict[DropReason, int]:
        counts: dict[DropReason, int] = {}
        for item in self.dropped:
            counts[item.reason] = counts.get(item.reason, 0) + 1
        return counts


def _is_record(value: Any) -> TypeGuard[dict[str, Any]]:
    return isinstance(value, dict)


def _result_rule_id(result: dict[str, Any]) -> str | None:
    rule_id = result.get("ruleId")
    return rule_id if isinstance(rule_id, str) and rule_id else None


def _extract_cwe(result: dict[str, Any], rule: dict[str, Any] | None) -> str | None:
    """Discover a canonical CWE id from the result or its rule metadata.

    Search order (first hit wins): the result's ``properties.cwe``; the rule's
    ``properties.cwe``; any ``CWE-NNN`` entry in the rule's ``properties.tags``;
    a CWE-shaped ``ruleId``; a CWE-shaped rule ``id``.
    """
    candidates: list[Any] = []
    props = result.get("properties")
    if _is_record(props):
        candidates.append(props.get("cwe"))
    if rule is not None:
        rule_props = rule.get("properties")
        if _is_record(rule_props):
            candidates.append(rule_props.get("cwe"))
            tags = rule_props.get("tags")
            if isinstance(tags, list):
                candidates.extend(tags)
    candidates.append(result.get("ruleId"))
    if rule is not None:
        candidates.append(rule.get("id"))

    for candidate in candidates:
        if isinstance(candidate, str):
            canonical = normalize_cwe(candidate)
            if canonical is not None:
                return canonical
        elif isinstance(candidate, list):
            for entry in candidate:
                if isinstance(entry, str):
                    canonical = normalize_cwe(entry)
                    if canonical is not None:
                        return canonical
    return None


def _primary_location(result: dict[str, Any]) -> tuple[str, int, int, str] | None:
    """Pull ``(file, line, column, snippet)`` from the first physical location."""
    locations = result.get("locations")
    if not isinstance(locations, list) or not locations:
        return None
    first = locations[0]
    if not _is_record(first):
        return None
    physical = first.get("physicalLocation")
    if not _is_record(physical):
        return None
    artifact = physical.get("artifactLocation")
    region = physical.get("region")
    if not _is_record(artifact) or not _is_record(region):
        return None
    uri = artifact.get("uri")
    start_line = region.get("startLine")
    if not isinstance(uri, str) or not uri.strip():
        return None
    if not isinstance(start_line, int) or isinstance(start_line, bool) or start_line <= 0:
        return None
    start_column = region.get("startColumn")
    column = (
        start_column
        if isinstance(start_column, int) and not isinstance(start_column, bool) and start_column > 0
        else 1
    )
    snippet_text = ""
    snippet = region.get("snippet")
    if _is_record(snippet) and isinstance(snippet.get("text"), str):
        snippet_text = snippet["text"]
    return uri.strip(), start_line, column, snippet_text


def _result_severity(result: dict[str, Any]) -> str | None:
    props = result.get("properties")
    if _is_record(props):
        severity = props.get("severity")
        if isinstance(severity, str) and severity.strip():
            return severity.strip().lower()
    return None


def _result_message(result: dict[str, Any]) -> str:
    message = result.get("message")
    if _is_record(message) and isinstance(message.get("text"), str):
        return message["text"]
    return ""


def _build_rule_index(run: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Map ``rule id -> rule object`` for the run's tool driver + extensions."""
    index: dict[str, dict[str, Any]] = {}
    tool = run.get("tool")
    if not _is_record(tool):
        return index
    components: list[Any] = []
    driver = tool.get("driver")
    if _is_record(driver):
        components.append(driver)
    extensions = tool.get("extensions")
    if isinstance(extensions, list):
        components.extend(extensions)
    for component in components:
        if not _is_record(component):
            continue
        rules = component.get("rules")
        if not isinstance(rules, list):
            continue
        for rule in rules:
            if _is_record(rule) and isinstance(rule.get("id"), str):
                index.setdefault(rule["id"], rule)
    return index


def parse_sarif_document(document: Any, *, producer_prefix: str = "sast") -> SastIntake:
    """Normalize an already-parsed SARIF document (a ``dict``).

    Raises :class:`SarifDocumentError` only for a structurally non-SARIF
    document; individual unusable results are dropped with a reason.
    """
    if not _is_record(document):
        raise SarifDocumentError("SARIF document is not a JSON object")
    if document.get("version") != SARIF_VERSION:
        raise SarifDocumentError(f"SARIF document version must be {SARIF_VERSION!r}")
    runs = document.get("runs")
    if not isinstance(runs, list) or not runs:
        raise SarifDocumentError("SARIF document has no runs")

    observations: list[Observation] = []
    dropped: list[DroppedResult] = []
    declared = 0
    index = 0

    for run in runs:
        if not _is_record(run):
            raise SarifDocumentError("SARIF run is not an object")
        results = run.get("results")
        if results is None:
            continue
        if not isinstance(results, list):
            raise SarifDocumentError("SARIF run 'results' is not an array")
        rule_index = _build_rule_index(run)

        for result in results:
            declared += 1
            if not _is_record(result):
                dropped.append(DroppedResult("malformed"))
                continue
            rule_id = _result_rule_id(result)
            rule = rule_index.get(rule_id) if rule_id is not None else None

            level = result.get("level")
            # SARIF makes 'level' optional (default 'warning'); honour that
            # rather than dropping a result that merely omitted it.
            if level is None:
                level = "warning"
            if not isinstance(level, str) or level not in _VALID_LEVELS:
                dropped.append(DroppedResult("bad-level", rule_id))
                continue

            cwe = _extract_cwe(result, rule)
            if cwe is None:
                dropped.append(DroppedResult("no-cwe", rule_id))
                continue
            route = class_for_cwe(cwe)
            if route is None:  # unreachable once cwe is canonical, but defensive
                dropped.append(DroppedResult("no-cwe", rule_id))
                continue

            location = _primary_location(result)
            if location is None:
                dropped.append(DroppedResult("no-location", rule_id))
                continue
            file_path, line, column, snippet = location

            source_location = SastSourceLocation(
                file=file_path,
                line=line,
                column=column,
                rule_id=rule_id or cwe,
                cwe=cwe,
                snippet=snippet,
            )
            observations.append(
                Observation(
                    producer_id=f"{producer_prefix}:{index}",
                    scan_source="sast",
                    vuln_class=route.vuln_class,
                    title=route.name,
                    source_location=source_location,
                    priority=route.priority,
                    confidence=_LEVEL_TO_CONFIDENCE[level],
                    severity=_result_severity(result),
                    message=_result_message(result),
                )
            )
            index += 1

    return SastIntake(
        observations=tuple(observations),
        dropped=tuple(dropped),
        declared_results=declared,
    )


def parse_sarif_content(content: str, *, producer_prefix: str = "sast") -> SastIntake:
    """Parse SARIF text, then normalize it via :func:`parse_sarif_document`."""
    try:
        document = json.loads(content)
    except (json.JSONDecodeError, ValueError) as exc:
        raise SarifDocumentError("SARIF document is not valid JSON") from exc
    return parse_sarif_document(document, producer_prefix=producer_prefix)


__all__ = [
    "DropReason",
    "DroppedResult",
    "SarifDocumentError",
    "SastIntake",
    "parse_sarif_content",
    "parse_sarif_document",
]
