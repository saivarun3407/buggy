"""Deterministic collapse of observation groups into reconciled tasks.

Given groups of observations already judged to describe the same bug, this
module collapses each group into one :class:`ReconciliationTask`:

* the **primary** is the ``preferred`` (SAST) member when the group has one, so
  the task keeps an exact ``file:line:rule``; the rest fold in as
  ``merged_from`` corroboration;
* the task's ``priority`` and ``confidence`` are the *strongest* across the
  whole group — a weak duplicate never waters down a strong signal another
  producer already established;
* tasks are sorted by a total order (priority, confidence, producer id) and
  assigned dense per-class references (``INJ-01`` …), reproducibly.

Clean-room ordering/selection design (original
``reconciliation/materialize-core.ts`` (AGPL).
"""

from __future__ import annotations

from buggy.reconciliation.contracts import (
    REF_PREFIX,
    Confidence,
    Observation,
    Priority,
    ReconciliationTask,
    VulnClass,
)

_PRIORITY_ORDER: dict[str, int] = {"P1": 0, "P2": 1, "P3": 2}
_CONFIDENCE_ORDER: dict[str, int] = {"high": 0, "medium": 1, "low": 2}
_MISSING_RANK = 99


class EmptyGroupError(ValueError):
    """A group reached collapse with no members — a caller contract breach."""


def _rank(value: str | None, order: dict[str, int]) -> int:
    if value is None:
        return _MISSING_RANK
    return order.get(value, _MISSING_RANK)


def _strongest_priority(members: tuple[Observation, ...]) -> Priority | None:
    best: Priority | None = None
    best_rank = _MISSING_RANK + 1
    for member in members:
        rank = _rank(member.priority, _PRIORITY_ORDER)
        if member.priority is not None and rank < best_rank:
            best = member.priority
            best_rank = rank
    return best


def _strongest_confidence(members: tuple[Observation, ...]) -> Confidence | None:
    best: Confidence | None = None
    best_rank = _MISSING_RANK + 1
    for member in members:
        rank = _rank(member.confidence, _CONFIDENCE_ORDER)
        if member.confidence is not None and rank < best_rank:
            best = member.confidence
            best_rank = rank
    return best


def _primary_index(members: tuple[Observation, ...]) -> int:
    """Index of the group's primary: a ``preferred`` member outranks ``default``.

    Ties (e.g. two SAST members) resolve to the lowest producer id, so the
    choice is deterministic across runs.
    """
    best_index = 0
    best_key = (
        0 if members[0].primary_preference == "preferred" else 1,
        members[0].producer_id,
    )
    for index in range(1, len(members)):
        member = members[index]
        key = (
            0 if member.primary_preference == "preferred" else 1,
            member.producer_id,
        )
        if key < best_key:
            best_index = index
            best_key = key
    return best_index


def _build_task(members: tuple[Observation, ...], task_id: str) -> ReconciliationTask:
    if not members:
        raise EmptyGroupError("cannot collapse an empty observation group")
    primary_index = _primary_index(members)
    primary = members[primary_index]
    merged = tuple(m for i, m in enumerate(members) if i != primary_index)
    return ReconciliationTask(
        task_id=task_id,
        vuln_class=primary.vuln_class,
        primary=primary,
        merged_from=merged,
        priority=_strongest_priority(members),
        confidence=_strongest_confidence(members),
    )


def _sort_key(task: ReconciliationTask) -> tuple[int, int, str]:
    return (
        _rank(task.priority, _PRIORITY_ORDER),
        _rank(task.confidence, _CONFIDENCE_ORDER),
        task.primary.producer_id,
    )


def build_tasks(
    groups: list[tuple[Observation, ...]],
    vuln_class: VulnClass,
) -> list[ReconciliationTask]:
    """Collapse per-class groups, sort by the locked order, mint dense refs.

    Every group must be non-empty and belong to ``vuln_class``; task ids are
    assigned *after* sorting so ``INJ-01`` is always the highest-priority
    injection task regardless of input order.
    """
    pre_tasks = [_build_task(group, task_id="") for group in groups]
    pre_tasks.sort(key=_sort_key)

    prefix = REF_PREFIX[vuln_class]
    tasks: list[ReconciliationTask] = []
    for index, task in enumerate(pre_tasks, start=1):
        tasks.append(
            ReconciliationTask(
                task_id=f"{prefix}-{index:02d}",
                vuln_class=task.vuln_class,
                primary=task.primary,
                merged_from=task.merged_from,
                priority=task.priority,
                confidence=task.confidence,
            )
        )
    return tasks


__all__ = ["EmptyGroupError", "build_tasks"]
