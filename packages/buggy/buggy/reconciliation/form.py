"""Task formation: group normalized observations into per-class tasks.

This is the join. Observations from both lanes are partitioned by class, each
class's observations are grouped so that same-bug findings land together, and
every group is collapsed (:mod:`buggy.reconciliation.merge`) into one
exploitation task whose primary record is the SAST evidence.

Grouping is pluggable. The default grouper is deterministic — it keys on
:meth:`Observation.group_key` (an explicit correlation key, else a SAST
``file:line`` signature, else a per-producer singleton). A production
deployment can inject an LLM-backed grouper instead; whatever it does, the
**singleton fallback** guarantees that if grouping fails or returns an
inconsistent partition, every observation still becomes its own task — an
observation is never silently dropped.

Clean-room form design (original implementation;
``observations.ts`` (AGPL) singleton-fallback design.

Orchestrator wiring (Phase 5): ``form_tasks`` is reached through the
``reconcile_sast_to_queue`` ``@tool`` (``buggy.reconciliation.queue``),
which is attached to the exploit agent's standard tool set
(``agents/standard/exploit.py``). The exploit lane calls it after the SAST lane
and reads the per-class ``queue_is_actionable`` gate before acting on a class.
"""

from __future__ import annotations

from collections import OrderedDict
from collections.abc import Callable, Sequence

from buggy.reconciliation.contracts import (
    ALL_CLASSES,
    Observation,
    ReconciliationTask,
    VulnClass,
)
from buggy.reconciliation.merge import build_tasks

#: A grouper takes one class's observations and returns same-bug groups.
Grouper = Callable[[Sequence[Observation]], list[tuple[Observation, ...]]]


class DuplicateProducerError(ValueError):
    """Two observations in one batch share a ``producer_id``."""


def combine_observations(*lanes: Sequence[Observation]) -> list[Observation]:
    """Concatenate lane outputs under one global unique-producer-id contract.

    A duplicate ``producer_id`` means two findings would be indistinguishable
    downstream, so it is a hard error rather than a silent collision.
    """
    combined: list[Observation] = []
    seen: set[str] = set()
    for lane in lanes:
        for observation in lane:
            if observation.producer_id in seen:
                raise DuplicateProducerError(f"duplicate producer_id: {observation.producer_id!r}")
            seen.add(observation.producer_id)
            combined.append(observation)
    return combined


def default_grouper(observations: Sequence[Observation]) -> list[tuple[Observation, ...]]:
    """Group by :meth:`Observation.group_key`, preserving first-seen order."""
    buckets: "OrderedDict[tuple[VulnClass, str], list[Observation]]" = OrderedDict()
    for observation in observations:
        buckets.setdefault(observation.group_key(), []).append(observation)
    return [tuple(members) for members in buckets.values()]


def _singletons(observations: Sequence[Observation]) -> list[tuple[Observation, ...]]:
    return [(observation,) for observation in observations]


def _partition_is_valid(
    groups: list[tuple[Observation, ...]],
    observations: Sequence[Observation],
) -> bool:
    """A grouping is valid iff it covers every producer id exactly once.

    Guards the never-drop invariant: a grouper that omits, duplicates, or
    invents an observation is rejected and the caller falls back to singletons.
    """
    expected = {o.producer_id for o in observations}
    seen: set[str] = set()
    for group in groups:
        if not group:
            return False
        for member in group:
            if member.producer_id in seen or member.producer_id not in expected:
                return False
            seen.add(member.producer_id)
    return seen == expected


def _group_class(
    observations: Sequence[Observation],
    grouper: Grouper,
) -> list[tuple[Observation, ...]]:
    """Run ``grouper`` for one class, with the singleton fallback around it."""
    try:
        groups = grouper(observations)
    except Exception:  # noqa: BLE001 — any grouper failure must not drop findings
        return _singletons(observations)
    if not _partition_is_valid(groups, observations):
        return _singletons(observations)
    return groups


def form_tasks(
    observations: Sequence[Observation],
    *,
    grouper: Grouper | None = None,
) -> dict[VulnClass, list[ReconciliationTask]]:
    """Form reconciled exploitation tasks, keyed by vulnerability class.

    Observations are partitioned by class, grouped (with singleton fallback),
    and collapsed into dense-referenced tasks. Classes with no observations are
    omitted from the result.
    """
    active_grouper = grouper or default_grouper

    by_class: dict[VulnClass, list[Observation]] = {}
    for observation in observations:
        by_class.setdefault(observation.vuln_class, []).append(observation)

    tasks_by_class: dict[VulnClass, list[ReconciliationTask]] = {}
    for vuln_class in ALL_CLASSES:
        class_observations = by_class.get(vuln_class)
        if not class_observations:
            continue
        groups = _group_class(class_observations, active_grouper)
        tasks_by_class[vuln_class] = build_tasks(groups, vuln_class)
    return tasks_by_class


__all__ = [
    "DuplicateProducerError",
    "Grouper",
    "combine_observations",
    "default_grouper",
    "form_tasks",
]
