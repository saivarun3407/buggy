"""Normalized observation contracts for white-box reconciliation.

Both lanes of the engagement reduce to one :class:`Observation`:

* a **static** SAST result parsed from SARIF, and
* a **dynamic** result from the live pentest lane.

The point of the common shape is the join: when a static finding and a live
finding describe the same underlying bug, reconciliation collapses them into a
single exploitation task whose *primary* record is the SAST evidence — because
only the static lane carries an exact ``file:line:rule`` the downstream report
and proof gate can cite. A dynamic finding corroborates but never overwrites
that provenance.

Clean-room design — the Python shapes
below are original; only the *design* (normalized observation, SAST-preferred
primary selection, class-keyed tasks) is carried over.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

# ── Closed vocabularies ────────────────────────────────────────────────

#: Which lane produced an observation.
ScanSource = Literal["sast", "dynamic"]

#: SAST priority band, copied from the CWE routing table.
Priority = Literal["P1", "P2", "P3"]

#: Confidence band — ordered high > medium > low for merge selection.
Confidence = Literal["high", "medium", "low"]

#: The six internal reconciliation classes. ``miscellaneous`` is the catch-all
#: that keeps an unrecognized-but-valid finding in the queue rather than
#: dropping it (see :func:`buggy.reconciliation.cwe_map.class_for_cwe`).
VulnClass = Literal["injection", "xss", "auth", "authz", "ssrf", "miscellaneous"]

ALL_CLASSES: tuple[VulnClass, ...] = (
    "injection",
    "xss",
    "auth",
    "authz",
    "ssrf",
    "miscellaneous",
)

#: Dense per-class reference prefix for minted task ids (``INJ-01`` …).
REF_PREFIX: dict[VulnClass, str] = {
    "injection": "INJ",
    "xss": "XSS",
    "auth": "AUTH",
    "authz": "AUTHZ",
    "ssrf": "SSRF",
    "miscellaneous": "MISC",
}


# ── Authoritative SAST provenance ──────────────────────────────────────


@dataclass(frozen=True, slots=True)
class SastSourceLocation:
    """Exact source location a static analyzer pinned a finding to.

    Copied verbatim out of the SARIF result (``file``/``line``/``column`` from
    the primary ``physicalLocation``; ``rule_id`` from the result's ``ruleId``;
    ``cwe`` from the rule/result CWE tag). This is the one piece of evidence a
    dynamic finding can never reconstruct, so it becomes a reconciled task's
    primary provenance and is threaded, unchanged, all the way into the
    published finding.
    """

    file: str
    line: int
    rule_id: str
    cwe: str
    column: int = 1
    snippet: str = ""

    def signature(self) -> str:
        """Stable ``file:line`` key used for same-bug correlation."""
        return f"{self.file}:{self.line}"


# ── The normalized observation ─────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class Observation:
    """One normalized finding from either lane, before task formation.

    Invariants (enforced at construction by the intake path, not here):

    * a ``scan_source == "sast"`` observation always carries
      ``source_location`` — its whole reason to outrank a dynamic twin;
    * ``producer_id`` is globally unique across both lanes in one batch
      (:func:`combine_observations` rejects a duplicate).
    """

    producer_id: str
    scan_source: ScanSource
    vuln_class: VulnClass
    title: str
    source_location: SastSourceLocation | None = None
    priority: Priority | None = None
    confidence: Confidence | None = None
    severity: str | None = None
    message: str = ""
    #: Optional explicit same-bug key. When two observations in one class share
    #: a non-empty ``correlation_key`` they are grouped. A SAST observation
    #: falls back to its ``source_location.signature()`` when this is unset, so
    #: a dynamic observation can join a static one by pointing its
    #: ``correlation_key`` at the same ``file:line``.
    correlation_key: str | None = None
    #: Live proxy exchange ids (dynamic lane corroboration / proof-gate input).
    http_exchange_ids: tuple[str, ...] = ()
    evidence: str = ""

    @property
    def primary_preference(self) -> Literal["preferred", "default"]:
        """SAST evidence is ``preferred``; a dynamic finding is ``default``.

        This single bit is the dedupe contract: in a merged group the
        ``preferred`` member becomes the task primary and keeps its exact
        ``file:line:rule``.
        """
        if self.scan_source == "sast" and self.source_location is not None:
            return "preferred"
        return "default"

    def group_key(self) -> tuple[VulnClass, str]:
        """Deterministic same-bug key for the default grouper.

        Precedence: an explicit ``correlation_key``; else a SAST observation's
        ``file:line`` signature; else a per-producer singleton key so a dynamic
        finding with no correlation hint stands on its own rather than being
        force-merged with an unrelated finding of the same class.
        """
        if self.correlation_key:
            return (self.vuln_class, self.correlation_key)
        if self.source_location is not None:
            return (self.vuln_class, self.source_location.signature())
        return (self.vuln_class, f"__singleton__:{self.producer_id}")


# ── Reconciled task + exploitation-queue entry ─────────────────────────


@dataclass(frozen=True, slots=True)
class ReconciliationTask:
    """A deduplicated exploitation task: one primary + folded corroboration."""

    task_id: str
    vuln_class: VulnClass
    primary: Observation
    merged_from: tuple[Observation, ...] = ()
    priority: Priority | None = None
    confidence: Confidence | None = None

    @property
    def provenance(self) -> SastSourceLocation | None:
        """Authoritative SAST location, if any member carries one.

        Normally the primary (SAST-preferred selection), but a SAST member
        folded under a dynamic-primary task still surfaces its provenance so a
        task is never reported without the location evidence it actually has.
        """
        if self.primary.source_location is not None:
            return self.primary.source_location
        for member in self.merged_from:
            if member.source_location is not None:
                return member.source_location
        return None

    @property
    def members(self) -> tuple[Observation, ...]:
        return (self.primary, *self.merged_from)

    @property
    def http_exchange_ids(self) -> tuple[str, ...]:
        """Union of live exchange ids across every member, order-stable."""
        seen: dict[str, None] = {}
        for member in self.members:
            for rid in member.http_exchange_ids:
                seen.setdefault(rid, None)
        return tuple(seen)


@dataclass(frozen=True, slots=True)
class ExploitationQueueEntry:
    """A single, materialized, per-class queue entry backed by its provenance.

    ``validated`` is the gate the exploit lane reads: an entry is only
    actionable when it is non-empty and backed by *some* concrete evidence —
    an authoritative SAST location, a cited live exchange, or captured
    dynamic evidence. An entry with none of these is a shell and is held back.
    """

    task_id: str
    vuln_class: VulnClass
    title: str
    priority: Priority | None
    confidence: Confidence | None
    severity: str | None
    provenance: SastSourceLocation | None
    corroboration_count: int
    http_exchange_ids: tuple[str, ...] = field(default_factory=tuple)
    evidence: str = ""

    @property
    def validated(self) -> bool:
        if not self.task_id or self.vuln_class not in ALL_CLASSES:
            return False
        return bool(self.provenance or self.http_exchange_ids or self.evidence.strip())


__all__ = [
    "ALL_CLASSES",
    "REF_PREFIX",
    "Confidence",
    "ExploitationQueueEntry",
    "Observation",
    "Priority",
    "ReconciliationTask",
    "SastSourceLocation",
    "ScanSource",
    "VulnClass",
]
