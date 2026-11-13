"""White-box reconciliation: join the SAST lane to the live exploit lane.

Phase 4 correlation layer. Both a static SAST SARIF finding and a dynamic live
finding normalize to a common :class:`~buggy.reconciliation.contracts.Observation`;
reconciliation groups them per vulnerability class and collapses same-bug
findings into a single exploitation task whose *primary* record is the SAST
evidence — carrying an authoritative ``file:line:rule`` as provenance. That
provenance threads through task formation into the published finding, so Phase
3's proof gate records ``file:line:rule`` alongside the required live PoC.

Pipeline::

    SARIF ──parse_sarif_content──▶ [Observation(sast)]   ┐
                                                          ├─ combine_observations
    live findings ─────────────▶ [Observation(dynamic)]  ┘
        │
        ▼ form_tasks (group + singleton fallback)
    {class: [ReconciliationTask]}
        │
        ▼ materialize_queue
    {class: [ExploitationQueueEntry]}  ── queue_is_actionable gates the exploit lane
        │                        └── each item carries a ``finding_template``
        ▼ provenance_to_finding (+ live PoC fields filled by the exploit lane)
    proof_gate.verify_finding ──▶ kg_adapter.publish_finding_node

The bridge is live: ``reconcile_sast_to_queue`` (on the exploit agent's
toolset) emits a ``provenance_to_finding`` template per queue item, so the
exploit lane hands the proof gate a finding that already carries the SAST
``file:line:rule`` alongside the live PoC it adds.
"""

from __future__ import annotations

from buggy.reconciliation.contracts import (
    ALL_CLASSES,
    ExploitationQueueEntry,
    Observation,
    ReconciliationTask,
    SastSourceLocation,
    VulnClass,
)
from buggy.reconciliation.cwe_map import class_for_cwe
from buggy.reconciliation.form import combine_observations, form_tasks
from buggy.reconciliation.merge import build_tasks
from buggy.reconciliation.queue import (
    RECONCILIATION_TOOLS,
    actionable_entries,
    is_actionable,
    materialize_queue,
    provenance_to_finding,
    queue_is_actionable,
    reconcile_sast_to_queue,
)
from buggy.reconciliation.sast_intake import (
    SarifDocumentError,
    SastIntake,
    parse_sarif_content,
    parse_sarif_document,
)

__all__ = [
    "ALL_CLASSES",
    "RECONCILIATION_TOOLS",
    "ExploitationQueueEntry",
    "Observation",
    "ReconciliationTask",
    "SarifDocumentError",
    "SastIntake",
    "SastSourceLocation",
    "VulnClass",
    "actionable_entries",
    "build_tasks",
    "class_for_cwe",
    "combine_observations",
    "form_tasks",
    "is_actionable",
    "materialize_queue",
    "parse_sarif_content",
    "parse_sarif_document",
    "provenance_to_finding",
    "queue_is_actionable",
    "reconcile_sast_to_queue",
]
