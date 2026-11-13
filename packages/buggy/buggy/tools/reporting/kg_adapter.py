"""Adapter — read engagement-scoped KG data from the new KGStore and
build an in-memory :class:`KnowledgeGraph` for the reporting renderers.

The renderers in ``reporting/{hackerone,bugcrowd,executive,sarif,timeline}.py``
all operate on the :class:`KnowledgeGraph` Pydantic model. Rather than
rewriting every renderer in the same PR, this adapter reads from the
new :class:`KGStore` (the post-#545 backend) and constructs the same
``KnowledgeGraph`` shape — preserving deterministic Node / Edge IDs so
downstream consumers and existing test patches remain stable.

This module is the seam that lets ``tools/reporting`` retire the old
``tools/research/_state._load`` shim without touching the renderer
code or the back-end Neo4j wiring used by the (still legacy) AD /
Contract tool surfaces — those migrate in dedicated follow-up PRs.
"""

from __future__ import annotations

import re
from typing import Any

from buggy.middleware.kg_internal.store import (
    KGStore,
    KGStoreConfigError,
    KGStoreUnavailableError,
)
from buggy_core.types.kg import (
    Edge,
    EdgeKind,
    KnowledgeGraph,
    Node,
    NodeKind,
)
from buggy_core.utils.normalize import normalize_endpoint, normalize_host

# Provenance / reserved property names that ``KGStore`` auto-injects on
# every observation. They live on the Neo4j node so we can read them
# back when rebuilding the in-memory graph, but they don't belong on
# ``Node.props`` / ``Edge.props`` — those carry the agent-supplied
# props only. Strip them before constructing the Pydantic model.
#
# ``_legacy_id`` is the SHA1 the in-memory ``Node`` carried before
# persistence. The legacy ``_state`` shim stores it so edges (whose
# ``src`` / ``dst`` are SHA1s) can resolve their endpoints on round-trip.
# We strip it from ``Node.props`` on load and instead restore it onto
# ``Node.id`` directly, preserving the legacy graph's identity model.
_RESERVED_NODE_PROPS = frozenset(
    {
        "engagement",
        "key",
        "label",
        "firstseen",
        "lastupdated",
        "created_by",
        "source_episode_id",
        "_legacy_id",
    }
)
_RESERVED_EDGE_PROPS = frozenset(
    {
        "engagement",
        "key",
        "firstseen",
        "lastupdated",
        "created_by",
        "source_episode_id",
        "weight",
    }
)


def _coerce_props(raw: Any, reserved: frozenset[str]) -> dict[str, Any]:
    if not isinstance(raw, dict):
        return {}
    return {k: v for k, v in raw.items() if k not in reserved}


def _canonical_finding_key(finding: dict[str, Any]) -> str:
    """Derive a merge-stable key for a gate-approved finding.

    The store MERGEs on ``(key, engagement)``. A title-derived key makes
    "SQL Injection on /login" and "SQLi in the /login endpoint" separate
    nodes for the same bug; a *locational* key — normalized host +
    normalized endpoint + vuln class (``kind``/``vuln_class``/``cwe``,
    else the title slug) — collapses them on write, so re-reporting an
    already-published finding refreshes its props instead of cloning it.

    Falls back to the title-based key whenever the finding carries no
    locational signal at all (a purely descriptive finding still dedups
    byte-identically, as before). An explicit ``key`` supplied by the
    caller always wins.
    """
    explicit = finding.get("key")
    if isinstance(explicit, str) and explicit.strip():
        return explicit.strip()

    raw_target = str(finding.get("target") or "")
    host = normalize_host(raw_target)
    endpoint = normalize_endpoint(raw_target)
    if endpoint and host and endpoint != host:
        # ``target`` was a URL — endpoint already carries ``host/path``.
        location = endpoint
    else:
        location = host or endpoint
    if not location:
        label = str(finding.get("title") or finding.get("label") or "finding")
        return f"finding::{label}"

    cls = (
        str(finding.get("kind") or finding.get("vuln_class") or finding.get("cwe") or "")
        .strip()
        .lower()
    )
    if not cls:
        cls = re.sub(r"[^a-z0-9]+", "-", str(finding.get("title") or "finding").lower()).strip("-")
    return f"finding::{location}::{cls}"


def publish_finding_node(
    engagement: str,
    finding: dict[str, Any],
    *,
    created_by: str = "proof_gate",
) -> tuple[str, bool]:
    """Persist a gate-approved finding as a FINDING node in the engagement KG.

    This is the write seam the proof gate publishes through: it is only ever
    called for a finding that has already passed :func:`verify_finding`, so a
    rejected (unproven / fabricated-evidence) finding never reaches here.

    Write-side dedup: when the caller supplies no explicit ``key``, the key
    is derived from the finding's normalized location + class
    (:func:`_canonical_finding_key`), so the same bug reported twice —
    by different agents with different wording — MERGEs onto one node
    rather than producing near-duplicates that only the report-time
    dedupe pass could catch.

    Returns ``(node_id, persisted)``. Persistence is best-effort and soft-fails
    exactly like :func:`load_engagement_graph` — when the KG store is
    unavailable the deterministic node id is still returned (with
    ``persisted=False``) so the caller has a stable handle and the gate verdict
    stands regardless of backend availability.
    """
    label = str(finding.get("title") or finding.get("label") or "finding")
    key = _canonical_finding_key(finding)
    props = {k: v for k, v in finding.items() if k not in {"title", "label", "key"}}
    node = Node.make(NodeKind.FINDING, label, key=key, **props)

    if not engagement:
        return node.id, False

    try:
        store = KGStore.from_env()
    except (KGStoreConfigError, KGStoreUnavailableError, ImportError):
        return node.id, False

    try:
        store.record_observations(
            [
                {
                    "kind": NodeKind.FINDING.value,
                    "key": key,
                    "label": label,
                    "props": props,
                    "edges_out": [],
                }
            ],
            engagement=engagement,
            created_by=created_by,
            source_episode_id=key,
        )
        return node.id, True
    except Exception:  # noqa: BLE001 — persistence must not break the gate
        return node.id, False
    finally:
        store.close()


def load_engagement_graph(engagement: str) -> KnowledgeGraph:
    """Build a :class:`KnowledgeGraph` from the new KGStore for one engagement.

    Returns an empty graph if the store is unavailable or unreachable —
    matches the soft-fail behaviour of the legacy ``_state._load`` so
    the reporting tools degrade gracefully when Neo4j is not running.
    """
    try:
        store = KGStore.from_env()
    except (KGStoreConfigError, KGStoreUnavailableError, ImportError):
        return KnowledgeGraph()

    graph = KnowledgeGraph()
    try:
        node_rows = store.execute_read(
            (
                "MATCH (n) WHERE n.engagement = $engagement "
                "RETURN labels(n)[0] AS kind, "
                "       n.key AS key, "
                "       n.label AS label, "
                "       properties(n) AS props, "
                "       coalesce(n.firstseen, 0.0) AS created_at, "
                "       coalesce(n.lastupdated, 0.0) AS updated_at"
            ),
            {"engagement": engagement},
            engagement=engagement,
        )
        for row in node_rows or []:
            kind_raw = row.get("kind")
            if not isinstance(kind_raw, str):
                continue
            try:
                kind = NodeKind(kind_raw)
            except ValueError:
                continue
            key = row.get("key") or ""
            label = row.get("label") or key or kind_raw
            raw_props = row.get("props") or {}
            props = _coerce_props(raw_props, _RESERVED_NODE_PROPS)
            node = Node.make(kind, str(label), key=str(key), **props)
            # Restore the legacy SHA1 id when the node was persisted
            # by the legacy shim — keeps edge.src / edge.dst lookups
            # consistent across round-trip.
            legacy_id = raw_props.get("_legacy_id") if isinstance(raw_props, dict) else None
            if isinstance(legacy_id, str) and legacy_id:
                node.id = legacy_id
            node.created_at = float(row.get("created_at") or 0.0)
            node.updated_at = float(row.get("updated_at") or 0.0)
            graph.nodes[node.id] = node

        edge_rows = store.execute_read(
            (
                "MATCH (a)-[r]->(b) "
                "WHERE a.engagement = $engagement AND r.engagement = $engagement "
                "  AND b.engagement = $engagement "
                "RETURN labels(a)[0] AS src_kind, "
                "       a.key AS src_key, "
                "       labels(b)[0] AS dst_kind, "
                "       b.key AS dst_key, "
                "       type(r) AS kind, "
                "       coalesce(r.weight, 1.0) AS weight, "
                "       properties(r) AS props, "
                "       coalesce(r.firstseen, 0.0) AS created_at"
            ),
            {"engagement": engagement},
            engagement=engagement,
        )
        for row in edge_rows or []:
            kind_raw = row.get("kind")
            src_kind_raw = row.get("src_kind")
            dst_kind_raw = row.get("dst_kind")
            src_key = row.get("src_key")
            dst_key = row.get("dst_key")
            if not (
                isinstance(kind_raw, str)
                and isinstance(src_kind_raw, str)
                and isinstance(dst_kind_raw, str)
                and isinstance(src_key, str)
                and isinstance(dst_key, str)
            ):
                continue
            try:
                kind = EdgeKind(kind_raw)
                src_kind = NodeKind(src_kind_raw)
                dst_kind = NodeKind(dst_kind_raw)
            except ValueError:
                continue
            src_id = Node.make(src_kind, src_key, key=src_key).id
            dst_id = Node.make(dst_kind, dst_key, key=dst_key).id
            weight = float(row.get("weight") or 1.0)
            props = _coerce_props(row.get("props"), _RESERVED_EDGE_PROPS)
            edge = Edge.make(src_id, dst_id, kind, weight=weight, **props)
            edge.created_at = float(row.get("created_at") or 0.0)
            graph.edges[edge.id] = edge

        return graph
    finally:
        store.close()
