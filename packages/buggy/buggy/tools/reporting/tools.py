"""LangChain @tool wrappers for the reporting package.

The reporting tools read the engagement KG that ``KGMiddleware`` and
``kg_record`` / ``kg_ingest`` write to (the post-#545 backend) — they
no longer use the legacy ``tools/research/_state`` shim. The
engagement label is resolved from the ``EngagementContextMiddleware``
contextvar; if it is not set (e.g. agent invoked outside the standard
middleware stack), every report tool returns the structure for an
empty graph and the agent can recover.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from langchain_core.tools import tool

from buggy.tools.proxy.tools import CaidoClient, CaidoError
from buggy.tools.reporting.bugcrowd import render_bugcrowd_csv
from buggy.tools.reporting.executive import render_executive_summary
from buggy.tools.reporting.hackerone import render_hackerone_markdown
from buggy.tools.reporting.kg_adapter import load_engagement_graph, publish_finding_node
from buggy.tools.reporting.proof_gate import proof_gate_strict, verify_finding
from buggy.tools.reporting.sarif import render_sarif
from buggy.tools.reporting.timeline import extract_timeline
from buggy_core.types.kg import KnowledgeGraph
from buggy_core.utils.engagement_scope import get_active_engagement
from buggy_core.utils.env import env_flag


def _load() -> tuple[KnowledgeGraph, None]:
    """Load the engagement KG for reporting.

    Reads the engagement label from the contextvar
    (``EngagementContextMiddleware`` sets it for every tool dispatch).
    Returns an empty graph when no engagement is active so the renderer
    sees a well-formed (but empty) shape.

    Kept under this name so the existing ``mock.patch(
    "buggy.tools.reporting.tools._load", ...)`` test surface
    continues to work — only the implementation changed.
    """
    engagement = get_active_engagement()
    if not engagement:
        return KnowledgeGraph(), None
    return load_engagement_graph(engagement), None


def _json(data: Any) -> str:
    return json.dumps(data, indent=2, default=str, ensure_ascii=False)


@tool
def report_hackerone(finding_id: str) -> str:
    """Render a HackerOne-style markdown report for a finding or vulnerability node."""
    graph, _ = _load()
    node = graph.nodes.get(finding_id)
    if node is None:
        return _json({"error": f"no node {finding_id} in graph"})
    md = render_hackerone_markdown(node, graph=graph)
    return _json({"id": finding_id, "markdown": md})


@tool
def report_bugcrowd_csv(min_severity: str = "medium") -> str:
    """Render the current graph as a Bugcrowd CSV submission bundle."""
    graph, _ = _load()
    csv = render_bugcrowd_csv(graph, min_severity=min_severity)
    return _json({"rows": csv.count("\n") - 1, "csv": csv})


@tool
def report_executive(engagement_name: str = "Engagement") -> str:
    """Produce an engagement-level executive summary from the graph."""
    graph, _ = _load()
    md = render_executive_summary(graph, engagement_name=engagement_name)
    return _json({"markdown": md})


@tool
def report_timeline() -> str:
    """Extract a chronological timeline of graph events."""
    graph, _ = _load()
    events = extract_timeline(graph)
    return _json({"count": len(events), "events": [e.to_dict() for e in events]})


@tool
def report_sarif(engagement_id: str, output_path: str) -> str:
    """Render the engagement graph as SARIF v2.1.0 JSON for GitHub code scanning / DefectDojo / SARIF aggregators.

    Writes UTF-8 to ``output_path`` (parent directories are created) and
    returns a JSON summary with the engagement id, written path, byte
    count, and number of result entries emitted.
    """
    graph, _ = _load()
    sarif = render_sarif(graph, engagement_id=engagement_id)
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(sarif, encoding="utf-8")
    payload = json.loads(sarif)
    results = payload["runs"][0]["results"]
    return _json(
        {
            "engagement_id": engagement_id,
            "path": str(path),
            "bytes": len(sarif.encode("utf-8")),
            "results": len(results),
        }
    )


def _new_caido_client() -> CaidoClient | None:
    """Build a proxy client for live-evidence verification.

    A construction failure is treated as "no client" — the proof gate then
    takes its fail-open path (keep cited ids with a warning) rather than
    rejecting, so a proxy that cannot even be constructed never silently
    deletes a real finding.
    """
    try:
        return CaidoClient()
    except Exception:  # noqa: BLE001 — degrade to fail-open
        return None


#: Env flag for the replay-artifact step (default on; ``=0`` disables).
FINDING_REPLAY_ENV = "BUGGY_FINDING_REPLAY"


def _mint_replays(
    client: CaidoClient | None,
    request_ids: list[str] | None,
    title: str,
) -> dict[str, Any] | None:
    """Replay each gate-verified evidence request once, as a review artifact.

    The human-in-the-loop lesson from fielded hackbots: verification lands
    hardest when the operator can open the *same proxy* and see the exact
    evidence request — not a re-keyed curl. ``caido requests repeat`` mints
    a Replay-tab entry per cited id; the resulting payload ids are stored
    on the finding so review is one click in the Caido UI.

    Best-effort in every dimension: a replay failure never touches the
    gate verdict (the finding was already proven against the *live*
    capture) — errors are recorded per entry and the finding still
    publishes. Disabled entirely via ``BUGGY_FINDING_REPLAY=0`` for
    deployments where re-firing evidence requests is undesirable; in that
    case the manual ``requests repeat <id>`` commands are still returned
    so the operator can mint the artifacts by hand.
    """
    ids = [rid for rid in (request_ids or []) if rid]
    if not ids:
        return None
    slug = re.sub(r"[^a-z0-9]+", "-", (title or "finding").lower()).strip("-") or "finding"
    replay: dict[str, Any] = {
        "name": f"finding::{slug}",
        "repeat_commands": [f"caido requests repeat {rid}" for rid in ids],
        "entries": [],
    }
    if client is None or not env_flag(FINDING_REPLAY_ENV, default=True):
        return replay
    for rid in ids:
        try:
            payload = client.repeat_request(rid)
        except CaidoError as exc:
            replay["entries"].append({"request_id": rid, "error": str(exc)[:200], "kind": exc.kind})
        except Exception as exc:  # noqa: BLE001 — artifact failure must not fail the finding
            replay["entries"].append({"request_id": rid, "error": str(exc)[:200]})
        else:
            replay["entries"].append({"request_id": rid, "replay": payload})
    return replay


@tool
def report_record_finding(
    title: str,
    severity: str = "info",
    poc_script_code: str = "",
    poc_description: str = "",
    evidence: str = "",
    http_exchange_ids: list[str] | None = None,
    cvss_vector: str = "",
    target: str = "",
    summary: str = "",
    analysis_only: bool = False,
) -> str:
    """Record a vulnerability finding — gated by live-evidence proof verification.

    This is the proof gate: a finding is REJECTED (never written to the KG)
    unless it carries a working PoC (``poc_script_code``), a PoC description
    (``poc_description``), and concrete ``evidence``, AND cites at least one
    ``http_exchange_ids`` entry, AND every cited id is positively confirmed in
    the live proxy capture. Fabricated findings whose evidence references
    requests that were never sent — or that cite no live request — are
    blocked here.

    Only a transport failure (CLI missing, timeout, connection refused) keeps
    the cited ids with an "unverified evidence" warning rather than rejecting —
    an unreachable proxy must never silently delete a real finding. An id the
    proxy reports absent, or answers for without confirming, is rejected.

    Strictness follows ``BUGGY_PROOF_GATE_STRICT`` (default strict → proof
    required). Set ``analysis_only=True`` to file a source/static finding
    without a live PoC; this is honoured only when the deployment has turned
    strict mode off (the source-only phase), otherwise proof is still required.

    Args:
        title: Specific finding title.
        severity: Qualitative severity band (info/low/medium/high/critical).
        poc_script_code: Working proof-of-concept exploit/payload.
        poc_description: Step-by-step reproduction (no code).
        evidence: Concrete proof (request/response excerpts, observed behavior).
        http_exchange_ids: Proxy request ids that prove this finding — copied
            from the live capture. Required unless ``analysis_only`` is honoured.
        cvss_vector: Optional CVSS 3.1 vector; validated by the spine scorer.
        target: Affected URL / domain / repository.
        summary: Optional short summary stored on the node.
        analysis_only: Request the proof-optional path (see strictness above).

    Returns:
        JSON. On acceptance: ``{success: true, report_id, severity,
        persisted, evidence_unverified, live_verified, warning?}``. On rejection:
        ``{success: false, error: "Validation failed", errors: [...]}``.
    """
    env_strict = proof_gate_strict()
    # analysis-only is only permitted when the deployment is non-strict; in a
    # strict deployment the env flag wins and proof is still required.
    gate_strict = not (analysis_only and not env_strict)

    finding: dict[str, Any] = {
        "title": title,
        "severity": severity,
        "poc_script_code": poc_script_code,
        "poc_description": poc_description,
        "evidence": evidence,
        "http_exchange_ids": http_exchange_ids,
        "cvss_vector": cvss_vector,
        "target": target,
        "summary": summary,
    }

    client = _new_caido_client()
    result = verify_finding(finding, client=client, strict=gate_strict)
    if not result.accepted:
        return _json({"success": False, "error": "Validation failed", "errors": result.errors})

    # Mint human-reviewable replay artifacts for live-verified evidence —
    # one Caido Replay entry per confirmed exchange id, so the operator
    # verifies in the same tool the agent worked in. Best-effort: replay
    # failures never affect the already-rendered gate verdict.
    replay = _mint_replays(client, result.http_exchange_ids, title)

    # Only the gate-approved, non-None fields are persisted. Verified ids
    # replace the raw input; the unverified-evidence flag rides along.
    node_fields = {k: v for k, v in finding.items() if v not in (None, "")}
    node_fields["http_exchange_ids"] = result.http_exchange_ids or []
    node_fields["evidence_unverified"] = result.evidence_unverified
    node_fields["live_verified"] = result.live_verified
    if replay:
        node_fields["replay"] = replay

    node_id, persisted = publish_finding_node(get_active_engagement() or "", node_fields)

    payload: dict[str, Any] = {
        "success": True,
        "report_id": node_id,
        "severity": severity,
        "persisted": persisted,
        "evidence_unverified": result.evidence_unverified,
        "live_verified": result.live_verified,
    }
    if result.warning:
        payload["warning"] = result.warning
    if replay:
        payload["replay"] = replay
    if not persisted:
        payload.setdefault(
            "note", "finding accepted by the gate but not persisted (KG store unavailable)"
        )
    return _json(payload)


REPORTING_TOOLS = [
    report_hackerone,
    report_bugcrowd_csv,
    report_executive,
    report_timeline,
    report_sarif,
]

# The gated recording tool is exported separately rather than folded into
# REPORTING_TOOLS: that bundle is a render-only suite pinned by a wiring
# regression test (every member must reach the analyst agent). Agent wiring of
# the recorder is a follow-up outside the reporting path.
RECORDING_TOOLS = [report_record_finding]
