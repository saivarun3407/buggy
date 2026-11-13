"""Agent-facing KG tools — ``kg_record`` and ``kg_ingest``.

Built by :func:`build_kg_tools` and attached to ``KGMiddleware.tools``
so ``langchain.agents.create_agent`` merges them into the agent's
toolset at compile time. The tools never accept ``engagement`` from
the LLM; the middleware injects it via ``InjectedState`` and the store
re-pulls it inside ``record_observations`` / ``ingest`` so an
``InjectedState`` override bug (open issue
``langchain-ai/langchain#31688``) cannot escape the engagement scope.

Surface (extended with the read path):

  - ``kg_record(observations)``           — atomic batch write of nodes
                                            and outgoing edges.
  - ``kg_ingest(scanner_kind, path)``     — dispatcher into the scanner
                                            adapter registry.
  - ``kg_query(topic, limit)``            — scoped search over past
                                            findings, attack paths,
                                            techniques and harness
                                            learnings. Own engagement
                                            always; the shared
                                            ``benchmark`` learning base
                                            additionally in benchmark
                                            mode. No raw Cypher is
                                            accepted from the LLM —
                                            the store injects the
                                            authoritative scope on
                                            every read.
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from typing import Annotated, Any

from langchain_core.tools import InjectedToolCallId, tool
from langgraph.prebuilt import InjectedState

from buggy.middleware.kg_internal.ingest import ingest as _ingest_dispatch
from buggy.middleware.kg_internal.store import KGStore
from buggy_core.utils.env import env_flag

DEFAULT_KG_TOOLS = frozenset({"kg_record", "kg_ingest", "kg_query"})

_ENGAGEMENT_UNSET = (
    "kg_engagement is not set on agent state; middleware before_agent did not hydrate"
)

# ── kg_query scoping ───────────────────────────────────────────────────
# The learning base the benchmark recorder writes to. Reading it is
# operator-shared reference data (challenge outcomes, attack paths,
# harness learnings) — never tenant engagement data — so exposing it to
# benchmark-mode agents does not cross the multi-tenant isolation line.
_BENCHMARK_LEARNING_SCOPE = "benchmark"

# Output budgets — the digest rides in tool output, so bound it.
_MAX_STEPS_SHOWN = 12
_MAX_STEP_CHARS = 200
_MAX_SUMMARY_CHARS = 300


def _benchmark_mode_active() -> bool:
    """Truthy evaluation of the BENCHMARK_MODE env var."""
    return env_flag("BENCHMARK_MODE")


def _resolve_engagement(state: dict[str, Any] | None) -> str:
    """Pull the engagement label from state with a fall-back to
    ``engagement_name`` (the upstream EngagementContextMiddleware field)."""
    if not isinstance(state, dict):
        return ""
    return str(state.get("kg_engagement") or state.get("engagement_name") or "").strip()


def _resolve_created_by(state: dict[str, Any] | None) -> str:
    """Best-effort agent identity for provenance. Falls back to a
    constant string so the trusted ``record_observations`` invariant
    holds even when the agent role is missing from state."""
    if not isinstance(state, dict):
        return "agent"
    role = state.get("role") or state.get("agent_name") or state.get("kg_created_by")
    if isinstance(role, str) and role:
        return role
    return "agent"


def _err(message: str) -> str:
    return json.dumps({"error": message})


def build_kg_tools(
    store: KGStore,
    enabled: Iterable[str] | None = None,
) -> list[Any]:
    """Construct the agent-facing KG tools bound to a single store.

    ``enabled`` selects which tools land in the returned list. Default
    is ``DEFAULT_KG_TOOLS`` (kg_record + kg_ingest). Plugin authors
    that ship a third KG tool can pass ``{"kg_record", "kg_ingest",
    "kg_my_custom_tool"}`` in conjunction with subclassing
    ``KGMiddleware`` to append the extra tool factory.
    """
    enabled_set: set[str] = set(enabled) if enabled is not None else set(DEFAULT_KG_TOOLS)
    tools: list[Any] = []

    if "kg_record" in enabled_set:

        @tool
        def kg_record(
            observations: str,
            state: Annotated[dict, InjectedState],
            tool_call_id: Annotated[str, InjectedToolCallId] = "",
        ) -> str:
            """Record one or more graph observations atomically.

            The middleware injects engagement scope + provenance — you
            only pass the observations. All observations in one call
            land in a single Neo4j transaction; partial failure rolls
            back the batch.

            ``observations`` is a JSON-encoded list. Each entry:

              {
                "kind": "Host" | "Service" | "Vulnerability" | ... ,
                "key": "host::10.0.0.1",        # deterministic dedup key
                "label": "10.0.0.1",
                "props": {"ip": "10.0.0.1", "explored": false, ...},
                "edges_out": [
                  {"to_key": "service::10.0.0.1:80",
                   "kind": "HOSTS", "weight": 0.5}
                ]
              }

            Reserved provenance keys (engagement, firstseen, lastupdated,
            created_by, source_episode_id) are stripped from your props
            silently — the middleware sets them.

            Returns JSON: {"created": N, "merged": M, "edges": E,
            "revision": "..."}.
            """
            engagement = _resolve_engagement(state)
            if not engagement:
                return _err(_ENGAGEMENT_UNSET)

            try:
                obs_list = json.loads(observations)
            except (TypeError, ValueError) as exc:
                return _err(f"observations must be valid JSON list: {exc}")
            if not isinstance(obs_list, list):
                return _err("observations must be a JSON list of observation dicts")

            try:
                result = store.record_observations(
                    obs_list,
                    engagement=engagement,
                    created_by=_resolve_created_by(state),
                    source_episode_id=tool_call_id or "no-tool-call-id",
                )
            except ValueError as exc:
                return _err(str(exc))
            except Exception as exc:  # noqa: BLE001 — surface to LLM
                return _err(f"kg_record failed: {exc}")
            return json.dumps(result)

        tools.append(kg_record)

    if "kg_ingest" in enabled_set:

        @tool
        def kg_ingest(
            scanner_kind: str,
            path: str,
            state: Annotated[dict, InjectedState],
            tool_call_id: Annotated[str, InjectedToolCallId] = "",
        ) -> str:
            """Ingest a scanner output file into the engagement graph.

            ``scanner_kind`` selects an adapter from the registry. Built-ins:
              nmap_xml, nuclei_jsonl, httpx_jsonl, sarif.

            ``path`` is an absolute file path inside the sandbox / host
            (the adapter reads it directly). Examples:
              kg_ingest("nmap_xml", "/workspace/scan.xml")
              kg_ingest("sarif",    "/workspace/semgrep.sarif")

            Returns JSON: {"scanner": "...", "path": "...",
            "ingested": ...} on success, or
            {"error": "...", "available": [...]} when ``scanner_kind``
            is unknown.
            """
            engagement = _resolve_engagement(state)
            if not engagement:
                return _err(_ENGAGEMENT_UNSET)

            try:
                result = _ingest_dispatch(
                    scanner_kind,
                    path,
                    store=store,
                    engagement=engagement,
                    created_by=_resolve_created_by(state),
                    source_episode_id=tool_call_id or "no-tool-call-id",
                )
            except Exception as exc:  # noqa: BLE001 — surface to LLM
                return _err(f"kg_ingest failed: {exc}")
            return json.dumps(result)

        tools.append(kg_ingest)

    if "kg_query" in enabled_set:

        @tool
        def kg_query(
            topic: str,
            state: Annotated[dict, InjectedState],
            tool_call_id: Annotated[str, InjectedToolCallId] = "",
            limit: int = 5,
        ) -> str:
            """Search the knowledge graph for past findings, attack paths, and learnings.

            Call this BEFORE attacking a vulnerability class (e.g.
            ``kg_query("idor")`` or ``kg_query("blind sqli")``): prior runs
            may have already recorded which techniques worked, the exact
            reproduction steps (attack path), and harness-level lessons
            (crash causes, credential pitfalls) for the same class.

            ``topic`` is matched case-insensitively against vulnerability
            tags, technique names, host labels, finding summaries, and
            recorded lessons. ``limit`` caps results (1-10, default 5).

            Returns JSON: {"findings": [{host, tags, passed, techniques,
            steps, summary}], "learnings": [{weakness, lesson, patches}]}
            ranked passes-first. Scopes searched: this engagement, plus the
            shared cross-run learning base in benchmark mode.
            """
            own = _resolve_engagement(state)
            scopes = (
                [s for s in (own, _BENCHMARK_LEARNING_SCOPE) if s]
                if _benchmark_mode_active()
                else ([own] if own else [])
            )
            if not scopes:
                return _err(
                    "No graph scope available: kg_engagement is unset and "
                    "BENCHMARK_MODE is not active. Ask the operator to "
                    "configure the engagement or enable benchmark mode."
                )
            limit_clamped = max(1, min(int(limit), 10))
            topic_lower = topic.strip().lower()
            if not topic_lower:
                return _err("topic must be a non-empty string")

            findings: list[dict[str, Any]] = []
            learnings: list[dict[str, Any]] = []
            errors: list[str] = []

            for scope in scopes:
                try:
                    rows = store.execute_read(
                        (
                            "MATCH (f:Finding)-[:MAPS_TO]->(h:Host) "
                            "WHERE f.engagement = $engagement AND ( "
                            "  EXISTS { MATCH (h)-[:HAS_VULN]->(v0:Vulnerability) "
                            "           WHERE toLower(v0.tag) CONTAINS $topic } "
                            "  OR toLower(coalesce(f.agent_summary, '')) CONTAINS $topic "
                            "  OR toLower(coalesce(h.key, '')) CONTAINS $topic ) "
                            "WITH DISTINCT f, h "
                            "OPTIONAL MATCH (h)-[:HAS_VULN]->(v:Vulnerability) "
                            "WITH f, h, collect(DISTINCT v.tag) AS tags "
                            "OPTIONAL MATCH (f)-[:USES]->(t:Technique) "
                            "WITH f, h, tags, collect(DISTINCT t.key) AS techniques "
                            "RETURN f.key AS finding, f.passed AS passed, "
                            "       coalesce(f.agent_summary, '') AS summary, "
                            "       coalesce(f.duration_seconds, 0) AS duration, "
                            "       h.key AS host, tags, techniques "
                            "ORDER BY f.passed DESC, f.recorded_at DESC "
                            "LIMIT $cap"
                        ),
                        {"topic": topic_lower, "cap": limit_clamped},
                        engagement=scope,
                    )
                except Exception as exc:  # noqa: BLE001 — surface to LLM
                    errors.append(f"scope {scope!r} findings query failed: {exc}")
                    continue

                matched_keys = [r.get("finding") for r in rows if r.get("finding")]
                path_steps: dict[str, list[str]] = {}
                if matched_keys:
                    try:
                        step_rows = store.execute_read(
                            (
                                "MATCH (f:Finding)-[:DERIVED_FROM]->(p:AttackPath) "
                                "WHERE f.engagement = $engagement AND f.key IN $keys "
                                "RETURN f.key AS finding, p.steps AS steps"
                            ),
                            {"keys": matched_keys},
                            engagement=scope,
                        )
                        for row in step_rows:
                            steps = row.get("steps")
                            if isinstance(steps, list):
                                path_steps[str(row.get("finding"))] = [
                                    s[:_MAX_STEP_CHARS] for s in steps if isinstance(s, str)
                                ]
                    except Exception as exc:  # noqa: BLE001 — steps are best-effort
                        errors.append(f"scope {scope!r} attack-path query failed: {exc}")

                for row in rows:
                    key = str(row.get("finding"))
                    findings.append(
                        {
                            "scope": scope,
                            "host": row.get("host"),
                            "tags": [t for t in (row.get("tags") or []) if t],
                            "passed": bool(row.get("passed")),
                            "techniques": [t for t in (row.get("techniques") or []) if t],
                            "duration_seconds": row.get("duration"),
                            "steps": path_steps.get(key, [])[:_MAX_STEPS_SHOWN],
                            "summary": str(row.get("summary") or "")[:_MAX_SUMMARY_CHARS],
                        }
                    )

                try:
                    weak_rows = store.execute_read(
                        (
                            "MATCH (w:Weakness) WHERE w.engagement = $engagement AND ( "
                            "  toLower(coalesce(w.label, '')) CONTAINS $topic "
                            "  OR toLower(coalesce(w.lesson, '')) CONTAINS $topic "
                            "  OR toLower(coalesce(w.symptom, '')) CONTAINS $topic "
                            "  OR toLower(coalesce(w.root_cause, '')) CONTAINS $topic ) "
                            "OPTIONAL MATCH (p:Patch)-[:PATCHES]->(w) "
                            "WITH w, collect(DISTINCT p.key) AS patches "
                            "RETURN w.key AS weakness, w.label AS label, "
                            "       coalesce(w.lesson, '') AS lesson, "
                            "       coalesce(w.root_cause, '') AS root_cause, "
                            "       patches "
                            "LIMIT $cap"
                        ),
                        {"topic": topic_lower, "cap": limit_clamped},
                        engagement=scope,
                    )
                    for row in weak_rows:
                        learnings.append(
                            {
                                "scope": scope,
                                "weakness": row.get("weakness"),
                                "label": row.get("label"),
                                "lesson": str(row.get("lesson") or "")[:_MAX_SUMMARY_CHARS],
                                "root_cause": str(row.get("root_cause") or "")[:_MAX_SUMMARY_CHARS],
                                "patches": [p for p in (row.get("patches") or []) if p],
                            }
                        )
                except Exception as exc:  # noqa: BLE001 — learnings are best-effort
                    errors.append(f"scope {scope!r} learnings query failed: {exc}")

            # Merge + rank across scopes: passes first, then fastest solve.
            # Per-scope queries already LIMIT $cap, so the merged pool can
            # hold up to cap*len(scopes) entries; the rank must happen on the
            # merged pool or a slow pass in scope A would beat a fast pass
            # in scope B purely by scope order.
            findings.sort(key=lambda f: (not f["passed"], f.get("duration_seconds") or 0))
            findings = findings[:limit_clamped]
            learnings = learnings[:limit_clamped]
            payload: dict[str, Any] = {
                "scopes_searched": scopes,
                "topic": topic_lower,
            }
            if not findings and not learnings:
                payload["result"] = (
                    "no matches — you are the first to attack this class; "
                    "your run will record the path for the next one."
                )
            else:
                payload["findings"] = findings
                payload["learnings"] = learnings
            if errors:
                payload["errors"] = errors
            return json.dumps(payload)

        tools.append(kg_query)

    return tools
