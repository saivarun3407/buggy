"""Benchmark KG recorder — persists challenge outcomes + attack paths to Neo4j.

Benchmark-mode agents optimize for flag capture (the benchmark skill
suspends the final-report rule), so nothing in the agent loop writes
engagement observations. The result: Neo4j held the skill ontology but
zero benchmark history — every run started from scratch with no
cross-run learning.

This recorder closes that gap from the harness side, deterministically.
After each challenge completes, the runner records the challenge, its
declared vulnerability classes, the technique (skill) each class routes
to, the run outcome, AND the attack steps — the actual tool-call
sequence the agent executed, fetched from the challenge's LangGraph
thread — as one engagement-scoped subgraph:

    (Finding)-[:MAPS_TO]->(Host)-[:HAS_VULN]->(Vulnerability)
    (Technique)-[:EXPLOITS]->(Vulnerability)
    (Finding)-[:USES]->(Technique)
    (Finding)-[:DERIVED_FROM]->(AttackPath)-[:STARTS_AT]->(Host)
    (AttackPath)-[:REACHES]->(Vulnerability)

``AttackPath.steps`` carries the ordered reproduction sequence (the
curl / bash / skill-load calls that produced the finding), so a finding
is replayable, not just a verdict.

Everything lands under the single ``benchmark`` engagement label so
learnings accumulate across runs — ``MATCH (h:Host)-[:HAS_VULN]->(v)
MATCH (f:Finding)-[:MAPS_TO]->(h) RETURN v, f.passed`` answers "which
classes fail and how often" over the full history. The tag→technique
routing table is parsed from the benchmark SKILL.md at runtime — the
skill is the canonical (and only) home of that mapping.

Future corpora (pentest reports, bug-bounty reports) join the same
graph: every ``Finding`` carries a ``source`` prop ("benchmark" here;
report ingesters write their own), and share the ``vuln:<tag>`` /
``skill:<file>`` anchor nodes — so agent-side KG queries will
cross-reference benchmark learnings with real-world findings without
new vocabulary.

Failure-safe by contract: any Neo4j problem (missing env, unreachable
bolt, driver absent) disables the recorder with one warning; it never
breaks a benchmark run.
"""

from __future__ import annotations

import logging
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any

from buggy_core.types.kg import EdgeKind, NodeKind

if TYPE_CHECKING:  # pragma: no cover - import cycle guard for typing only
    from benchmark.schemas import Challenge, ChallengeResult

log = logging.getLogger(__name__)

# Cumulative, cross-run learning scope. Distinct from the per-challenge
# ``benchmark-<id>`` engagement the agent graph runs under: that one is
# per-run operational state, this one is the durable learning base.
BENCHMARK_ENGAGEMENT = "benchmark"

# Attack-step extraction bounds. Steps are the reproduction sequence —
# long enough to replay a challenge, short enough that a 100-message
# thread doesn't become a megabyte node.
_MAX_STEPS = 60
_MAX_STEP_CHARS = 220

_SKILL_MD_PATH = (
    Path(__file__).resolve().parents[1]
    / "packages"
    / "buggy"
    / "buggy"
    / "skills"
    / "benchmark"
    / "SKILL.md"
)

# Routing-table rows: | `tag` | `skill.md` (optional prose) |
_TAG_ROW_RE = re.compile(r"^\|\s*`([a-z0-9_]+)`\s*\|(.+)\|\s*$", re.MULTILINE)
_SKILL_FILE_RE = re.compile(r"`([a-z0-9-]+\.md)`")

# Tool-call arg keys that carry the step payload, in priority order —
# the first present key wins. bash-family tools use command/cmd,
# load_skill uses path/skill, task dispatch uses description.
_STEP_ARG_KEYS = (
    "command",
    "cmd",
    "path",
    "skill",
    "description",
    "url",
    "query",
)


def load_tag_to_skills(path: Path = _SKILL_MD_PATH) -> dict[str, list[str]]:
    """Parse the tag→skill routing table out of the benchmark SKILL.md.

    Returns ``{tag: [skill files]}``. Rows whose cell names several skills
    (``blind_sqli`` → ``blind-sqli.md`` + ``sqli.md``) yield all of them —
    the recorder links the run to every technique the fast-path table
    offers for that class. Missing file / unparseable table → empty dict;
    the recorder degrades to Vulnerability-only edges.
    """
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        log.warning("kg_recorder: cannot read %s (%s) — no technique edges", path, exc)
        return {}
    mapping: dict[str, list[str]] = {}
    for tag, cell in _TAG_ROW_RE.findall(text):
        skills = sorted(set(_SKILL_FILE_RE.findall(cell)))
        if skills:
            mapping[tag] = skills
    return mapping


class BenchmarkKGRecorder:
    """Records per-challenge benchmark results into the engagement KG.

    Construct once per runner invocation. ``store`` injection keeps the
    unit tests hermetic; production resolves Neo4j from the environment:

      - ``BENCHMARK_NEO4J_URI`` — bolt endpoint (default ``bolt://localhost:7687``,
        the published compose port; the in-container agents use
        ``bolt://neo4j:7687`` but the runner executes host-side)
      - ``BUGGY_NEO4J_USER`` — default ``neo4j``
      - ``BUGGY_NEO4J_PASSWORD`` / ``NEO4J_PASSWORD`` — no default;
        unset → recorder disabled

    ``langgraph_url`` points at the LangGraph server whose threads hold
    the per-challenge message history; the recorder fetches each
    finished challenge's thread state to extract the attack steps.
    """

    def __init__(
        self,
        *,
        store: Any | None = None,
        batch_id: str | None = None,
        langgraph_url: str = "http://localhost:2024",
    ) -> None:
        self._store = store if store is not None else self._store_from_env()
        self._batch_id = batch_id or f"batch-{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}"
        self._langgraph_url = langgraph_url.rstrip("/")
        self._tag_to_skills: dict[str, list[str]] | None = None

    @staticmethod
    def _store_from_env() -> Any | None:
        """Resolve a KGStore from env, or None (disabled) on any problem."""
        import os

        from buggy.middleware.kg_internal.store import (
            KGStore,
            KGStoreConfig,
            KGStoreUnavailableError,
        )

        password = (
            os.environ.get("BUGGY_NEO4J_PASSWORD", "").strip()
            or os.environ.get("NEO4J_PASSWORD", "").strip()
        )
        if not password:
            log.warning(
                "kg_recorder: no Neo4j password (BUGGY_NEO4J_PASSWORD / NEO4J_PASSWORD) "
                "— benchmark learning paths will NOT be recorded"
            )
            return None
        config = KGStoreConfig(
            uri=os.environ.get("BENCHMARK_NEO4J_URI", "").strip()
            or os.environ.get("BUGGY_NEO4J_URI", "").strip()
            or "bolt://localhost:7687",
            user=os.environ.get("BUGGY_NEO4J_USER", "").strip() or "neo4j",
            password=password,
        )
        try:
            return KGStore(config)
        except (KGStoreUnavailableError, ImportError) as exc:
            log.warning("kg_recorder: Neo4j unreachable — learning paths disabled: %s", exc)
            return None

    @property
    def enabled(self) -> bool:
        return self._store is not None

    def _techniques_for(self, tags: list[str]) -> dict[str, list[str]]:
        """Tag→skills for the challenge's tags (routing table lazily parsed)."""
        if self._tag_to_skills is None:
            self._tag_to_skills = load_tag_to_skills()
        return {t: self._tag_to_skills.get(t, []) for t in tags}

    # ── Attack-step extraction ────────────────────────────────────────

    def fetch_attack_steps(self, thread_id: str) -> list[str]:
        """Extract the ordered tool-call sequence from a challenge thread.

        The steps ARE the reproduction sequence: every tool call the
        orchestrator issued, in order (skill loads, bash probes, curl
        requests, subagent dispatches). Any failure — unreachable
        server, deleted thread, unexpected shape — returns ``[]`` so
        the caller records the outcome-only path rather than skipping
        the finding entirely.
        """
        import httpx

        try:
            resp = httpx.get(f"{self._langgraph_url}/threads/{thread_id}/state", timeout=30.0)
            resp.raise_for_status()
            state = resp.json()
        except Exception as exc:
            log.warning("kg_recorder: thread state fetch failed (%s): %s", thread_id, exc)
            return []
        values = state.get("values") if isinstance(state, dict) else None
        messages = values.get("messages") if isinstance(values, dict) else None
        if not isinstance(messages, list):
            return []

        steps: list[str] = []
        for msg in messages:
            if not isinstance(msg, dict) or msg.get("type") != "ai":
                continue
            for tc in msg.get("tool_calls") or []:
                if not isinstance(tc, dict):
                    continue
                step = self._format_step(tc)
                if step and len(steps) < _MAX_STEPS:
                    steps.append(step)

        # The orchestrator dispatches the real work to sub-agents (recon,
        # exploit) whose tool calls live in the thread's
        # ``subagent_transcripts`` — without them the "attack path" would
        # only ever show skill loads and task dispatches. Each entry is
        # ``{type: subagent_tool_call, agent, tool, args, id}``.
        transcripts = values.get("subagent_transcripts") if isinstance(values, dict) else None
        if isinstance(transcripts, list):
            for entry in transcripts:
                if not isinstance(entry, dict) or entry.get("type") != "subagent_tool_call":
                    continue
                if len(steps) >= _MAX_STEPS:
                    break
                step = self._format_step({"name": entry.get("tool"), "args": entry.get("args")})
                if step:
                    agent = str(entry.get("agent") or "subagent")
                    steps.append(f"[{agent}] {step}")
        return steps

    @staticmethod
    def _format_step(tool_call: dict[str, Any]) -> str | None:
        """Render one tool call as a replayable step string."""
        name = str(tool_call.get("name") or "tool")
        args = tool_call.get("args")
        payload = ""
        if isinstance(args, dict):
            for key in _STEP_ARG_KEYS:
                value = args.get(key)
                if isinstance(value, str) and value.strip():
                    payload = value.strip()
                    break
            else:
                # No known key — fall back to the longest string arg so
                # exotic tools still produce a useful step.
                candidates = [v for v in args.values() if isinstance(v, str) and v.strip()]
                if candidates:
                    payload = max(candidates, key=len).strip()
        if payload:
            payload = re.sub(r"\s+", " ", payload)[:_MAX_STEP_CHARS]
            return f"{name}: {payload}"
        return None

    def build_observations(
        self,
        challenge: Challenge,
        result: ChallengeResult,
    ) -> list[dict[str, Any]]:
        """Assemble the node/edge observation batch for one challenge run."""
        host_key = f"challenge:{challenge.id}"
        techniques = self._techniques_for(challenge.tags)
        steps = self.fetch_attack_steps(result.thread_id) if result.thread_id else []

        observations: list[dict[str, Any]] = [
            {
                "kind": NodeKind.HOST,
                "key": host_key,
                "label": f"{challenge.id} — {challenge.name}",
                "props": {
                    "level": challenge.level,
                    "tags": list(challenge.tags),
                },
                "edges_out": [
                    {"to_key": f"vuln:{tag}", "kind": EdgeKind.HAS_VULN, "weight": 1.0}
                    for tag in challenge.tags
                ],
            }
        ]

        for tag in challenge.tags:
            observations.append(
                {
                    "kind": NodeKind.VULNERABILITY,
                    "key": f"vuln:{tag}",
                    "label": tag,
                    "props": {"tag": tag},
                }
            )
            for skill in techniques.get(tag, []):
                observations.append(
                    {
                        "kind": NodeKind.TECHNIQUE,
                        "key": f"skill:{skill}",
                        "label": skill,
                        "props": {"skill_file": skill},
                        "edges_out": [
                            {"to_key": f"vuln:{tag}", "kind": EdgeKind.EXPLOITS, "weight": 1.0}
                        ],
                    }
                )

        finding_props: dict[str, Any] = {
            "passed": result.passed,
            "level": result.level,
            "duration_seconds": result.duration_seconds,
            "recorded_at": datetime.now(timezone.utc).isoformat(),
        }
        if result.flag_captured:
            finding_props["flag_captured"] = result.flag_captured
        if result.token_count is not None:
            finding_props["token_count"] = result.token_count
        if result.cost_usd is not None:
            finding_props["cost_usd"] = result.cost_usd
        if result.error:
            finding_props["error"] = result.error[:300]
        if result.trace_id:
            finding_props["trace_id"] = result.trace_id
        if result.agent_summary:
            finding_props["agent_summary"] = result.agent_summary[:500]

        used_skills = sorted({s for skills in techniques.values() for s in skills})
        path_key = f"path:{self._batch_id}:{challenge.id}"
        finding_edges: list[dict[str, Any]] = [
            {"to_key": host_key, "kind": EdgeKind.MAPS_TO, "weight": 1.0},
            *(
                {"to_key": f"skill:{skill}", "kind": EdgeKind.USES, "weight": 1.0}
                for skill in used_skills
            ),
        ]
        if steps:
            finding_edges.append({"to_key": path_key, "kind": EdgeKind.DERIVED_FROM, "weight": 1.0})
        observations.append(
            {
                "kind": NodeKind.FINDING,
                "key": f"run:{self._batch_id}:{challenge.id}",
                "label": f"{challenge.id} — {'PASS' if result.passed else 'FAIL'}",
                "props": {**finding_props, "source": "benchmark"},
                "edges_out": finding_edges,
            }
        )

        if steps:
            observations.append(
                {
                    "kind": NodeKind.ATTACK_PATH,
                    "key": path_key,
                    "label": f"{challenge.id} attack path ({len(steps)} steps)",
                    "props": {
                        "steps": steps,
                        "step_count": len(steps),
                        "source": "benchmark",
                        "recorded_at": datetime.now(timezone.utc).isoformat(),
                    },
                    "edges_out": [
                        {"to_key": host_key, "kind": EdgeKind.STARTS_AT, "weight": 1.0},
                        *(
                            {"to_key": f"vuln:{tag}", "kind": EdgeKind.REACHES, "weight": 1.0}
                            for tag in challenge.tags
                        ),
                    ],
                }
            )
        return observations

    def record(self, challenge: Challenge, result: ChallengeResult) -> dict[str, Any] | None:
        """Write one challenge's learning path. Never raises.

        Returns the store's write summary (``{"created": …, "edges": …}``)
        or ``None`` when disabled/failed. Observations ride one atomic
        ``record_observations`` transaction — a half-written path is not
        possible.
        """
        if self._store is None:
            return None
        try:
            summary = self._store.record_observations(
                self.build_observations(challenge, result),
                engagement=BENCHMARK_ENGAGEMENT,
                created_by="benchmark-runner",
                source_episode_id=self._batch_id,
            )
            log.info(
                "kg_recorder: %s (%s) → %s",
                challenge.id,
                "PASS" if result.passed else "FAIL",
                summary,
            )
            return summary
        except Exception as exc:  # noqa: BLE001 — observability must not kill runs
            log.warning("kg_recorder: failed to record %s: %s", challenge.id, exc)
            return None
