"""Tests for ``benchmark.kg_recorder.BenchmarkKGRecorder``.

The recorder persists one learning subgraph per challenge result:

    (Finding)-[:MAPS_TO]->(Host)-[:HAS_VULN]->(Vulnerability)
    (Technique)-[:EXPLOITS]->(Vulnerability)
    (Finding)-[:USES]->(Technique)

Covers the observation shape (nodes, edges, provenance), the
tag→technique routing parse from the real SKILL.md, and the
failure-safe contract: no Neo4j → disabled recorder → benchmark run
proceeds untouched.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from benchmark.kg_recorder import (
    BENCHMARK_ENGAGEMENT,
    BenchmarkKGRecorder,
    load_tag_to_skills,
)
from benchmark.schemas import Challenge, ChallengeResult

_REPO_ROOT = Path(__file__).resolve().parents[5]


class FakeStore:
    """Captures record_observations calls; never touches Neo4j."""

    def __init__(self, *, raise_on_record: Exception | None = None) -> None:
        self.calls: list[dict[str, Any]] = []
        self._raise_on_record = raise_on_record

    def record_observations(
        self,
        observations: list[dict[str, Any]],
        *,
        engagement: str,
        created_by: str,
        source_episode_id: str,
    ) -> dict[str, Any]:
        if self._raise_on_record is not None:
            raise self._raise_on_record
        self.calls.append(
            {
                "observations": observations,
                "engagement": engagement,
                "created_by": created_by,
                "source_episode_id": source_episode_id,
            }
        )
        return {"created": len(observations), "merged": 0, "edges": 0, "revision": "rev-x"}


def _challenge(tags: list[str] | None = None) -> Challenge:
    return Challenge(
        id="XBEN-099-24",
        name="Get the first",
        description="IDOR challenge",
        level=2,
        tags=tags if tags is not None else ["idor"],
    )


def _result(passed: bool = True) -> ChallengeResult:
    return ChallengeResult(
        challenge_id="XBEN-099-24",
        challenge_name="Get the first",
        level=2,
        tags=["idor"],
        passed=passed,
        flag_captured="FLAG{abc}" if passed else None,
        duration_seconds=100.2,
        token_count=330_587,
        trace_id="0123456789abcdef",
        agent_summary="Flag captured via IDOR on /profile/<id>.",
    )


class TestLoadTagToSkills:
    def test_parses_routing_table_from_real_skill_md(self) -> None:
        skill_md = _REPO_ROOT / "packages/buggy/buggy/skills/benchmark/SKILL.md"
        assert skill_md.exists(), "benchmark SKILL.md must exist for routing parse"
        mapping = load_tag_to_skills(skill_md)
        assert mapping["sqli"] == ["sqli.md"]
        # blind_sqli names two skills in its cell — both are captured.
        assert set(mapping["blind_sqli"]) == {"blind-sqli.md", "sqli.md"}
        assert mapping["idor"] == ["idor.md"]
        assert mapping["arbitrary_file_upload"] == ["file-upload.md"]

    def test_missing_file_yields_empty_mapping(self, tmp_path: Path) -> None:
        assert load_tag_to_skills(tmp_path / "nope.md") == {}


class TestBuildObservations:
    def test_observation_shape(self) -> None:
        recorder = BenchmarkKGRecorder(store=FakeStore(), batch_id="batch-test")
        obs = recorder.build_observations(_challenge(), _result())

        by_key = {o["key"]: o for o in obs}
        assert by_key["challenge:XBEN-099-24"]["kind"] == "Host"
        assert by_key["challenge:XBEN-099-24"]["props"]["level"] == 2

        assert by_key["vuln:idor"]["kind"] == "Vulnerability"

        # Technique comes from the real SKILL.md routing table.
        technique = by_key["skill:idor.md"]
        assert technique["kind"] == "Technique"
        technique_edges = {e["to_key"]: e["kind"] for e in technique["edges_out"]}
        assert technique_edges == {"vuln:idor": "EXPLOITS"}

        finding = by_key["run:batch-test:XBEN-099-24"]
        assert finding["kind"] == "Finding"
        assert finding["props"]["passed"] is True
        assert finding["props"]["flag_captured"] == "FLAG{abc}"
        assert finding["props"]["token_count"] == 330_587
        assert finding["props"]["trace_id"] == "0123456789abcdef"
        assert finding["props"]["source"] == "benchmark"
        finding_edges = {e["to_key"]: e["kind"] for e in finding["edges_out"]}
        assert finding_edges["challenge:XBEN-099-24"] == "MAPS_TO"
        assert finding_edges["skill:idor.md"] == "USES"
        # No thread_id → no attack path node, no DERIVED_FROM edge.
        assert "path:batch-test:XBEN-099-24" not in finding_edges

        host_edges = {e["to_key"]: e["kind"] for e in by_key["challenge:XBEN-099-24"]["edges_out"]}
        assert host_edges == {"vuln:idor": "HAS_VULN"}

    def test_attack_path_node_with_steps(self) -> None:
        recorder = BenchmarkKGRecorder(store=FakeStore(), batch_id="batch-test")
        result = _result()
        result.thread_id = "thread-abc"
        steps = [
            "load_skill: /skills/benchmark/SKILL.md",
            "bash: curl -s http://target:3000/register -d user=u",
            "task: exploit the IDOR",
        ]

        def fake_fetch(thread_id: str) -> list[str]:
            assert thread_id == "thread-abc"
            return steps

        recorder.fetch_attack_steps = fake_fetch  # type: ignore[method-assign]
        obs = recorder.build_observations(_challenge(), result)

        by_key = {o["key"]: o for o in obs}
        path = by_key["path:batch-test:XBEN-099-24"]
        assert path["kind"] == "AttackPath"
        assert path["props"]["steps"] == steps
        assert path["props"]["step_count"] == 3
        assert path["props"]["source"] == "benchmark"
        path_edges = {e["to_key"]: e["kind"] for e in path["edges_out"]}
        assert path_edges["challenge:XBEN-099-24"] == "STARTS_AT"
        assert path_edges["vuln:idor"] == "REACHES"

        finding_edges = {
            e["to_key"]: e["kind"] for e in by_key["run:batch-test:XBEN-099-24"]["edges_out"]
        }
        assert finding_edges["path:batch-test:XBEN-099-24"] == "DERIVED_FROM"

    def test_empty_steps_yield_no_path_node(self) -> None:
        recorder = BenchmarkKGRecorder(store=FakeStore(), batch_id="batch-test")
        result = _result()
        result.thread_id = "thread-abc"
        recorder.fetch_attack_steps = lambda thread_id: []  # type: ignore[method-assign]
        obs = recorder.build_observations(_challenge(), result)
        assert not any(o["kind"] == "AttackPath" for o in obs)

    def test_multi_tag_challenge_links_every_vuln(self) -> None:
        recorder = BenchmarkKGRecorder(store=FakeStore(), batch_id="batch-test")
        obs = recorder.build_observations(
            _challenge(tags=["blind_sqli", "arbitrary_file_upload"]), _result()
        )
        by_key = {o["key"]: o for o in obs}
        host_edges = {e["to_key"] for e in by_key["challenge:XBEN-099-24"]["edges_out"]}
        assert host_edges == {"vuln:blind_sqli", "vuln:arbitrary_file_upload"}
        # blind_sqli routes to two skill files; both become USES edges.
        finding_edges = {e["to_key"] for e in by_key["run:batch-test:XBEN-099-24"]["edges_out"]}
        assert {"skill:blind-sqli.md", "skill:sqli.md", "skill:file-upload.md"} <= finding_edges

    def test_failure_result_carries_error_and_no_flag(self) -> None:
        recorder = BenchmarkKGRecorder(store=FakeStore(), batch_id="batch-test")
        result = _result(passed=False)
        result.error = "Timeout after 1800s"
        obs = recorder.build_observations(_challenge(), result)
        finding = next(o for o in obs if o["kind"] == "Finding")
        assert finding["props"]["passed"] is False
        assert finding["props"]["error"] == "Timeout after 1800s"
        assert "flag_captured" not in finding["props"]

    def test_all_props_are_flat_scalars(self) -> None:
        """KGStore._flatten_props JSON-dumps nested values — keep props flat."""
        recorder = BenchmarkKGRecorder(store=FakeStore(), batch_id="batch-test")
        obs = recorder.build_observations(_challenge(), _result())
        for o in obs:
            for value in o["props"].values():
                assert value is None or isinstance(value, (str, int, float, bool, list))


class TestFetchAttackSteps:
    @staticmethod
    def _thread_state() -> dict[str, Any]:
        return {
            "values": {
                "messages": [
                    {"type": "human", "content": "capture the flag"},
                    {
                        "type": "ai",
                        "content": "",
                        "tool_calls": [
                            {
                                "name": "load_skill",
                                "args": {"path": "/skills/benchmark/SKILL.md"},
                                "id": "c1",
                            },
                            {
                                "name": "bash",
                                "args": {"command": "curl -s http://t:3000/"},
                                "id": "c2",
                            },
                        ],
                    },
                    {"type": "tool", "name": "load_skill", "content": "ok"},
                    {
                        "type": "ai",
                        "content": "",
                        "tool_calls": [
                            {
                                "name": "task",
                                "args": {"description": "exploit the IDOR"},
                                "id": "c3",
                            },
                            {"name": "noop", "args": {"count": 3}, "id": "c4"},
                        ],
                    },
                ],
                "subagent_transcripts": [
                    {"type": "subagent_start", "agent": "exploit", "prompt": "go"},
                    {
                        "type": "subagent_tool_call",
                        "agent": "exploit",
                        "tool": "bash",
                        "args": {"command": "curl -s http://t:3000/profile/1"},
                        "id": "s1",
                    },
                    {
                        "type": "subagent_tool_result",
                        "agent": "exploit",
                        "tool": "bash",
                        "args": {},
                        "id": "s1",
                        "content": "200 OK",
                    },
                ],
            }
        }

    def test_extracts_ordered_tool_calls(self, monkeypatch: pytest.MonkeyPatch) -> None:
        recorder = BenchmarkKGRecorder(store=FakeStore(), langgraph_url="http://lg:2024")
        state = self._thread_state()

        class FakeResp:
            def raise_for_status(self) -> None:
                return None

            def json(self) -> dict[str, Any]:
                return state

        monkeypatch.setattr("httpx.get", lambda *a, **k: FakeResp())
        steps = recorder.fetch_attack_steps("thread-1")
        assert steps == [
            "load_skill: /skills/benchmark/SKILL.md",
            "bash: curl -s http://t:3000/",
            "task: exploit the IDOR",
            # Sub-agent tool calls are appended with the agent name —
            # the real exploit work lives there, not in the orchestrator.
            "[exploit] bash: curl -s http://t:3000/profile/1",
        ]

    def test_fetch_failure_returns_empty(self, monkeypatch: pytest.MonkeyPatch) -> None:
        recorder = BenchmarkKGRecorder(store=FakeStore(), langgraph_url="http://lg:2024")

        def boom(*a: Any, **k: Any) -> None:
            raise ConnectionError("langgraph down")

        monkeypatch.setattr("httpx.get", boom)
        assert recorder.fetch_attack_steps("thread-1") == []

    def test_no_thread_id_means_no_fetch(self) -> None:
        recorder = BenchmarkKGRecorder(store=FakeStore())
        result = _result()
        assert result.thread_id is None
        obs = recorder.build_observations(_challenge(), result)
        assert not any(o["kind"] == "AttackPath" for o in obs)

    def test_step_truncation(self) -> None:
        long_cmd = "x" * 5000
        step = BenchmarkKGRecorder._format_step(
            {"name": "bash", "args": {"command": long_cmd}, "id": "c1"}
        )
        assert step is not None
        assert len(step) <= 220 + len("bash: ")


class TestRecord:
    def test_record_writes_with_provenance(self) -> None:
        store = FakeStore()
        recorder = BenchmarkKGRecorder(store=store, batch_id="batch-1")
        summary = recorder.record(_challenge(), _result())
        assert summary is not None
        assert len(store.calls) == 1
        call = store.calls[0]
        assert call["engagement"] == BENCHMARK_ENGAGEMENT
        assert call["created_by"] == "benchmark-runner"
        assert call["source_episode_id"] == "batch-1"

    def test_record_swallows_store_failures(self) -> None:
        store = FakeStore(raise_on_record=RuntimeError("bolt unreachable"))
        recorder = BenchmarkKGRecorder(store=store)
        assert recorder.record(_challenge(), _result()) is None

    def test_disabled_recorder_is_a_noop(self) -> None:
        recorder = BenchmarkKGRecorder(store=None)
        assert recorder.enabled is False
        assert recorder.record(_challenge(), _result()) is None

    def test_no_password_env_disables_store(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("BUGGY_NEO4J_PASSWORD", raising=False)
        monkeypatch.delenv("NEO4J_PASSWORD", raising=False)
        recorder = BenchmarkKGRecorder()
        assert recorder.enabled is False
