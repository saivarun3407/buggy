"""Unit tests for :class:`CoordinatorMiddleware` and ``view_agent_graph``.

Driver-free. Covers registration via ``before_agent``, its idempotency, the
``_merge_agent_graph`` concurrency reducer, the plain-text tree rendering, and
that the COORDINATOR slot resolves through ``build_middleware``.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock, patch

from buggy.agents import build as build_module
from buggy.middleware.coordinator import (
    CoordinatorMiddleware,
    CoordinatorState,
    _merge_agent_graph,
)
from buggy.tools.coordinator import build_coordinator_tools, render_agent_graph
from buggy_core import plugin_loader
from buggy_core.contracts.slots import MiddlewareSlot


def _apply(state: dict[str, Any], update: dict[str, Any] | None) -> dict[str, Any]:
    """Thread a ``before_agent`` update back onto state via the real reducers."""
    if not update:
        return state
    new_state = dict(state)
    if "agent_graph" in update:
        new_state["agent_graph"] = _merge_agent_graph(
            state.get("agent_graph"), update["agent_graph"]
        )
    if "agent_counter" in update:
        new_state["agent_counter"] = update["agent_counter"]
    return new_state


def _call_tool(tool: Any, state: dict[str, Any]) -> str:
    """Invoke a coordinator tool with a synthetic ToolCall envelope."""
    command = tool.invoke(
        {
            "name": getattr(tool, "name", "tool"),
            "type": "tool_call",
            "id": "test-call-id",
            "args": {"state": state},
        }
    )
    messages = getattr(command, "update", {}).get("messages") or []
    return getattr(messages[-1], "content", "") if messages else ""


def test_state_schema_is_coordinator_state() -> None:
    assert CoordinatorMiddleware.state_schema is CoordinatorState


# ── before_agent registration ───────────────────────────────────────────


def test_before_agent_registers_node_with_role_status_parent() -> None:
    mw = CoordinatorMiddleware(role="buggy")
    update = mw.before_agent({}, runtime=None)

    assert update is not None
    graph = update["agent_graph"]
    assert update["agent_counter"] == 1
    assert list(graph) == ["buggy-1"]

    node = graph["buggy-1"]
    assert node["role"] == "buggy"
    assert node["status"] == "running"
    assert node["parent_id"] is None
    assert node["agent_id"] == "buggy-1"
    assert isinstance(node["spawned_at"], str) and node["spawned_at"]


def test_before_agent_seeds_id_from_existing_counter() -> None:
    mw = CoordinatorMiddleware(role="recon")
    update = mw.before_agent({"agent_counter": 4}, runtime=None)
    assert update is not None
    assert update["agent_counter"] == 5
    assert list(update["agent_graph"]) == ["recon-5"]


# ── idempotency ─────────────────────────────────────────────────────────


def test_before_agent_is_idempotent_when_state_is_threaded() -> None:
    mw = CoordinatorMiddleware(role="buggy")
    state: dict[str, Any] = {}
    state = _apply(state, mw.before_agent(state, runtime=None))

    second = mw.before_agent(state, runtime=None)

    assert second is None
    assert state["agent_counter"] == 1
    assert list(state["agent_graph"]) == ["buggy-1"]


def test_re_register_does_not_bump_counter_even_without_threading() -> None:
    mw = CoordinatorMiddleware(role="buggy")
    first = mw.before_agent({}, runtime=None)
    assert first is not None

    # State lost the registration (empty graph): the agent re-emits the SAME
    # node to restore it, and never bumps the counter again.
    second = mw.before_agent({}, runtime=None)
    assert second is not None
    assert "agent_counter" not in second
    assert second["agent_graph"] == first["agent_graph"]


# ── _merge_agent_graph reducer ──────────────────────────────────────────


def test_merge_unions_distinct_ids() -> None:
    a = {"buggy-1": {"agent_id": "buggy-1", "role": "buggy", "status": "running"}}
    b = {"recon-2": {"agent_id": "recon-2", "role": "recon", "status": "running"}}
    merged = _merge_agent_graph(a, b)
    assert set(merged) == {"buggy-1", "recon-2"}
    assert merged["buggy-1"]["role"] == "buggy"
    assert merged["recon-2"]["role"] == "recon"


def test_merge_same_id_is_per_field_last_write_wins() -> None:
    current = {"recon-2": {"agent_id": "recon-2", "role": "recon", "status": "running"}}
    update = {"recon-2": {"status": "finished"}}
    merged = _merge_agent_graph(current, update)
    # role preserved from current, status overwritten by update.
    assert merged["recon-2"] == {
        "agent_id": "recon-2",
        "role": "recon",
        "status": "finished",
    }


def test_merge_handles_empty_sides() -> None:
    assert _merge_agent_graph(None, None) == {}
    node = {"buggy-1": {"agent_id": "buggy-1", "role": "buggy", "status": "running"}}
    assert _merge_agent_graph(None, node) == node
    assert _merge_agent_graph(node, None) == node


def test_two_concurrent_registrations_both_survive_merge() -> None:
    """Parallel sub-agent registrations each carry their own node back on
    join; the reducer keeps both rather than dropping one."""
    orchestrator = CoordinatorMiddleware(role="buggy").before_agent({}, runtime=None)
    specialist = CoordinatorMiddleware(role="recon").before_agent({}, runtime=None)
    merged = _merge_agent_graph(orchestrator["agent_graph"], specialist["agent_graph"])
    assert set(merged) == {"buggy-1", "recon-1"}


# ── view_agent_graph rendering ──────────────────────────────────────────


def test_render_empty_graph_line() -> None:
    assert render_agent_graph({}) == "No agents registered yet."
    tool = build_coordinator_tools()[0]
    assert _call_tool(tool, {}) == "No agents registered yet."
    assert _call_tool(tool, {"agent_graph": {}}) == "No agents registered yet."


def test_view_agent_graph_renders_parent_child_tree_deterministically() -> None:
    graph = {
        "recon-2": {
            "agent_id": "recon-2",
            "role": "recon",
            "parent_id": "buggy-1",
            "status": "running",
            "spawned_at": "2026-01-01T00:00:02+00:00",
        },
        "buggy-1": {
            "agent_id": "buggy-1",
            "role": "buggy",
            "parent_id": None,
            "status": "waiting",
            "spawned_at": "2026-01-01T00:00:01+00:00",
        },
    }
    tool = build_coordinator_tools()[0]
    rendered = _call_tool(tool, {"agent_graph": graph})
    assert rendered == ("buggy-1 [WAITING] buggy\n  recon-2 [RUNNING] recon")


def test_render_orders_roots_by_spawned_at_then_id() -> None:
    graph = {
        "recon-2": {
            "agent_id": "recon-2",
            "role": "recon",
            "parent_id": None,
            "status": "running",
            "spawned_at": "2026-01-01T00:00:02+00:00",
        },
        "buggy-1": {
            "agent_id": "buggy-1",
            "role": "buggy",
            "parent_id": None,
            "status": "running",
            "spawned_at": "2026-01-01T00:00:01+00:00",
        },
    }
    rendered = render_agent_graph(graph)
    assert rendered.splitlines() == [
        "buggy-1 [RUNNING] buggy",
        "recon-2 [RUNNING] recon",
    ]


# ── slot wiring ─────────────────────────────────────────────────────────


def test_coordinator_slot_resolves_through_build_middleware() -> None:
    with patch.object(build_module, "entry_points", return_value=[]):
        with patch.object(plugin_loader, "entry_points", return_value=[]):
            stack = build_module.build_middleware(
                role="buggy",
                slots=frozenset({MiddlewareSlot.COORDINATOR}),
                backend=MagicMock(),
                llm=MagicMock(),
                fallback_models=None,
            )
    coordinators = [m for m in stack if isinstance(m, CoordinatorMiddleware)]
    assert len(coordinators) == 1
    assert "view_agent_graph" in {t.name for t in coordinators[0].tools}
