"""Agent-coordination tools — a read-only view over the run's agent registry.

Mirrors ``buggy.tools.opplan``: a ``build_*_tools()`` factory and a
``*_TOOL_NAMES`` set. The single tool here, ``view_agent_graph``, renders the
``agent_graph`` channel owned by ``CoordinatorMiddleware`` as a plain-text
tree. It mutates nothing — it only reports the live roster.
"""

from __future__ import annotations

from typing import Annotated, Any

from langchain_core.messages import ToolMessage
from langchain_core.tools import InjectedToolCallId, tool
from langgraph.prebuilt import InjectedState
from langgraph.types import Command

COORDINATOR_TOOL_NAMES: frozenset[str] = frozenset({"view_agent_graph"})

_EMPTY_GRAPH_LINE = "No agents registered yet."


def render_agent_graph(agent_graph: dict[str, dict]) -> str:
    """Render the registry as an indented tree.

    Roots (no parent, or a parent id absent from the graph) come first; a
    node's children are indented two spaces under it. Siblings and roots are
    ordered by ``spawned_at`` then ``agent_id`` so the output is
    deterministic. Every registered agent appears exactly once, even if its
    parent linkage forms an orphan or a cycle.
    """
    if not agent_graph:
        return _EMPTY_GRAPH_LINE

    children: dict[str | None, list[dict]] = {}
    for node in agent_graph.values():
        parent = node.get("parent_id")
        if parent not in agent_graph:
            parent = None
        children.setdefault(parent, []).append(node)

    def _order(node: dict) -> tuple[str, str]:
        return (node.get("spawned_at") or "", node.get("agent_id") or "")

    lines: list[str] = []
    visited: set[str] = set()

    def _emit(node: dict, depth: int) -> None:
        agent_id = node.get("agent_id", "?")
        if agent_id in visited:
            return
        visited.add(agent_id)
        status = str(node.get("status", "")).upper()
        role = node.get("role", "?")
        lines.append(f"{'  ' * depth}{agent_id} [{status}] {role}")
        for child in sorted(children.get(agent_id, []), key=_order):
            _emit(child, depth + 1)

    for root in sorted(children.get(None, []), key=_order):
        _emit(root, 0)
    for node in sorted(agent_graph.values(), key=_order):
        _emit(node, 0)

    return "\n".join(lines)


def build_coordinator_tools() -> list:
    """Create the coordination tools with ``InjectedState`` for direct reads."""

    @tool(
        description=(
            "Show the live tree of agents running in this engagement. "
            "Returns each agent's id, status, and role, with children "
            "indented under their parent. Read-only — it reports the current "
            "roster and changes nothing."
        )
    )
    def view_agent_graph(
        state: Annotated[dict, InjectedState],
        tool_call_id: Annotated[str, InjectedToolCallId] = "",
    ) -> Command[Any]:
        """Render the agent graph from state as a plain-text tree."""
        graph = state.get("agent_graph") or {}
        return Command(
            update={
                "messages": [
                    ToolMessage(content=render_agent_graph(graph), tool_call_id=tool_call_id)
                ],
            }
        )

    return [view_agent_graph]


__all__ = [
    "COORDINATOR_TOOL_NAMES",
    "build_coordinator_tools",
    "render_agent_graph",
]
