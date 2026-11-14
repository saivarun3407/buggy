"""CoordinatorMiddleware — the addressable agent-graph registry for a run.

Mirrors :class:`OPPLANMiddleware` (buggy/middleware/opplan.py) and
:class:`KGMiddleware` (buggy/middleware/kg.py): an ``AgentState`` subclass
with ``OmitFromInput`` channels plus concurrency reducers, tools built in
``__init__`` via a factory, and lifecycle hooks. Once attached to an agent
the agent is registered into a shared ``agent_graph`` and gains the
read-only ``view_agent_graph`` tool to inspect the live roster.

Hooks:

  * ``before_agent``    — register this agent into ``agent_graph`` with a
                          stable id, ``status="running"``, and a spawn
                          timestamp. Idempotent per instance.
  * ``wrap_model_call`` — inject the short, cache-friendly system-prompt
                          block that tells the agent ``view_agent_graph``
                          exists.

The registry is a ``dict[str, AgentNode]`` keyed by ``agent_id`` — a table,
not a branching structure. ``status`` is a state machine, not a set of
booleans. Messaging between agents is deliberately absent here; this slot
owns visibility only.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Annotated, Any, Literal, NotRequired, TypedDict, cast, override

from langchain.agents import AgentState
from langchain.agents.middleware import AgentMiddleware
from langchain.agents.middleware.types import OmitFromInput
from langchain_core.messages import SystemMessage

from buggy.middleware.state_reducers import reduce_converging_value
from buggy.tools.coordinator import build_coordinator_tools

AgentStatus = Literal["running", "waiting", "finished", "stopped", "error"]


class AgentNode(TypedDict):
    """One agent in the run's coordination graph (serialized to a dict in state)."""

    agent_id: str
    role: str
    parent_id: str | None
    status: AgentStatus
    spawned_at: str


def _merge_agent_graph(
    current: dict[str, dict] | None,
    update: dict[str, dict] | None,
) -> dict[str, dict]:
    """Per-agent-id merge of concurrent registry writes.

    Union of ids; for an id both sides carry, ``update``'s node fields
    overwrite the existing ones (last-write-wins per field). Without this,
    parallel sub-agent registrations in one superstep trip LangGraph's
    INVALID_CONCURRENT_GRAPH_UPDATE — the same hazard the opplan
    ``_reduce_*`` reducers exist to close. This is the structural merge an
    accumulating channel needs; last-write-wins on the whole value would
    drop a concurrent branch's node.
    """
    if not update:
        return current or {}
    merged = dict(current or {})
    for agent_id, node in update.items():
        existing = merged.get(agent_id)
        merged[agent_id] = {**existing, **node} if existing else dict(node)
    return merged


class CoordinatorState(AgentState):
    """Agent state carrying the run's agent registry.

    Both channels are ``OmitFromInput`` — only this middleware writes them.
    """

    agent_graph: Annotated[NotRequired[dict[str, dict]], OmitFromInput, _merge_agent_graph]
    """Registry of every agent in the run, keyed by ``agent_id``."""

    agent_counter: Annotated[NotRequired[int], OmitFromInput, reduce_converging_value]
    """Monotonic seed for agent ids. Each agent registers exactly once
    (idempotent, instance-bound), so concurrent writers all carry a value
    derived from the same prior count and last-write-wins-on-non-None is
    sufficient — mirrors opplan's convergent-channel reducers."""


COORDINATOR_SYSTEM_PROMPT = (
    "## Agent coordination graph\n"
    "Other agents may be running in this engagement alongside you.\n"
    "Call `view_agent_graph()` to see the live tree of agents — each one's\n"
    "id, role, and status. It is read-only: it reports who is running, it\n"
    "does not message anyone or change anything."
)


class CoordinatorMiddleware(AgentMiddleware):
    """Register the attached agent into the run's coordination graph.

    Parameters
    ----------
    role
        The role of the agent this middleware is attached to. Supplied by
        the slot factory (``_make_coordinator``) from ``build_middleware``.
    """

    state_schema = CoordinatorState

    def __init__(self, *, role: str) -> None:
        super().__init__()
        self._role = role
        self._agent_id: str | None = None
        self._node: AgentNode | None = None
        self.tools = build_coordinator_tools()

    @override
    def before_agent(self, state: Any, runtime: Any) -> dict[str, Any] | None:
        return self._register(state)

    @override
    async def abefore_agent(self, state: Any, runtime: Any) -> dict[str, Any] | None:
        return self._register(state)

    def _register(self, state: Any) -> dict[str, Any] | None:
        """Register this agent, converging to a single node for its lifetime.

        First call allocates an id from the monotonic counter and records the
        node on the instance. A later call re-emits that same node only if the
        graph has lost it, and otherwise no-ops — so repeats never duplicate a
        node nor bump the counter again.
        """
        get = state.get if hasattr(state, "get") else (lambda _k, _d=None: _d)
        graph = get("agent_graph") or {}

        if self._node is not None:
            if graph.get(self._agent_id) == self._node:
                return None
            return {"agent_graph": {self._agent_id: self._node}}

        counter = int(get("agent_counter") or 0) + 1
        agent_id = f"{self._role}-{counter}"
        node: AgentNode = {
            "agent_id": agent_id,
            "role": self._role,
            "parent_id": None,
            "status": "running",
            "spawned_at": datetime.now(timezone.utc).isoformat(),
        }
        self._agent_id = agent_id
        self._node = node
        return {"agent_graph": {agent_id: dict(node)}, "agent_counter": counter}

    @override
    def wrap_model_call(self, request: Any, handler: Any) -> Any:
        return handler(self._inject_context(request))

    @override
    async def awrap_model_call(self, request: Any, handler: Any) -> Any:
        return await handler(self._inject_context(request))

    def _inject_context(self, request: Any) -> Any:
        """Append the coordinator prompt as a single cache-eligible block.

        The block is identical every turn, so it anchors a prompt-cache
        breakpoint the same way ``KGMiddleware`` and ``OPPLANMiddleware`` do.
        The live roster is fetched on demand via ``view_agent_graph`` rather
        than injected here, so nothing dynamic rides along.
        """
        block: dict[str, Any] = {
            "type": "text",
            "text": "\n\n" + COORDINATOR_SYSTEM_PROMPT,
            "cache_control": {"type": "ephemeral"},
        }
        if request.system_message is not None:
            new_content = [*request.system_message.content_blocks, block]
        else:
            new_content = [block]
        new_system = SystemMessage(content=cast("list[str | dict[str, str]]", new_content))
        return request.override(system_message=new_system)


__all__ = [
    "AgentNode",
    "AgentStatus",
    "CoordinatorMiddleware",
    "CoordinatorState",
    "COORDINATOR_SYSTEM_PROMPT",
    "_merge_agent_graph",
]
