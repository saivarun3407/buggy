"""Retrospective Agent -- post-engagement self-healing feedback loop.

Runs as the LAST sub-agent dispatch before the orchestrator writes its
final report.  Reads ``events.jsonl`` and the OPPLAN to detect failures,
tool issues, access problems, efficiency gaps, and coverage gaps.
Produces ``retro/RETROSPECTIVE.md`` with actionable improvement
requirements and a product-manager-ready backlog table.

Design mirrors :mod:`buggy.agents.standard.blue_cell`:

- **Read-only**: no bash tool, no sandbox, no SandboxNotification slot.
  The retrospective agent only reads workspace artifacts and writes a
  single report file.
- **No KG writes**: purely analytical -- reads events and OPPLAN, does
  not modify the knowledge graph or engagement state.

Tool surface:
    ``retro_analyze_events`` -- statistical analysis of events.jsonl
    ``retro_analyze_objectives`` -- OPPLAN gap analysis
    ``retro_write_report`` -- writes retro/RETROSPECTIVE.md

Middleware stack -- ``_BASE_SLOTS`` (same as ``blue_cell``): no bash,
no KG writes, no sandbox notification.

Library API
-----------
Factory shape mirrors ``langchain.agents.create_agent`` /
``deepagents.create_deep_agent`` -- every keyword is optional, and
explicit values fully replace the OSS baseline.
"""

from __future__ import annotations

from typing import Any

from langchain.agents import create_agent

from buggy.agents.build import build_middleware, build_tools
from buggy.agents.prompts import load_prompt
from buggy.backends import build_sandbox_backend, make_agent_backend
from buggy.llm import LLMFactory
from buggy.tools.research.retrospective import RETROSPECTIVE_TOOLS
from buggy_core.plugin_loader import SubAgentSpec, is_bundle_enabled, load_plugin_callbacks

_STANDARD_TOOLS: dict[str, Any] = {t.name: t for t in RETROSPECTIVE_TOOLS}

_ROLE = "retrospective"
_RECURSION_LIMIT = 60


def create_retrospective_agent(
    *,
    backend: Any = None,
    llm: Any = None,
    fallback_models: list | None = None,
    tools: list[Any] | None = None,
    middleware: list[Any] | None = None,
    system_prompt: str | None = None,
    recursion_limit: int | None = None,
):
    """Build the Retrospective agent.

    Notes:
      - Read-only: no sandbox bash access (no ``sandbox=`` arg, no
        ``set_sandbox()`` call, no ``SandboxNotification`` slot).
      - Reads ``events.jsonl`` and ``plan/opplan.json`` from the
        workspace directory; writes ``retro/RETROSPECTIVE.md``.

    Args:
        backend: deepagents-style filesystem backend.
        llm: bound chat model. Defaults to
            ``LLMFactory().get_model("retrospective")``.
        fallback_models: passed to ``ModelFallbackMiddleware``.
        tools: full tool list -- when provided, replaces the standard
            registry entirely.
        middleware: full middleware list -- when provided, replaces the
            OSS slot stack entirely.
        system_prompt: full prompt -- when provided, replaces the
            baseline.
        recursion_limit: ``with_config({"recursion_limit": ...})``
            override. Defaults to 60.

    Returns:
        Compiled LangGraph agent.
    """
    if llm is None or fallback_models is None:
        factory = LLMFactory()
        if llm is None:
            llm = factory.get_model(_ROLE)
        if fallback_models is None:
            fallback_models = factory.get_fallback_models(_ROLE)

    # No set_sandbox() -- Retrospective intentionally has no bash tool.
    sandbox = build_sandbox_backend()

    if backend is None:
        backend = make_agent_backend(sandbox)

    if tools is None:
        tools = build_tools(role=_ROLE, standard_tools=_STANDARD_TOOLS)
    if middleware is None:
        middleware = build_middleware(
            role=_ROLE,
            backend=backend,
            llm=llm,
            fallback_models=fallback_models,
            sandbox=None,  # no SandboxNotification for read-only agent
        )
    if system_prompt is None:
        system_prompt = load_prompt(_ROLE, shared=[])

    return create_agent(
        llm,
        system_prompt=system_prompt,
        tools=tools,
        middleware=middleware,
        name=_ROLE,
    ).with_config(
        {
            "recursion_limit": recursion_limit or _RECURSION_LIMIT,
            "callbacks": load_plugin_callbacks(role=_ROLE, backend=backend),
        }
    )


# Module-level graph for LangGraph Platform (langgraph serve)
if is_bundle_enabled("standard"):
    graph = create_retrospective_agent()


SUBAGENT_SPEC = SubAgentSpec(
    name="retrospective",
    description=(
        "Retrospective agent -- post-engagement self-healing feedback loop. "
        "Analyzes events.jsonl and the OPPLAN for agent failures, tool "
        "failures, access issues, efficiency gaps, and coverage gaps. "
        "Produces retro/RETROSPECTIVE.md with actionable improvement "
        "requirements and a product backlog table. Read-only (no bash). "
        "Dispatch as the LAST sub-agent before the final report."
    ),
    factory=create_retrospective_agent,
    parent_agents=("buggy",),
    bundle="standard",
    priority=95,  # after blue_cell (90), before final report
)
