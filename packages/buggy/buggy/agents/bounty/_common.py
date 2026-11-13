"""Shared factory scaffolding for the fork-only ``bounty`` bundle.

The ten bounty specialists share an identical factory shape — only the
role name, the domain-specific tool set, the skill sources, and the
system prompt differ. This module centralises the boilerplate so each
agent file declares just its distinguishing parts and calls
:func:`make_bounty_agent`.

Every bounty agent is a bash-executing, RoE-scoped, HITL-gated
specialist attached to the ``buggy`` orchestrator — all ten map to
the standard bash-agent slot stack in ``SLOTS_PER_ROLE`` (so they
inherit ENGAGEMENT_CONTEXT for RoE scope injection, SANDBOX_NOTIFICATION,
and HITL_APPROVAL). They all carry the bug-bounty workflow tools (scope
ingestion → enforced RoE, scope check, HackerOne / Bugcrowd report
generation) plus a shared research surface (payload libraries,
disclosed-report search, CVE PoC lookup, kill-chain mapping, RoE-gated
web acquisition) on top of their domain tools, so any bounty specialist
can scope-check a finding and emit a platform-ready submission.

Factory shape mirrors ``langchain.agents.create_agent`` — every keyword
is optional and explicit values fully replace the OSS baseline — so the
bounty specialists stay interchangeable with the standard / plugin
agents and pick up plugin tool / middleware / prompt overrides via
``build_tools`` / ``build_middleware`` / ``load_prompt`` automatically.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from typing import Any

from langchain.agents import create_agent

from buggy.agents.build import build_middleware, build_tools
from buggy.agents.prompts import load_prompt
from buggy.backends import build_sandbox_backend, make_agent_backend
from buggy.llm import LLMFactory
from buggy.tools.assessment import ASSESSMENT_REVIEW_TOOLS
from buggy.tools.bash import BASH_TOOLS
from buggy.tools.bash.bash import set_sandbox
from buggy.tools.references.tools import (
    cve_poc_lookup,
    h1_search,
    killchain_lookup,
    oneliner_search,
    payload_search,
    ref_suggest,
)
from buggy.tools.reporting.tools import report_bugcrowd_csv, report_hackerone
from buggy.tools.research.bounty import BOUNTY_TOOLS
from buggy.tools.research.bounty_scope import BOUNTY_SCOPE_TOOLS
from buggy.tools.research.structured_findings import emit_structured_finding
from buggy.tools.web.search import web_fetch, web_search
from buggy_core.plugin_loader import load_plugin_callbacks

# Bundle label shared by every bounty ``SUBAGENT_SPEC`` and used to build
# the per-role skill source paths (``/skills/bounty/<role>/``).
BUNDLE = "bounty"

# Bounty work is deep and iterative (audit a whole ASVS chapter, chain a
# multi-step business-logic abuse); match the standard bash specialists.
_DEFAULT_RECURSION_LIMIT = 1000

# Bug-bounty workflow surface shared by every bounty specialist: ingest a
# pasted program scope into the enforced RoE, scope-check a candidate
# finding, and render HackerOne / Bugcrowd submissions.
_BOUNTY_WORKFLOW_TOOLS: list[Any] = [
    *BOUNTY_SCOPE_TOOLS,
    *BOUNTY_TOOLS,
    *ASSESSMENT_REVIEW_TOOLS,
    report_hackerone,
    report_bugcrowd_csv,
    emit_structured_finding,
]

# Research / reference surface — payload libraries, disclosed-report
# search, CVE PoC lookup, kill-chain mapping, and RoE-gated web
# acquisition. Shared by every specialist on top of its domain tools.
_REFERENCE_TOOLS: list[Any] = [
    ref_suggest,
    payload_search,
    h1_search,
    cve_poc_lookup,
    oneliner_search,
    killchain_lookup,
    web_search,
    web_fetch,
]


def bounty_skill_sources(role: str) -> list[str]:
    """Skill source paths for a bounty ``role`` — bundle skills + shared."""
    return [f"/skills/{BUNDLE}/{role}/", "/skills/shared/"]


def build_bounty_tools(role: str, domain_tools: Sequence[Any]) -> list[Any]:
    """Compose a bounty specialist's tools and run them through ``build_tools``.

    ``domain_tools`` (the role's lane-specific tools) are layered ahead of
    the shared bounty-workflow, research, and bash surfaces, name-keyed so
    plugin overrides can target any tool, then resolved via the standard
    ``build_tools`` pipeline (plugin additions / disables applied).
    """
    standard: dict[str, Any] = {
        t.name: t
        for t in [
            *_BOUNTY_WORKFLOW_TOOLS,
            *_REFERENCE_TOOLS,
            *BASH_TOOLS,
            *domain_tools,
        ]
    }
    return build_tools(role=role, standard_tools=standard)


def make_bounty_agent(
    *,
    role: str,
    domain_tools: Sequence[Any],
    recursion_limit: int = _DEFAULT_RECURSION_LIMIT,
) -> Callable[..., Any]:
    """Build a langchain-style factory for the bounty specialist ``role``.

    Args:
        role: agent role name. Must be present in ``SLOTS_PER_ROLE`` (all
            ten bounty roles are) so ``build_middleware`` resolves its slot
            stack, and in ``AGENT_TIERS`` / ``AGENT_TEMPERATURES`` so the
            model factory can build its model.
        domain_tools: the role's lane-specific tools, layered ahead of the
            shared bounty-workflow / research / bash surfaces.
        recursion_limit: default ``with_config`` recursion limit for the
            compiled agent.

    Returns:
        A zero-arg-capable factory (every keyword optional) returning the
        compiled LangGraph agent. Suitable both as ``SubAgentSpec.factory``
        and for direct library use.
    """
    skill_sources = bounty_skill_sources(role)
    default_recursion_limit = recursion_limit

    def factory(
        *,
        # ── Dependencies (injected for testing / library composition) ──
        backend: Any = None,
        llm: Any = None,
        fallback_models: list | None = None,
        sandbox: Any = None,
        # ── langchain-style composition (full replace when provided) ───
        tools: list[Any] | None = None,
        middleware: list[Any] | None = None,
        system_prompt: str | None = None,
        # ── Tuning ─────────────────────────────────────────────────────
        recursion_limit: int | None = None,
    ):
        if llm is None or fallback_models is None:
            llm_factory = LLMFactory()
            if llm is None:
                llm = llm_factory.get_model(role)
            if fallback_models is None:
                fallback_models = llm_factory.get_fallback_models(role)

        if sandbox is None:
            sandbox = build_sandbox_backend()
        set_sandbox(sandbox)

        if backend is None:
            backend = make_agent_backend(sandbox)

        if tools is None:
            tools = build_bounty_tools(role, domain_tools)
        if middleware is None:
            middleware = build_middleware(
                role=role,
                skill_sources=skill_sources,
                backend=backend,
                llm=llm,
                fallback_models=fallback_models,
                sandbox=sandbox,
            )
        if system_prompt is None:
            # ``bounty_workflow`` is the shared bug-bounty fragment
            # (scope-ingestion → enforced RoE → scope-check → HackerOne /
            # Bugcrowd reporting) appended to every bounty specialist so
            # the scope discipline and submission pipeline stay identical
            # across the slate without duplicating it in ten prompt files.
            system_prompt = load_prompt(role, shared=["bash", "bounty_workflow"])

        return create_agent(
            llm,
            system_prompt=system_prompt,
            tools=tools,
            middleware=middleware,
            name=role,
        ).with_config(
            {
                "recursion_limit": recursion_limit or default_recursion_limit,
                "callbacks": load_plugin_callbacks(role=role, backend=backend),
            }
        )

    # Give the closure a descriptive identity for tracebacks / repr — every
    # bounty file aliases the return value to ``create_<role>_agent`` anyway.
    factory.__name__ = f"create_{role}_agent"
    factory.__qualname__ = factory.__name__
    return factory
