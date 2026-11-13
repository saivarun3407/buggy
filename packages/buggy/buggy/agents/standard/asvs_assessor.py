"""ASVS Assessor Agent — systematic OWASP ASVS compliance auditor.

Specialist (non-orchestrator) bash-using agent designed for structured,
control-by-control ASVS assessments. Unlike the recon agent (observe-only,
no classification) or the analyst (free-form vulnerability hunting), the
ASVS Assessor walks each ASVS requirement in order, renders a PASS/FAIL/N-A
verdict backed by both white-box code review and live HTTP testing, and
produces a structured coverage matrix.

Tool surface: BASH_TOOLS + REPORTING_TOOLS + REFERENCES_TOOLS + web search/fetch.
Same as analyst minus the KG tools (the assessor produces a structured
markdown register rather than graph nodes).

Middleware stack — standard bash-agent slots
(``SLOTS_PER_ROLE["asvs_assessor"]``):

  ENGAGEMENT_CONTEXT → ROE_GUARDRAIL → HITL_APPROVAL → UNTRUSTED_OUTPUT
    → PROMPT_INJECTION_SHIELD → SKILLS → FILESYSTEM → EVENT_LOG
    → SANDBOX_NOTIFICATION → BUDGET → MODEL_FALLBACK → SUMMARIZATION
    → PROMPT_CACHING → PATCH_TOOL_CALLS

Library API
-----------
Factory shape mirrors ``langchain.agents.create_agent`` /
``deepagents.create_deep_agent`` — every keyword is optional, and
explicit values fully replace the OSS baseline:

  - ``tools=[...]``         full tool list (overrides the standard set)
  - ``middleware=[...]``    full middleware list (overrides the slot stack)
  - ``system_prompt="..."`` full prompt (overrides the loaded baseline)

When a keyword is ``None`` (default), the factory builds the OSS
baseline AND applies any plugin overrides discovered via the
``buggy.bundles`` entry-point group.
"""

from __future__ import annotations

from typing import Any

from langchain.agents import create_agent

from buggy.agents._benchmark_mode import benchmark_skill_sources
from buggy.agents.build import build_middleware, build_tools
from buggy.agents.prompts import load_prompt
from buggy.backends import build_sandbox_backend, make_agent_backend
from buggy.llm import LLMFactory
from buggy.tools.assessment import ASSESSMENT_REVIEW_TOOLS
from buggy.tools.bash import BASH_TOOLS
from buggy.tools.bash.bash import set_sandbox
from buggy.tools.references.tools import REFERENCES_TOOLS
from buggy.tools.reporting.tools import REPORTING_TOOLS
from buggy.tools.web.search import web_fetch, web_search
from buggy_core.plugin_loader import SubAgentSpec, is_bundle_enabled, load_plugin_callbacks

_STANDARD_TOOLS: dict[str, Any] = {
    t.name: t
    for t in [
        web_search,
        web_fetch,
        *REPORTING_TOOLS,
        *REFERENCES_TOOLS,
        *BASH_TOOLS,
        *ASSESSMENT_REVIEW_TOOLS,
    ]
}


_ROLE = "asvs_assessor"
_RECURSION_LIMIT = 1000
_SKILL_SOURCES: list[str] = [
    "/skills/standard/analyst/",
    "/skills/standard/recon/",
    "/skills/shared/",
]


def create_asvs_assessor_agent(
    *,
    # ── Dependencies (injected for testing / library composition) ────
    backend: Any = None,
    llm: Any = None,
    fallback_models: list | None = None,
    sandbox: Any = None,
    # ── langchain-style composition (full replace when provided) ─────
    tools: list[Any] | None = None,
    middleware: list[Any] | None = None,
    system_prompt: str | None = None,
    # ── Tuning ───────────────────────────────────────────────────────
    recursion_limit: int | None = None,
):
    """Build the ASVS Assessor agent.

    Args:
        backend: deepagents-style filesystem backend. Defaults to
            ``make_agent_backend(build_sandbox_backend())``.
        llm: bound chat model. Defaults to
            ``LLMFactory().get_model("asvs_assessor")``.
        fallback_models: passed to ``ModelFallbackMiddleware``. Defaults
            to ``LLMFactory().get_fallback_models("asvs_assessor")``.
        sandbox: sandbox backend for bash execution and
            ``SandboxNotificationMiddleware``. Defaults to
            ``build_sandbox_backend()``.
        tools: full tool list — when provided, replaces the standard
            registry entirely. When ``None`` (default), the OSS
            baseline is built and plugin overrides (via
            ``buggy.bundles``) are applied.
        middleware: full middleware list — when provided, replaces the
            OSS slot stack entirely. When ``None``, the baseline is
            assembled with plugin slot overrides applied.
        system_prompt: full prompt — when provided, replaces the
            baseline. When ``None``, the standard prompt is loaded and
            plugin prompt overrides are applied.
        recursion_limit: ``with_config({"recursion_limit": ...})``
            override. Defaults to 1000.

    Returns:
        Compiled LangGraph agent.
    """
    if llm is None or fallback_models is None:
        factory = LLMFactory()
        if llm is None:
            llm = factory.get_model(_ROLE)
        if fallback_models is None:
            fallback_models = factory.get_fallback_models(_ROLE)

    if sandbox is None:
        sandbox = build_sandbox_backend()
    set_sandbox(sandbox)

    if backend is None:
        backend = make_agent_backend(sandbox)

    if tools is None:
        tools = build_tools(role=_ROLE, standard_tools=_STANDARD_TOOLS)
    if middleware is None:
        middleware = build_middleware(
            role=_ROLE,
            skill_sources=[*_SKILL_SOURCES, *benchmark_skill_sources()],
            backend=backend,
            llm=llm,
            fallback_models=fallback_models,
            sandbox=sandbox,
        )
    if system_prompt is None:
        system_prompt = load_prompt(_ROLE, shared=["bash"])

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
    graph = create_asvs_assessor_agent()


SUBAGENT_SPEC = SubAgentSpec(
    name="asvs_assessor",
    description=(
        "OWASP ASVS compliance assessor — systematic, control-by-control "
        "security verification. Use for: structured ASVS L1/L2/L3 assessments, "
        "compliance audits, security control verification matrices, and any "
        "task requiring per-requirement pass/fail/N-A verdicts with dual-mode "
        "evidence (white-box code review + live HTTP testing). Produces a "
        "structured coverage matrix in recon/asvs-register.md and promotes "
        "critical/high failures to findings/FIND-NNN.md. NOT for free-form "
        "vulnerability hunting (use analyst) or raw observation (use recon)."
    ),
    factory=create_asvs_assessor_agent,
    parent_agents=("buggy",),
    bundle="standard",
    priority=30,
)
