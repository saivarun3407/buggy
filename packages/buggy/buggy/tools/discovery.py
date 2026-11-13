"""Registry-backed capability discovery for agents.

Turns the machine-readable Kali capability registry
(:mod:`buggy_core.capabilities`) into an agent-callable search tool
so a specialist can ask "what tool do I have for X, and how do I reach
it?" BEFORE hand-rolling a curl/Python loop or assuming a tool is
missing. Read-only: it inspects the static registry, runs no commands,
and touches no engagement state — so it carries no RoE/sandbox context
and is safe for every role.

The tool is role-aware. ``make_capability_search(role)`` binds an
agent's role so its discovery is scoped to what the role is expected and
allowed to reach: the role's :data:`ROLE_CAPABILITY_POLICY` default risk
ceiling is applied when the agent does not pass ``max_risk``, per-tool
role allowlists are honored, and the tools most relevant to the role's
kill-chain phases are surfaced under ``recommended_for_role``. None of
this hides tools the agent explicitly asks for — a higher ``max_risk``
always widens the search, and execution stays governed by RoE / HITL.
"""

from __future__ import annotations

import json
from typing import Any

from langchain_core.tools import tool

from buggy_core.capabilities import (
    RiskTier,
    reach_instruction,
    role_capability_policy,
    search_capabilities,
)

# Cap the payload so a broad query can't flood the model's context. The
# response tells the agent how many matched and how to narrow.
_RESULT_CAP = 40

_DESCRIPTION = (
    "Search the Kali capability registry for security tools that are actually "
    "installed/available on this platform, and learn how to reach each one "
    "(run in bash, activate a profile, use a sidecar's dedicated tools, or "
    "pip-install). Use this BEFORE writing a custom script or concluding a "
    "tool is unavailable. Optional filters (AND-combined): query (free-text "
    "over id/description/binaries/category), category (e.g. recon, web, ad, "
    "reversing, credentials), phase (MITRE tactic id e.g. TA0006), max_risk "
    "(passive|bounded_active|intrusive|high_impact|hardware), include_planned "
    "(also show not-yet-installed tools). Results are scoped to your role's "
    "default risk ceiling unless you pass max_risk. Returns JSON; runs no commands."
)


def make_capability_search(role: str | None = None) -> Any:
    """Build a role-scoped ``capability_search`` tool.

    When ``role`` maps to a :data:`ROLE_CAPABILITY_POLICY` entry, the
    returned tool applies that role's default risk ceiling (unless the
    caller passes ``max_risk``), honors per-tool role allowlists, and
    highlights the tools relevant to the role's phases. ``role=None``
    reproduces the unscoped behavior.
    """
    policy = role_capability_policy(role)

    @tool("capability_search", description=_DESCRIPTION)
    def capability_search(
        query: str = "",
        category: str = "",
        phase: str = "",
        max_risk: str = "",
        include_planned: bool = False,
    ) -> str:
        applied_defaults: dict[str, str] = {}
        effective_max_risk = max_risk
        if not effective_max_risk and policy is not None:
            effective_max_risk = policy.max_risk.name.lower()
            applied_defaults["max_risk"] = effective_max_risk

        try:
            caps = search_capabilities(
                query=query,
                category=category,
                phase=phase,
                max_risk=effective_max_risk or None,
                include_planned=include_planned,
                role=role or None,
            )
        except ValueError as exc:
            return json.dumps(
                {
                    "error": str(exc),
                    "valid_max_risk": [tier.name.lower() for tier in RiskTier],
                }
            )

        total = len(caps)
        # Surface the role's phase-relevant tools first so they survive the
        # result cap (a broad search must never truncate away exactly the
        # tools the role should be reaching for). Stable partition keeps
        # registry order within each group.
        phases = policy.phases if policy is not None else ()
        if phases:
            recommended_caps = [cap for cap in caps if any(p in phases for p in cap.phases)]
            other_caps = [cap for cap in caps if not any(p in phases for p in cap.phases)]
            caps = recommended_caps + other_caps

        shown = caps[:_RESULT_CAP]
        payload: dict[str, object] = {
            "count": total,
            "returned": len(shown),
            "capabilities": [
                {
                    "id": cap.id,
                    "category": cap.category,
                    "binaries": list(cap.binaries),
                    "delivery": cap.delivery,
                    "reach": reach_instruction(cap),
                    "risk": cap.risk_tier.name.lower(),
                    "phases": list(cap.phases),
                    "lifecycle": cap.lifecycle.value,
                    "description": cap.description,
                }
                for cap in shown
            ],
        }

        if role:
            payload["role"] = role
        if policy is not None:
            payload["role_risk_ceiling"] = policy.max_risk.name.lower()
            if policy.phases:
                payload["role_phases"] = list(policy.phases)
                recommended = [
                    cap.id for cap in shown if any(p in policy.phases for p in cap.phases)
                ]
                if recommended:
                    payload["recommended_for_role"] = recommended
        if applied_defaults:
            payload["applied_defaults"] = applied_defaults

        if total == 0:
            payload["note"] = (
                "No matching supported/preview capabilities. Try include_planned=true, "
                "a broader query, a higher max_risk, or consult the "
                "<KALI_ENVIRONMENT> prompt block."
            )
        elif total > len(shown):
            payload["note"] = (
                f"{total} matches; showing first {len(shown)}. Narrow with "
                "category/phase/max_risk or a more specific query."
            )
        return json.dumps(payload)

    return capability_search


# Unscoped default — kept as the module-level tool so BASH_TOOLS and any
# role that isn't wired through ``build_tools`` still get discovery. Each
# specialist's ``build_tools(role=...)`` swaps in a role-scoped variant.
capability_search = make_capability_search(None)

CAPABILITY_DISCOVERY_TOOLS = [capability_search]

__all__ = [
    "CAPABILITY_DISCOVERY_TOOLS",
    "capability_search",
    "make_capability_search",
]
