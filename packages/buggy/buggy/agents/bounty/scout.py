"""Bounty Scout — autonomous bug-bounty intake / program-selection agent.

The front door to the ``bounty`` bundle. The scout authenticates to the
HackerOne and Bugcrowd APIs (token identifier + value read from the
environment only), lists the programs the operator can access, and walks
a strict human-in-the-loop selection flow:

  authenticate → list open programs → operator picks one → fetch the
  program's structured scope + exclusions + reporting policy → operator
  confirms in-scope / out-of-scope / excluded classes → operator confirms
  reporting requirements and per-program rules → ``ingest_bounty_scope``
  writes the hard-enforced RoE (command parser + sandbox egress allowlist)
  → hand off to recon / ASVS / the specialist slate.

Per-program rules (no automated scanning, request-rate caps) are parsed
from the policy and, once the operator confirms, folded into the enforced
RoE — not merely displayed. The scout adds the platform-intake tools on
top of the shared bounty-workflow surface; everything else (slot stack,
skills, reporting) matches the rest of the bundle.
"""

from __future__ import annotations

from typing import Any

from buggy.agents.bounty._common import make_bounty_agent
from buggy.tools.research.bounty_intake import BOUNTY_INTAKE_TOOLS
from buggy_core.plugin_loader import SubAgentSpec, is_bundle_enabled

_ROLE = "scout"

# Platform-intake tools are the scout's lane-specific surface: list /
# fetch program scope from the HackerOne + Bugcrowd APIs and analyze
# per-program rules. ``ingest_bounty_scope`` itself is already part of the
# shared bounty-workflow surface every bundle agent carries.
_DOMAIN_TOOLS: list[Any] = list(BOUNTY_INTAKE_TOOLS)

create_scout_agent = make_bounty_agent(role=_ROLE, domain_tools=_DOMAIN_TOOLS)


# Module-level graph for LangGraph Platform (langgraph serve).
if is_bundle_enabled("bounty"):
    graph = create_scout_agent()


SUBAGENT_SPEC = SubAgentSpec(
    name=_ROLE,
    description=(
        "Bug-bounty intake / program-selection specialist. Dispatch FIRST, "
        "before recon, to set up a HackerOne / Bugcrowd engagement: it lists "
        "the programs your API token can access, has you pick one, fetches the "
        "program's structured scope + exclusions + reporting policy, confirms "
        "scope and per-program rules with you, then hard-enforces them into "
        "the RoE (command parser + sandbox egress) before any testing begins."
    ),
    factory=create_scout_agent,
    parent_agents=("buggy",),
    bundle="bounty",
    priority=59,
)
