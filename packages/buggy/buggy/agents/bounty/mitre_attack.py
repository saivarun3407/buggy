"""MITRE ATT&CK Agent — coverage mapping, emulation, detection validation.

One agent that owns the engagement's relationship to MITRE ATT&CK:

  * **Coverage mapping** — maps observed and planned activity to ATT&CK
    tactics / techniques and produces an ATT&CK Navigator-style layer +
    technique matrix for the engagement.
  * **Adversary emulation** — turns a chosen threat profile into an
    ordered technique plan (kill-chain phases → techniques → concrete
    procedures) the orchestrator can dispatch.
  * **Detection / purple-team validation** — records which techniques
    were exercised and whether they were detected, feeding the blue-cell
    / detection story.

Backed by the kill-chain reference tools (``killchain_lookup`` /
``killchain_suggest``) plus the shared research and bash surface.
"""

from __future__ import annotations

from typing import Any

from buggy.agents.bounty._common import make_bounty_agent
from buggy.tools.references.tools import killchain_suggest
from buggy.tools.research.exploit_synthesis import EXPLOIT_TOOLS
from buggy.tools.research.sast_orchestrator import SAST_TOOLS
from buggy_core.plugin_loader import SubAgentSpec, is_bundle_enabled

_ROLE = "mitre_attack"

_DOMAIN_TOOLS: list[Any] = [killchain_suggest, *SAST_TOOLS, *EXPLOIT_TOOLS]

create_mitre_attack_agent = make_bounty_agent(role=_ROLE, domain_tools=_DOMAIN_TOOLS)


# Module-level graph for LangGraph Platform (langgraph serve).
if is_bundle_enabled("bounty"):
    graph = create_mitre_attack_agent()


SUBAGENT_SPEC = SubAgentSpec(
    name=_ROLE,
    description=(
        "MITRE ATT&CK specialist. Use to map engagement activity to ATT&CK "
        "tactics/techniques (Navigator layer + matrix), build adversary-"
        "emulation technique plans from a threat profile, and validate "
        "detection / purple-team coverage of the techniques exercised."
    ),
    factory=create_mitre_attack_agent,
    parent_agents=("buggy",),
    bundle="bounty",
    priority=61,
)
