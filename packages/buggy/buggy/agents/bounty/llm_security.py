"""LLM / AI App Security Agent — OWASP LLM Top 10.

Targets the attack surface of LLM-backed application features: direct
and indirect prompt injection, system-prompt / instruction leakage,
jailbreaks, insecure output handling (downstream XSS / SSRF / command
injection from model output), excessive agency / tool abuse (the model
invoking sensitive tools or actions), sensitive-information disclosure,
and training-data / context leakage.

Probes chat / completion / agent endpoints with crafted and
indirect-injection payloads via the shared bash + web + payload surface.
Confirmed findings are scope-checked and rendered as HackerOne /
Bugcrowd submissions.
"""

from __future__ import annotations

from typing import Any

from buggy.agents.bounty._common import make_bounty_agent
from buggy.tools.research.dast_crawler import DAST_TOOLS
from buggy_core.plugin_loader import SubAgentSpec, is_bundle_enabled

_ROLE = "llm_security"

_DOMAIN_TOOLS: list[Any] = [*DAST_TOOLS]

create_llm_security_agent = make_bounty_agent(role=_ROLE, domain_tools=_DOMAIN_TOOLS)


# Module-level graph for LangGraph Platform (langgraph serve).
if is_bundle_enabled("bounty"):
    graph = create_llm_security_agent()


SUBAGENT_SPEC = SubAgentSpec(
    name=_ROLE,
    description=(
        "LLM / AI app security specialist (OWASP LLM Top 10). Use against "
        "LLM-backed features for direct & indirect prompt injection, "
        "system-prompt leakage, jailbreaks, insecure output handling, "
        "excessive agency / tool abuse, and sensitive-info disclosure."
    ),
    factory=create_llm_security_agent,
    parent_agents=("buggy",),
    bundle="bounty",
    priority=68,
)
