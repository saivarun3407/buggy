"""SSRF & Cloud-metadata Agent — SSRF to internal/cloud pivot.

Hunts server-side request forgery and turns it into impact: reaching the
cloud metadata service (169.254.169.254 and the GCP / Azure / Alibaba
equivalents) to steal instance credentials, internal port / service
scanning through the vulnerable server, and DNS-rebinding / redirect /
gopher / file-scheme bypasses of SSRF filters.

The cloud-metadata endpoints stay force-denied by the enforced RoE
egress policy unless the program explicitly authorises metadata testing
(``ingest_bounty_scope(allow_cloud_metadata=True)``) — so this agent
proves SSRF reach within scope rather than blindly hitting metadata.
Driven by the shared bash + web + payload surface; confirmed findings are
scope-checked and rendered as HackerOne / Bugcrowd submissions.
"""

from __future__ import annotations

from typing import Any

from buggy.agents.bounty._common import make_bounty_agent
from buggy.tools.research.dast_crawler import DAST_TOOLS
from buggy.tools.research.iac_scanner import IAC_TOOLS
from buggy_core.plugin_loader import SubAgentSpec, is_bundle_enabled

_ROLE = "ssrf_cloud"

_DOMAIN_TOOLS: list[Any] = [*DAST_TOOLS, *IAC_TOOLS]

create_ssrf_cloud_agent = make_bounty_agent(role=_ROLE, domain_tools=_DOMAIN_TOOLS)


# Module-level graph for LangGraph Platform (langgraph serve).
if is_bundle_enabled("bounty"):
    graph = create_ssrf_cloud_agent()


SUBAGENT_SPEC = SubAgentSpec(
    name=_ROLE,
    description=(
        "SSRF & cloud-metadata specialist. Use to find server-side request "
        "forgery and escalate it — cloud metadata credential theft "
        "(169.254.169.254 et al.), internal port/service scanning via the "
        "vulnerable host, and DNS-rebinding / redirect / gopher filter "
        "bypasses. Respects the RoE cloud-metadata opt-in."
    ),
    factory=create_ssrf_cloud_agent,
    parent_agents=("buggy",),
    bundle="bounty",
    priority=66,
)
