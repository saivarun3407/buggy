"""GraphQL Security Agent — introspection, batching abuse, depth DoS.

Targets GraphQL-specific attack surface: introspection exposure and
schema mining, alias / array-batching abuse (rate-limit and brute-force
amplification), query depth / complexity denial-of-service, field-level
authorization bypass (BOLA/BFLA expressed through the graph), injection
through resolver arguments, and mutation abuse.

Driven by the shared bash + web + payload surface (introspection queries,
crafted batched / deeply-nested documents via curl). Confirmed findings
are scope-checked and rendered as HackerOne / Bugcrowd submissions.
"""

from __future__ import annotations

from typing import Any

from buggy.agents.bounty._common import make_bounty_agent
from buggy.tools.research.dast_crawler import DAST_TOOLS
from buggy_core.plugin_loader import SubAgentSpec, is_bundle_enabled

_ROLE = "graphql_security"

_DOMAIN_TOOLS: list[Any] = [*DAST_TOOLS]

create_graphql_security_agent = make_bounty_agent(role=_ROLE, domain_tools=_DOMAIN_TOOLS)


# Module-level graph for LangGraph Platform (langgraph serve).
if is_bundle_enabled("bounty"):
    graph = create_graphql_security_agent()


SUBAGENT_SPEC = SubAgentSpec(
    name=_ROLE,
    description=(
        "GraphQL security specialist. Use against GraphQL endpoints for "
        "introspection / schema mining, alias & array-batching abuse, query "
        "depth/complexity DoS, resolver-level authorization bypass "
        "(BOLA/BFLA), and injection through resolver arguments."
    ),
    factory=create_graphql_security_agent,
    parent_agents=("buggy",),
    bundle="bounty",
    priority=65,
)
