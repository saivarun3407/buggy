"""Business-logic & Race-condition Agent — workflow abuse and TOCTOU.

Hunts the flaws no signature catches because the requests are
individually valid: multi-step workflow abuse (skipping / reordering /
replaying steps, negative quantities, price / coupon / currency
tampering), and concurrency races — TOCTOU and parallel-request
overruns (limit-overrun, double-spend, coupon / referral / withdrawal
races) exploited by firing many requests in a tight window.

Driven by the shared bash + web surface (scripted multi-step flows and
high-concurrency request bursts via curl / xargs / parallel). Confirmed
abuse chains are scope-checked and rendered as HackerOne / Bugcrowd
submissions.
"""

from __future__ import annotations

from typing import Any

from buggy.agents.bounty._common import make_bounty_agent
from buggy.tools.research.dast_crawler import DAST_TOOLS
from buggy_core.plugin_loader import SubAgentSpec, is_bundle_enabled

_ROLE = "business_logic"

_DOMAIN_TOOLS: list[Any] = [*DAST_TOOLS]

create_business_logic_agent = make_bounty_agent(role=_ROLE, domain_tools=_DOMAIN_TOOLS)


# Module-level graph for LangGraph Platform (langgraph serve).
if is_bundle_enabled("bounty"):
    graph = create_business_logic_agent()


SUBAGENT_SPEC = SubAgentSpec(
    name=_ROLE,
    description=(
        "Business-logic & race-condition specialist. Use for multi-step "
        "workflow abuse (step skipping/reordering, price/coupon/quantity "
        "tampering) and concurrency races — TOCTOU, limit-overrun, "
        "double-spend — via tight-window parallel requests. Catches what "
        "scanners can't: individually-valid requests with abusive intent."
    ),
    factory=create_business_logic_agent,
    parent_agents=("buggy",),
    bundle="bounty",
    priority=64,
)
