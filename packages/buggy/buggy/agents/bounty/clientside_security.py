"""Client-side Security Agent — XSS, CORS, prototype pollution, postMessage.

Targets browser-executed attack surface: reflected / stored / DOM-based
XSS, CORS misconfiguration (credentialed cross-origin reads), client-side
prototype pollution and its gadget chains, ``postMessage`` origin-trust
flaws, open redirects, and DOM clobbering.

Drives a real Playwright browser (``browser_action``) so DOM-sink and
``postMessage`` issues can be proven with live execution and console
evidence, alongside the shared bash + web + payload surface. Confirmed
findings are scope-checked and rendered as HackerOne / Bugcrowd
submissions.
"""

from __future__ import annotations

from typing import Any

from buggy.agents.bounty._common import make_bounty_agent
from buggy.tools.browser import BROWSER_TOOLS
from buggy.tools.research.dast_crawler import DAST_TOOLS
from buggy.tools.research.taint_analyzer import TAINT_TOOLS
from buggy_core.plugin_loader import SubAgentSpec, is_bundle_enabled

_ROLE = "clientside_security"

_DOMAIN_TOOLS: list[Any] = [*BROWSER_TOOLS, *DAST_TOOLS, *TAINT_TOOLS]

create_clientside_security_agent = make_bounty_agent(role=_ROLE, domain_tools=_DOMAIN_TOOLS)


# Module-level graph for LangGraph Platform (langgraph serve).
if is_bundle_enabled("bounty"):
    graph = create_clientside_security_agent()


SUBAGENT_SPEC = SubAgentSpec(
    name=_ROLE,
    description=(
        "Client-side security specialist. Use for reflected/stored/DOM XSS, "
        "CORS misconfiguration, prototype pollution + gadget chains, "
        "postMessage origin-trust flaws, open redirects, and DOM clobbering. "
        "Drives a live Playwright browser to prove DOM-sink execution."
    ),
    factory=create_clientside_security_agent,
    parent_agents=("buggy",),
    bundle="bounty",
    priority=67,
)
