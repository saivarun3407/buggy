"""Authentication / Session Agent — account-takeover chains.

Targets the authentication, federation, and session layers where the
top-payout bug-bounty findings live: OAuth2 / OIDC / SAML / SSO flow
abuse (redirect_uri / state / code-leak, IdP-confusion, assertion
manipulation), JWT attacks (``alg=none``, HS/RS confusion, ``kid``
injection, weak secret cracking), session fixation, and password-reset /
MFA bypass — chained into full account takeover.

Driven by the shared bash + web + payload surface (curl-driven flow
manipulation, JWT tampering, token replay across sessions). Confirmed
takeover chains are scope-checked and rendered as HackerOne / Bugcrowd
submissions.
"""

from __future__ import annotations

from typing import Any

from buggy.agents.bounty._common import make_bounty_agent
from buggy.tools.research.config_audit import CONFIG_AUDIT_TOOLS
from buggy.tools.research.dast_crawler import DAST_TOOLS
from buggy_core.plugin_loader import SubAgentSpec, is_bundle_enabled

_ROLE = "authn_session"

_DOMAIN_TOOLS: list[Any] = [*CONFIG_AUDIT_TOOLS, *DAST_TOOLS]

create_authn_session_agent = make_bounty_agent(role=_ROLE, domain_tools=_DOMAIN_TOOLS)


# Module-level graph for LangGraph Platform (langgraph serve).
if is_bundle_enabled("bounty"):
    graph = create_authn_session_agent()


SUBAGENT_SPEC = SubAgentSpec(
    name=_ROLE,
    description=(
        "Authentication / session specialist for account-takeover chains. "
        "Use for OAuth2/OIDC/SAML/SSO flow abuse, JWT attacks (alg confusion, "
        "kid injection, weak-secret cracking), session fixation, and "
        "password-reset / MFA bypass. Highest bug-bounty payouts."
    ),
    factory=create_authn_session_agent,
    parent_agents=("buggy",),
    bundle="bounty",
    priority=63,
)
