"""ASVS 5.0 Audit Agent — OWASP Application Security Verification Standard.

Runs a full OWASP ASVS 5.0 verification pass over the recon-discovered
host / service / endpoint inventory. Dispatched as its own post-recon
objective: it consumes recon's findings and walks every applicable ASVS
chapter (V1 encoding, V2 validation/sanitization, V3 web-frontend, V6
authentication, V7 session management, V8 authorization, V9
self-contained tokens, V11 crypto, V13 API/web-service, ...) at the
level (L1 / L2 / L3) the engagement targets.

Hybrid verification: black-box DAST (curl / nuclei / testssl probing of
live endpoints) plus white-box review of any source made available,
emitting a per-chapter / per-requirement verdict (pass / fail / n-a)
with evidence — the same structured findings the bug-bounty reporters
turn into HackerOne / Bugcrowd submissions.
"""

from __future__ import annotations

from typing import Any

from buggy.agents.bounty._common import make_bounty_agent
from buggy.tools.research.config_audit import CONFIG_AUDIT_TOOLS
from buggy.tools.research.sast_orchestrator import SAST_TOOLS
from buggy.tools.research.sca import SCA_TOOLS
from buggy.tools.research.taint_analyzer import TAINT_TOOLS
from buggy_core.plugin_loader import SubAgentSpec, is_bundle_enabled

_ROLE = "asvs"

_DOMAIN_TOOLS: list[Any] = [*SAST_TOOLS, *CONFIG_AUDIT_TOOLS, *TAINT_TOOLS, *SCA_TOOLS]

create_asvs_agent = make_bounty_agent(role=_ROLE, domain_tools=_DOMAIN_TOOLS)


# Module-level graph for LangGraph Platform (langgraph serve).
if is_bundle_enabled("bounty"):
    graph = create_asvs_agent()


SUBAGENT_SPEC = SubAgentSpec(
    name=_ROLE,
    description=(
        "OWASP ASVS 5.0 verification specialist. Dispatch right after recon "
        "to run a full Application Security Verification Standard audit over "
        "the discovered endpoints — per-chapter / per-requirement pass/fail "
        "verdicts at L1/L2/L3 (validation, auth, session, authorization, "
        "tokens, crypto, API). Hybrid black-box DAST + white-box review."
    ),
    factory=create_asvs_agent,
    parent_agents=("buggy",),
    bundle="bounty",
    priority=60,
)
