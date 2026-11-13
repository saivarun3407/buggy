"""Buggy middleware - custom AgentMiddleware implementations."""

from buggy.middleware.budget import BudgetEnforcementMiddleware
from buggy.middleware.engagement import EngagementContextMiddleware
from buggy.middleware.event_logging import EventLogMiddleware
from buggy.middleware.filesystem import FilesystemMiddleware
from buggy.middleware.hitl import (
    DEFAULT_HIGH_IMPACT_POLICY,
    ApprovalDecision,
    ApprovalPolicyRule,
    ApprovalRequest,
    ApprovalTransport,
    FileBackedApprovalTransport,
    HITLApprovalMiddleware,
    InProcessApprovalTransport,
)
from buggy.middleware.kg import KGMiddleware
from buggy.middleware.notifications import (
    SandboxNotificationMiddleware,
)
from buggy.middleware.opplan import OPPLANMiddleware
from buggy.middleware.parsing_firewall import ParsingFirewallMiddleware
from buggy.middleware.prompt_injection_shield import (
    PromptInjectionShieldMiddleware,
)
from buggy.middleware.roe import (
    RoEEnforcementMiddleware,  # compat alias, removed at 2.0.0
    RoEGuardrailMiddleware,
)
from buggy.middleware.skillogy import SkillogyMiddleware, maybe_install_skillogy
from buggy.middleware.skills import SkillsMiddleware
from buggy.middleware.untrusted_output import UntrustedOutputMiddleware

__all__ = [
    "ApprovalDecision",
    "ApprovalPolicyRule",
    "ApprovalRequest",
    "ApprovalTransport",
    "BudgetEnforcementMiddleware",
    "DEFAULT_HIGH_IMPACT_POLICY",
    "EngagementContextMiddleware",
    "EventLogMiddleware",
    "FileBackedApprovalTransport",
    "FilesystemMiddleware",
    "HITLApprovalMiddleware",
    "InProcessApprovalTransport",
    "KGMiddleware",
    "OPPLANMiddleware",
    "ParsingFirewallMiddleware",
    "PromptInjectionShieldMiddleware",
    "RoEEnforcementMiddleware",
    "RoEGuardrailMiddleware",
    "SandboxNotificationMiddleware",
    "SkillogyMiddleware",
    "SkillsMiddleware",
    "UntrustedOutputMiddleware",
    "maybe_install_skillogy",
]
