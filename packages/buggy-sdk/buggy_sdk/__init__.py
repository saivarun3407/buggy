"""buggy-sdk — plugin author entrypoint for the Buggy framework.

A complete Buggy plugin can be written importing only from this
package: every protocol, contract, registry, and helper plugin authors
need is exported here. No underscore-prefixed framework internals are
required.

Phase 3 surface:

  * ``buggy_sdk`` (this module) — re-exports the public
    ``buggy-core`` API (types, protocols, contracts, registries,
    plugin loader). Tracks the framework's release version (current
    series: 1.1.x → 1.1.2 with this redesign; shim removal at 2.0.0).
    Public names listed in ``__all__`` are SemVer-stable.
  * ``buggy_sdk.testing`` — pytest fixtures and fakes
    (``FakeBackend``, ``FakeLLM``, ``FakeSandbox``) for hermetic
    plugin tests that don't need a live framework.

Deferred from Phase 3 (follow-up commits):

  * ``buggy-sdk plugin new --kind=...`` scaffolding CLI
  * Runnable example plugin per ``kind`` under ``examples/``
"""

from __future__ import annotations

from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as _version

# Re-export the buggy-core contracts so plugin authors only need
# a single import line:
#
#     from buggy_sdk import (
#         BackendProtocol, MiddlewareProtocol, ToolContribution,
#         PluginBundle, SubAgentSpec, RoleRegistry, ...
#     )
from buggy_core.contracts.contributions import (
    MiddlewareContribution,
    PromptContribution,
    SafetyDeclaration,
    SubAgentContribution,
    ToolContribution,
)
from buggy_core.contracts.slots import (
    SAFETY_CRITICAL_SLOTS,
    SLOTS_PER_ROLE,
    MiddlewareSlot,
)
from buggy_core.plugin_loader import (
    PluginBundle,
    SubAgentSpec,
    is_bundle_enabled,
)
from buggy_core.protocols import (
    AgentProtocol,
    BackendProtocol,
    CallbackProtocol,
    LLMProtocol,
    MiddlewareProtocol,
    SandboxProtocol,
    ToolProtocol,
)
from buggy_core.registry import (
    PluginConflictWarning,
    PluginInfo,
    PluginRegistry,
    RoleRegistry,
    RoleResolution,
    RoleSpec,
    SafetyRegistry,
    SkillSourceRegistry,
)

# Read the installed distribution version — release.yml stamps the git
# tag into wheel metadata at build time; local checkouts read 0.0.0.
# Mirrors buggy-core / buggy so all three report consistently.
try:
    __version__ = _version("buggy-sdk")
except PackageNotFoundError:
    __version__ = "0.0.0"

__all__ = [
    # Protocols (buggy_core.protocols)
    "AgentProtocol",
    "BackendProtocol",
    "CallbackProtocol",
    "LLMProtocol",
    "MiddlewareProtocol",
    "SandboxProtocol",
    "ToolProtocol",
    # Slot enum + constants (buggy_core.contracts.slots)
    "MiddlewareSlot",
    "SAFETY_CRITICAL_SLOTS",
    "SLOTS_PER_ROLE",
    # Plugin contributions (buggy_core.contracts.contributions)
    "MiddlewareContribution",
    "PromptContribution",
    "SafetyDeclaration",
    "SubAgentContribution",
    "ToolContribution",
    # Plugin loader (buggy_core.plugin_loader)
    "PluginBundle",
    "SubAgentSpec",
    "is_bundle_enabled",
    # Registries (buggy_core.registry)
    "PluginConflictWarning",
    "PluginInfo",
    "PluginRegistry",
    "RoleRegistry",
    "RoleResolution",
    "RoleSpec",
    "SafetyRegistry",
    "SkillSourceRegistry",
    # Version
    "__version__",
]
