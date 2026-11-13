"""Stability snapshot — every public ``buggy-core`` name imports.

Locks in the public surface so accidental removal / rename fails CI.
Spec §6.1 enumerates the SemVer-stable surface plugin authors and
downstream consumers can rely on at v1.0; this test asserts each
listed name is importable from its declared module.

To intentionally remove or rename a public name:
  1. Update this manifest in the same commit
  2. Update the CHANGELOG (and migration guide if the rename breaks
     callers)
  3. Bump the major version if at 1.0+
"""

from __future__ import annotations

import importlib
from typing import Any

import pytest

# (module, name) pairs. Every entry must resolve to an importable
# attribute. Reorganize by category for readability.
CORE_PUBLIC_API: tuple[tuple[str, str], ...] = (
    # buggy_core.types.engagement
    ("buggy_core.types.engagement", "RoE"),
    ("buggy_core.types.engagement", "OPPLAN"),
    ("buggy_core.types.engagement", "Finding"),
    ("buggy_core.types.engagement", "Evidence"),
    ("buggy_core.types.engagement", "Objective"),
    ("buggy_core.types.engagement", "AttackPath"),
    ("buggy_core.types.engagement", "ObjectivePhase"),
    ("buggy_core.types.engagement", "ObjectiveStatus"),
    ("buggy_core.types.engagement", "OpsecLevel"),
    ("buggy_core.types.engagement", "C2Tier"),
    ("buggy_core.types.engagement", "FindingSeverity"),
    ("buggy_core.types.engagement", "FindingConfidence"),
    ("buggy_core.types.engagement", "RemediationPriority"),
    ("buggy_core.types.engagement", "EngagementType"),
    ("buggy_core.types.engagement", "ScopeEntry"),
    ("buggy_core.types.engagement", "EscalationContact"),
    # buggy_core.types.llm
    ("buggy_core.types.llm", "Tier"),
    ("buggy_core.types.llm", "AuthMethod"),
    ("buggy_core.types.llm", "ModelProfile"),
    ("buggy_core.types.llm", "Credentials"),
    ("buggy_core.types.llm", "ProxyConfig"),
    ("buggy_core.types.llm", "ModelAssignment"),
    ("buggy_core.types.llm", "LLMModelMapping"),
    # buggy_core.types.kg
    ("buggy_core.types.kg", "Node"),
    ("buggy_core.types.kg", "Edge"),
    ("buggy_core.types.kg", "NodeKind"),
    ("buggy_core.types.kg", "EdgeKind"),
    ("buggy_core.types.kg", "Severity"),
    ("buggy_core.types.kg", "KnowledgeGraph"),
    # buggy_core.types.roe — machine-readable RoE enforcement schema
    ("buggy_core.types.roe", "EnforcementMode"),
    ("buggy_core.types.roe", "ScopeRule"),
    ("buggy_core.types.roe", "MachineEnforcement"),
    ("buggy_core.types.roe", "Decision"),
    ("buggy_core.types.roe", "evaluate_target"),
    ("buggy_core.types.roe", "evaluate_command"),
    # buggy_core.protocols
    ("buggy_core.protocols", "BackendProtocol"),
    ("buggy_core.protocols", "MiddlewareProtocol"),
    ("buggy_core.protocols", "ToolProtocol"),
    ("buggy_core.protocols", "CallbackProtocol"),
    ("buggy_core.protocols", "LLMProtocol"),
    ("buggy_core.protocols", "SandboxProtocol"),
    ("buggy_core.protocols", "AgentProtocol"),
    # buggy_core.contracts.slots
    ("buggy_core.contracts.slots", "MiddlewareSlot"),
    ("buggy_core.contracts.slots", "SAFETY_CRITICAL_SLOTS"),
    ("buggy_core.contracts.slots", "SLOTS_PER_ROLE"),
    # buggy_core.contracts.contributions
    ("buggy_core.contracts.contributions", "ToolContribution"),
    ("buggy_core.contracts.contributions", "MiddlewareContribution"),
    ("buggy_core.contracts.contributions", "PromptContribution"),
    ("buggy_core.contracts.contributions", "SubAgentContribution"),
    ("buggy_core.contracts.contributions", "SafetyDeclaration"),
    # buggy_core.registry
    ("buggy_core.registry", "PluginRegistry"),
    ("buggy_core.registry", "PluginInfo"),
    ("buggy_core.registry", "PluginConflictWarning"),
    ("buggy_core.registry", "RoleRegistry"),
    ("buggy_core.registry", "RoleSpec"),
    ("buggy_core.registry", "RoleResolution"),
    ("buggy_core.registry", "MiddlewareInfo"),
    ("buggy_core.registry", "ToolInfo"),
    ("buggy_core.registry", "OverrideInfo"),
    ("buggy_core.registry", "SafetyRegistry"),
    ("buggy_core.registry", "SkillSourceRegistry"),
    # buggy_core.plugin_loader (still here for back-compat;
    # contracts will eventually split into contracts/, registry/ per
    # spec §9.1 but the public symbol set stays the same).
    ("buggy_core.plugin_loader", "PluginBundle"),
    ("buggy_core.plugin_loader", "SubAgentSpec"),
    ("buggy_core.plugin_loader", "is_bundle_enabled"),
    ("buggy_core.plugin_loader", "load_plugin_tools"),
    ("buggy_core.plugin_loader", "load_plugin_middleware"),
    ("buggy_core.plugin_loader", "load_plugin_callbacks"),
    ("buggy_core.plugin_loader", "load_plugin_skill_sources"),
    ("buggy_core.plugin_loader", "load_subagents_for_parent"),
    ("buggy_core.plugin_loader", "load_plugin_agents"),
    # buggy_core.utils
    ("buggy_core.utils.config", "BuggyConfig"),
    ("buggy_core.utils.config", "LLMConfig"),
    ("buggy_core.utils.config", "load_config"),
    ("buggy_core.utils.logging", "configure_logging"),
    ("buggy_core.utils.logging", "get_logger"),
)


@pytest.mark.parametrize(("module_name", "attr"), CORE_PUBLIC_API)
def test_public_name_importable(module_name: str, attr: str) -> None:
    """Each (module, name) in the manifest must resolve.

    Failures indicate accidental removal or rename — fix the
    implementation, or update both this manifest and the CHANGELOG
    in the same commit.
    """
    module = importlib.import_module(module_name)
    value: Any = getattr(module, attr, None)
    assert value is not None, (
        f"{module_name}.{attr} returned None — accidental removal? "
        f"If intentional, update this manifest + CHANGELOG together."
    )


def test_manifest_count_unchanged() -> None:
    """Snapshot the manifest size so silent drift surfaces.

    Bumping the count is fine in either direction — the test
    documents the intentional change in the diff. Lowering without
    a major-version bump is an audit signal.
    """
    # Update this number deliberately when adding/removing public names.
    expected = 75
    actual = len(CORE_PUBLIC_API)
    assert actual == expected, (
        f"CORE_PUBLIC_API has {actual} entries, expected {expected}. "
        f"If intentional, bump this number AND update the CHANGELOG."
    )
