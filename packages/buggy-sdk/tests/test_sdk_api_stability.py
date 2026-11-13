"""Stability snapshot — every public ``buggy-sdk`` name imports.

Spec §6.3 lists the SDK single-import surface that plugin authors
rely on. This test locks in the 23 stable symbols + the testing
fakes so a removed re-export fails CI.

See ``packages/buggy-core/tests/test_public_api_stability.py``
for the corresponding core-layer snapshot.
"""

from __future__ import annotations

import importlib
from typing import Any

import pytest

SDK_PUBLIC_API: tuple[tuple[str, str], ...] = (
    # Protocols (7)
    ("buggy_sdk", "BackendProtocol"),
    ("buggy_sdk", "MiddlewareProtocol"),
    ("buggy_sdk", "ToolProtocol"),
    ("buggy_sdk", "CallbackProtocol"),
    ("buggy_sdk", "LLMProtocol"),
    ("buggy_sdk", "SandboxProtocol"),
    ("buggy_sdk", "AgentProtocol"),
    # Slot enum + constants (3)
    ("buggy_sdk", "MiddlewareSlot"),
    ("buggy_sdk", "SAFETY_CRITICAL_SLOTS"),
    ("buggy_sdk", "SLOTS_PER_ROLE"),
    # Focused contributions (5)
    ("buggy_sdk", "ToolContribution"),
    ("buggy_sdk", "MiddlewareContribution"),
    ("buggy_sdk", "PromptContribution"),
    ("buggy_sdk", "SubAgentContribution"),
    ("buggy_sdk", "SafetyDeclaration"),
    # Plugin loader (3)
    ("buggy_sdk", "PluginBundle"),
    ("buggy_sdk", "SubAgentSpec"),
    ("buggy_sdk", "is_bundle_enabled"),
    # Registry (8)
    ("buggy_sdk", "PluginRegistry"),
    ("buggy_sdk", "PluginInfo"),
    ("buggy_sdk", "PluginConflictWarning"),
    ("buggy_sdk", "RoleRegistry"),
    ("buggy_sdk", "RoleSpec"),
    ("buggy_sdk", "RoleResolution"),
    ("buggy_sdk", "SafetyRegistry"),
    ("buggy_sdk", "SkillSourceRegistry"),
    # Testing fakes (3)
    ("buggy_sdk.testing", "FakeBackend"),
    ("buggy_sdk.testing", "FakeLLM"),
    ("buggy_sdk.testing", "FakeSandbox"),
    # Scaffold entry (CLI also wired via [project.scripts])
    ("buggy_sdk.scaffold", "app"),
)


@pytest.mark.parametrize(("module_name", "attr"), SDK_PUBLIC_API)
def test_sdk_public_name_importable(module_name: str, attr: str) -> None:
    module = importlib.import_module(module_name)
    value: Any = getattr(module, attr, None)
    assert value is not None, (
        f"{module_name}.{attr} returned None — accidental removal? "
        f"If intentional, update this manifest + CHANGELOG together."
    )


def test_sdk_manifest_count_unchanged() -> None:
    """Snapshot the manifest size."""
    expected = 30
    actual = len(SDK_PUBLIC_API)
    assert actual == expected, (
        f"SDK_PUBLIC_API has {actual} entries, expected {expected}. "
        f"If intentional, bump this number AND update the CHANGELOG."
    )
