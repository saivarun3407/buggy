"""Registry primitives — pluggable role / skill / plugin catalogs.

Submodules:

  * ``conflict``  — ``PluginConflictWarning`` raised at registry-load
    time when two plugins register the same key (tool / slot / role /
    skill path). Carries an ``owner`` attribute identifying the
    contributor (required by spec §16.4 #6).
  * ``resolution`` — ``RoleResolution`` frozen dataclass returned by
    ``PluginRegistry.introspect_role()``. Tuple-typed collections so
    instances are hashable + memoizable on run-id (spec §16.4 #1).
  * ``roles``    — ``RoleRegistry`` pluggable role catalog. Plugins
    register custom roles via ``buggy.roles`` entry-point group
    (closes gap §8 #5 — a vendor ``apt`` no longer abuses
    ``default_role="buggy"``).
  * ``skills``   — ``SkillSourceRegistry`` validating ``/skills/<.../>``
    paths and warning on collisions (closes gap §8 #12).
  * ``safety``   — ``SafetyRegistry`` for plugin-extended safety-critical
    tool / middleware names. Framework's ``_check_safety_gate`` consults
    the merged accessors so plugin declarations participate in the
    env-gated override check (closes gap §8 #10, spec §16.4 #4 —
    additive-only).
  * ``plugins``  — ``PluginRegistry`` central read-only view; primary
    API is ``introspect_role(role) -> RoleResolution`` (closes gap §8
    #7) and ``detect_collisions() -> list[PluginConflictWarning]``
    (closes gap §8 #4).
"""

from __future__ import annotations

from buggy_core.registry.conflict import PluginConflictWarning
from buggy_core.registry.plugins import PluginInfo, PluginRegistry
from buggy_core.registry.resolution import (
    MiddlewareInfo,
    OverrideInfo,
    RoleResolution,
    ToolInfo,
)
from buggy_core.registry.roles import RoleRegistry, RoleSpec
from buggy_core.registry.safety import SafetyRegistry
from buggy_core.registry.skills import SkillSourceRegistry

__all__ = [
    "MiddlewareInfo",
    "OverrideInfo",
    "PluginConflictWarning",
    "PluginInfo",
    "PluginRegistry",
    "RoleRegistry",
    "RoleResolution",
    "RoleSpec",
    "SafetyRegistry",
    "SkillSourceRegistry",
    "ToolInfo",
]
