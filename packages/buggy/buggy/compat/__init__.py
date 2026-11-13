"""Backward-compatibility shim layer for the core/framework/sdk split.

Per spec §7.3 of
``docs/superpowers/specs/2026-05-23-core-framework-sdk-split-design.md``,
this module ships the one-release migration shim:

  * Legacy import paths (``buggy.core.schemas``,
    ``buggy.llm.models``, ``buggy.tools.research.graph``,
    ``buggy.plugin_loader``, ``buggy.core.config``,
    ``buggy.core.logging``) keep working via the per-file
    re-export modules in Phase 1.
  * ``register_legacy_imports()`` (default-on, opt-out via
    ``BUGGY_NO_COMPAT=1``) raises ``DeprecationWarning`` once on
    first call to surface the migration list in test logs.

The shim is REMOVED at ``2.0.0``. Phase 2 of the redesign rewrites
all internal framework call sites to import from
``buggy_core.*`` directly; downstream consumers we don't know
about are the audience for this shim layer.
"""

from __future__ import annotations

import warnings

from buggy_core.utils.env import env_flag

_REGISTERED: bool = False

_LEGACY_PATH_NOTES: tuple[tuple[str, str], ...] = (
    ("buggy.core.schemas", "buggy_core.types.engagement"),
    ("buggy.llm.models", "buggy_core.types.llm"),
    ("buggy.tools.research.graph", "buggy_core.types.kg"),
    ("buggy.plugin_loader", "buggy_core.plugin_loader"),
    ("buggy.core.config", "buggy_core.utils.config"),
    ("buggy.core.logging", "buggy_core.utils.logging"),
    (
        "buggy.agents.middleware_slots",
        "buggy_core.contracts.slots (enum/SLOTS_PER_ROLE only)",
    ),
)


def register_legacy_imports() -> None:
    """Enable the Phase 1 compat shim layer.

    Default-on via ``buggy.__init__`` (Phase 2 wires this);
    opt-out via ``BUGGY_NO_COMPAT=1`` in the environment. Idempotent —
    repeated calls are no-ops.

    Emits a single ``DeprecationWarning`` per process listing the
    legacy → canonical path mapping so test logs surface the migration
    list. The legacy paths keep working until ``2.0.0`` — the warning
    is informational, not blocking.
    """
    global _REGISTERED
    if _REGISTERED:
        return
    if env_flag("BUGGY_NO_COMPAT"):
        _REGISTERED = True
        return

    lines = ["Buggy Phase 1 compat shims active. Migrate the following paths before 2.0.0:"]
    for legacy, canonical in _LEGACY_PATH_NOTES:
        lines.append(f"  - {legacy}  ->  {canonical}")
    warnings.warn(
        "\n".join(lines),
        DeprecationWarning,
        stacklevel=2,
    )
    _REGISTERED = True


__all__ = ["register_legacy_imports"]
