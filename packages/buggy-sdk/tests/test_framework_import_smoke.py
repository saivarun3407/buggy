"""Framework import smoke — proves Phase 2.x.3 import rewrite landed
cleanly across all 16 agent factories without needing the sandbox
container or LiteLLM proxy.

Closes the most-valuable subset of spec §14 acceptance #3 — full
``pytest packages/buggy/tests`` requires the live sandbox HTTP
daemon for many integration tests, but the smoke here proves the
mechanical import rewrite produced a working framework surface.

Lives under buggy-sdk/tests so it shares the existing pytest
testpaths (the buggy-sdk testing fakes already pull the
framework in via the ``fixtures`` extra path).
"""

from __future__ import annotations


def test_all_16_agent_factories_importable() -> None:
    """The 16 agent factories listed in spec §6.2 import cleanly."""
    from buggy.agents import (
        create_ad_operator_agent,
        create_analyst_agent,
        create_buggy_agent,
        create_cloud_hunter_agent,
        create_contract_auditor_agent,
        create_detector_agent,
        create_exploit_agent,
        create_exploiter_agent,
        create_patcher_agent,
        create_postexploit_agent,
        create_recon_agent,
        create_reverser_agent,
        create_scanner_agent,
        create_soundwave_agent,
        create_verifier_agent,
        create_vulnresearch_agent,
    )
    from buggy.agents.build import build_middleware, build_tools

    factories = (
        create_ad_operator_agent,
        create_analyst_agent,
        create_cloud_hunter_agent,
        create_contract_auditor_agent,
        create_buggy_agent,
        create_detector_agent,
        create_exploit_agent,
        create_exploiter_agent,
        create_patcher_agent,
        create_postexploit_agent,
        create_recon_agent,
        create_reverser_agent,
        create_scanner_agent,
        create_soundwave_agent,
        create_verifier_agent,
        create_vulnresearch_agent,
    )
    assert len(factories) == 16
    assert all(callable(f) for f in factories)
    assert callable(build_middleware)
    assert callable(build_tools)


def test_framework_backends_importable() -> None:
    """Spec §6.2 backend public API surface."""
    from buggy.backends import (
        SKILLS_LOCAL_PATH,
        HTTPSandbox,
        build_sandbox_backend,
        make_agent_backend,
    )

    assert HTTPSandbox is not None
    assert isinstance(SKILLS_LOCAL_PATH, str)
    assert callable(build_sandbox_backend)
    assert callable(make_agent_backend)


def test_framework_middleware_importable() -> None:
    """Spec §6.2 middleware classes — 11 standard slot implementations."""
    from buggy.middleware import (
        EngagementContextMiddleware,
        FilesystemMiddleware,
        OPPLANMiddleware,
        SkillsMiddleware,
    )

    for cls in (
        EngagementContextMiddleware,
        FilesystemMiddleware,
        OPPLANMiddleware,
        SkillsMiddleware,
    ):
        assert isinstance(cls, type), f"{cls.__name__} is not a class"


def test_framework_llm_importable() -> None:
    """Spec §6.2 LLMFactory + create_llm."""
    from buggy.llm import LLMFactory, create_llm

    assert isinstance(LLMFactory, type)
    assert callable(create_llm)


def test_compat_register_legacy_imports_idempotent() -> None:
    """Re-calling register_legacy_imports() is a no-op (boot called it
    once at framework import; explicit re-call must not re-warn)."""
    import warnings

    from buggy.compat import register_legacy_imports

    with warnings.catch_warnings(record=True) as ws:
        warnings.simplefilter("always")
        register_legacy_imports()  # second call after boot's
        register_legacy_imports()  # third call
    # No new DeprecationWarning emitted from the boot list (boot
    # already fired its single one). The per-import warnings on the
    # shim modules fire only on attribute access; nothing accessed
    # here.
    boot_warnings = [w for w in ws if "Phase 1 compat shims" in str(w.message)]
    assert boot_warnings == [], (
        f"register_legacy_imports() should be idempotent; got {len(boot_warnings)} repeat warnings"
    )


def test_role_registry_seeded_with_16_oss_roles() -> None:
    """Framework boot pre-registers every OSS role per spec §8 gap #5."""
    import buggy  # boot fires

    del buggy  # silence unused-import lint

    from buggy_core.contracts.slots import SLOTS_PER_ROLE
    from buggy_core.registry import RoleRegistry

    for role in SLOTS_PER_ROLE:
        spec = RoleRegistry.get(role)
        assert spec is not None, f"OSS role {role!r} missing from RoleRegistry"


def test_plugin_registry_finds_oss_subagents() -> None:
    """Spec §14 #1 / gap #4 — PluginRegistry walks the live
    entry-point graph and surfaces the OSS subagent plugins."""
    import buggy  # boot fires

    del buggy  # silence unused-import lint

    from buggy_core.registry import PluginRegistry

    # Discard any cached snapshot left over from monkeypatched
    # collision tests in the core test suite; rebuild against the
    # live entry-point graph.
    PluginRegistry.reset()
    reg = PluginRegistry.load()
    plugins = reg.list_plugins()
    # 13 OSS subagents register via ``buggy.subagents`` per
    # packages/buggy/pyproject.toml entry-points.
    subagent_plugins = [p for p in plugins if "buggy.subagents" in p.groups]
    assert len(subagent_plugins) >= 13, (
        f"expected >=13 OSS subagent plugins discovered, found "
        f"{len(subagent_plugins)}: {[p.name for p in subagent_plugins]}"
    )
    # No collisions for the bare OSS install.
    assert reg.detect_collisions() == ()
