"""Capability registry integrity (schema, uniqueness, prompt generation).

The registry (:mod:`buggy_core.capabilities`) is the single source
of truth for which security tools the platform provides. These tests lock
the invariants every other consumer (prompt builder, telemetry allowlist,
sandbox image drift test, discovery tools) relies on.
"""

from __future__ import annotations

import pytest

from buggy_core.capabilities import (
    BINARY_TO_CAPABILITY,
    CAPABILITY_REGISTRY,
    Capability,
    Lifecycle,
    RiskTier,
    base_apt_packages,
    base_binaries,
    base_pip_packages,
    capabilities_by_delivery,
    capabilities_by_lifecycle,
    generate_kali_environment_block,
    prompt_categories,
    reach_instruction,
    security_binaries,
)

_INSTALLED = (Lifecycle.SUPPORTED, Lifecycle.PREVIEW)


def test_registry_non_empty() -> None:
    assert len(CAPABILITY_REGISTRY) > 20


def test_capability_ids_unique() -> None:
    ids = [c.id for c in CAPABILITY_REGISTRY]
    dupes = {i for i in ids if ids.count(i) > 1}
    assert not dupes, f"duplicate capability ids: {sorted(dupes)}"


def test_binaries_unique_across_registry() -> None:
    """No binary may be claimed by two capabilities — the join key to
    telemetry and discovery must be unambiguous."""
    seen: dict[str, str] = {}
    collisions: list[str] = []
    for cap in CAPABILITY_REGISTRY:
        for binary in cap.binaries:
            if binary in seen:
                collisions.append(f"{binary}: {seen[binary]} vs {cap.id}")
            else:
                seen[binary] = cap.id
    assert not collisions, f"binary claimed twice: {collisions}"


def test_binary_index_covers_registry() -> None:
    total = sum(len(c.binaries) for c in CAPABILITY_REGISTRY)
    assert len(BINARY_TO_CAPABILITY) == total


@pytest.mark.parametrize("cap", CAPABILITY_REGISTRY, ids=lambda c: c.id)
def test_capability_fields_well_formed(cap: Capability) -> None:
    assert cap.id and cap.id.strip() == cap.id
    assert cap.category
    assert cap.description
    assert isinstance(cap.risk_tier, RiskTier)
    assert isinstance(cap.lifecycle, Lifecycle)
    # Delivery must be one of the known classes.
    assert cap.delivery in {"base", "pip", "sidecar", "external"} or cap.delivery.startswith(
        "profile:"
    ), f"{cap.id}: bad delivery {cap.delivery!r}"


@pytest.mark.parametrize("cap", CAPABILITY_REGISTRY, ids=lambda c: c.id)
def test_base_installed_capabilities_declare_apt_packages(cap: Capability) -> None:
    """Anything delivered ``base`` and installed must name its install
    source — apt packages (most tools) or pip packages baked at build
    (tools with no apt package, e.g. volatility3) — so the sandbox-image
    drift tests can verify it is actually in the image."""
    if cap.delivery == "base" and cap.lifecycle in _INSTALLED:
        assert cap.apt_packages or cap.pip_packages, (
            f"{cap.id}: base+installed but no apt_packages or pip_packages"
        )


@pytest.mark.parametrize("cap", CAPABILITY_REGISTRY, ids=lambda c: c.id)
def test_profile_delivery_declares_profile(cap: Capability) -> None:
    if cap.delivery.startswith("profile:"):
        profile = cap.delivery.removeprefix("profile:")
        assert cap.requires_profile == profile, (
            f"{cap.id}: delivery {cap.delivery!r} but requires_profile={cap.requires_profile!r}"
        )


def test_base_apt_packages_sorted_and_deduped() -> None:
    pkgs = base_apt_packages()
    assert pkgs == sorted(set(pkgs))
    assert "nmap" in pkgs
    assert "ffuf" in pkgs  # tranche addition


def test_base_binaries_include_new_tranche() -> None:
    bins = base_binaries()
    for expected in ("ffuf", "feroxbuster", "nuclei", "testssl", "gitleaks", "tshark"):
        assert expected in bins, f"{expected} missing from base binaries"


def test_security_binaries_exclude_runtime() -> None:
    bins = security_binaries()
    # pure-runtime helpers are not security tools
    assert "tmux" not in bins
    assert "npm" not in bins
    # but real tools are present
    assert "nmap" in bins


def test_helpers_consistent() -> None:
    assert capabilities_by_delivery("base")
    assert capabilities_by_lifecycle(Lifecycle.PLANNED)
    cats = prompt_categories()
    assert "web" in cats and "recon" in cats


def test_generated_prompt_is_truthful() -> None:
    block = generate_kali_environment_block()
    assert block.startswith("<KALI_ENVIRONMENT>")
    assert block.rstrip().endswith("</KALI_ENVIRONMENT>")
    # It must NOT repeat the old false "full Kali / every tool installed" claim.
    lowered = block.lower()
    assert "every tool in the" not in lowered
    assert "full kali linux distribution" not in lowered
    # PLANNED (uninstalled) tools must not appear in the installed section.
    installed_section = block.split("**Not yet installed**")[0]
    assert "certipy" not in installed_section


def test_generated_prompt_lists_installed_tools() -> None:
    block = generate_kali_environment_block()
    for tool in ("nmap", "ffuf", "nuclei", "sqlmap", "msfconsole", "testssl"):
        assert tool in block, f"{tool} should be advertised as installed"


def test_impacket_binaries_are_prefixed_executables() -> None:
    """Kali installs impacket as ``impacket-``-prefixed executables, not the
    ``.py`` example-script names — the registry must reflect the real image."""
    cap = BINARY_TO_CAPABILITY["impacket-secretsdump"]
    assert cap.id == "impacket"
    assert cap.delivery == "base"
    assert "impacket-scripts" in cap.apt_packages  # ntlmrelayx et al.
    assert all(b.startswith("impacket-") for b in cap.binaries)
    assert not any(b.endswith(".py") for b in cap.binaries)


def test_ghidra_is_sidecar_delivered() -> None:
    """Ghidra is not in the bash sandbox; it is reached via the ghidra-mcp
    sidecar and dedicated tools, so it must not be a base/profile bash tool."""
    cap = BINARY_TO_CAPABILITY["ghidra"]
    assert cap.delivery == "sidecar"
    assert cap.requires_service == "ghidra-mcp"
    assert cap.requires_profile == "reversing"
    # ghidra must be absent from the bash-runnable base binary set.
    assert "ghidra" not in base_binaries()


def test_radare2_and_binwalk_are_base_installed() -> None:
    """radare2 + binwalk are lightweight CLIs wired into the base image so
    bash can run them directly (not gated behind the reversing profile)."""
    for binary in ("radare2", "binwalk"):
        cap = BINARY_TO_CAPABILITY[binary]
        assert cap.delivery == "base", f"{binary} should be base-delivered"
        assert cap.apt_packages
        assert binary in base_binaries()


def test_phase_b_tools_are_baked_into_base_image() -> None:
    """Phase B promoted chisel/ligolo-ng/afl++/plaso/volatility3 from PLANNED
    to SUPPORTED base delivery — they must be genuinely reachable (in the
    base binary set, run-directly reach), not merely listed as planned."""
    for binary in (
        "chisel",
        "ligolo-proxy",
        "ligolo-agent",
        "afl-fuzz",
        "vol",
        "plaso-log2timeline",
    ):
        cap = BINARY_TO_CAPABILITY[binary]
        assert cap.lifecycle is Lifecycle.SUPPORTED, f"{binary} must be supported"
        assert cap.delivery == "base", f"{binary} must be base-delivered"
        assert binary in base_binaries()
        assert "run it directly" in reach_instruction(cap)


def test_volatility3_is_pip_baked_at_build() -> None:
    """volatility3 has no apt package, so it is base-delivered via a
    build-time pip install (pip_packages), not the runtime ``pip`` class."""
    cap = BINARY_TO_CAPABILITY["vol"]
    assert cap.delivery == "base"
    assert cap.apt_packages == ()
    assert cap.pip_packages == ("volatility3",)
    assert "volatility3" in base_pip_packages()
    # apt drift set must NOT include it (it is not an apt package).
    assert "volatility3" not in base_apt_packages()


def test_ligolo_binaries_match_kali_package() -> None:
    """Kali's ligolo-ng ships ligolo-proxy + ligolo-agent — there is no
    ``ligolo-ng`` binary, so the registry must not advertise one."""
    cap = BINARY_TO_CAPABILITY["ligolo-proxy"]
    assert cap.id == "ligolo-ng"
    assert set(cap.binaries) == {"ligolo-proxy", "ligolo-agent"}
    assert "ligolo-ng" not in cap.binaries


def test_planned_tools_not_in_base_binaries() -> None:
    planned = capabilities_by_lifecycle(Lifecycle.PLANNED)
    base = base_binaries()
    for cap in planned:
        for binary in cap.binaries:
            assert binary not in base, f"{cap.id} is PLANNED but {binary} appears in base binaries"
