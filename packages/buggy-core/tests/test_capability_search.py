"""Tests for the registry search + reach helpers used by agent discovery."""

from __future__ import annotations

import pytest

from buggy_core.capabilities import (
    BINARY_TO_CAPABILITY,
    CAPABILITY_REGISTRY,
    ROLE_CAPABILITY_POLICY,
    Capability,
    Lifecycle,
    RiskTier,
    reach_instruction,
    role_capability_policy,
    search_capabilities,
)


def test_search_defaults_to_supported_and_preview_only() -> None:
    results = search_capabilities()
    assert results
    assert all(c.lifecycle in (Lifecycle.SUPPORTED, Lifecycle.PREVIEW) for c in results)


def test_include_planned_surfaces_planned_capabilities() -> None:
    without = search_capabilities()
    with_planned = search_capabilities(include_planned=True)
    assert len(with_planned) > len(without)
    assert any(c.lifecycle is Lifecycle.PLANNED for c in with_planned)


def test_query_matches_binary_and_description() -> None:
    by_binary = search_capabilities(query="secretsdump")
    assert any(c.id == "impacket" for c in by_binary)
    # Free-text also hits the description text, not just ids/binaries.
    assert search_capabilities(query="port scanner")


def test_category_filter_is_exact() -> None:
    recon = search_capabilities(category="recon")
    assert recon
    assert all(c.category == "recon" for c in recon)
    assert search_capabilities(category="RECON") == recon


def test_phase_filter_matches_mitre_tactic() -> None:
    creds = search_capabilities(phase="TA0006")
    assert creds
    assert all("TA0006" in c.phases for c in creds)


def test_max_risk_excludes_riskier_tools() -> None:
    passive = search_capabilities(max_risk="passive")
    assert passive
    assert all(c.risk_tier is RiskTier.PASSIVE for c in passive)
    # A higher ceiling is a superset.
    intrusive = search_capabilities(max_risk="intrusive")
    assert len(intrusive) >= len(passive)
    assert all(c.risk_tier.value <= RiskTier.INTRUSIVE.value for c in intrusive)


def test_unknown_max_risk_raises() -> None:
    with pytest.raises(ValueError, match="unknown max_risk"):
        search_capabilities(max_risk="nope")


def test_reach_instruction_reflects_delivery() -> None:
    assert "run it directly" in reach_instruction(BINARY_TO_CAPABILITY["nmap"])
    assert "sidecar" in reach_instruction(BINARY_TO_CAPABILITY["ghidra"])
    assert "NOT bash" in reach_instruction(BINARY_TO_CAPABILITY["ghidra"])


def test_reach_instruction_base_capability_with_service_requires_ops_start() -> None:
    # Sliver ships in the base image but is inert until its c2-sliver
    # workload runs — the hint must not claim it is directly runnable and
    # must have the agent confirm readiness before invoking.
    sliver = BINARY_TO_CAPABILITY["sliver"]
    assert sliver.delivery == "base"
    assert sliver.requires_service == "c2-sliver"
    text = reach_instruction(sliver)
    assert "c2-sliver" in text
    assert "ops_start" in text
    assert "ops_status" in text
    assert "run it directly" not in text


def test_reach_instruction_pip_uses_break_system_packages() -> None:
    # Kali's Python is externally managed; plain pip3 install is rejected.
    supported_pip = Capability(
        id="some-pip-tool",
        category="dfir",
        description="hypothetical supported pip tool",
        binaries=("some-pip-tool",),
        delivery="pip",
        lifecycle=Lifecycle.SUPPORTED,
    )
    text = reach_instruction(supported_pip)
    assert "--break-system-packages" in text
    assert "some-pip-tool" in text


def test_reach_instruction_planned_tool_is_not_installed() -> None:
    # Planned tools (any delivery) must never be described as installed,
    # or agents will invoke commands that do not exist.
    for binary in ("certipy",):
        cap = BINARY_TO_CAPABILITY[binary]
        assert cap.lifecycle is Lifecycle.PLANNED
        text = reach_instruction(cap)
        assert "not pre-installed" in text
        assert "installed in the sandbox" not in text


def test_reach_instruction_covers_every_registry_delivery() -> None:
    # No capability should fall through to the raw delivery string.
    for cap in CAPABILITY_REGISTRY:
        text = reach_instruction(cap)
        assert text and text != cap.delivery


# ── Role/phase/risk-aware discovery policy ──────────────────────────────

_REGISTRY_PHASES = {p for cap in CAPABILITY_REGISTRY for p in cap.phases}


def test_role_capability_policy_lookup() -> None:
    assert role_capability_policy(None) is None
    assert role_capability_policy("") is None
    assert role_capability_policy("not-a-role") is None
    recon = role_capability_policy("recon")
    assert recon is not None
    assert recon.max_risk is RiskTier.BOUNDED_ACTIVE
    assert "TA0043" in recon.phases


def test_role_policy_phases_are_real_registry_tactics() -> None:
    # A policy that highlights a phase no tool declares would silently
    # surface nothing — keep the mapping honest against the registry.
    for role, policy in ROLE_CAPABILITY_POLICY.items():
        for phase in policy.phases:
            assert phase in _REGISTRY_PHASES, f"{role} highlights unknown phase {phase}"


def test_role_ceiling_narrows_search() -> None:
    # recon's bounded_active ceiling must exclude the intrusive+ tools an
    # unfiltered search returns.
    recon_policy = role_capability_policy("recon")
    assert recon_policy is not None
    recon_ceiling = recon_policy.max_risk
    scoped = search_capabilities(max_risk=recon_ceiling.name.lower())
    assert all(cap.risk_tier.value <= recon_ceiling.value for cap in scoped)
    assert len(scoped) < len(search_capabilities())
