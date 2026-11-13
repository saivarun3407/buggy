"""Tests for the capability_search agent tool."""

from __future__ import annotations

import json

from buggy.tools.bash import BASH_TOOLS
from buggy.tools.discovery import (
    CAPABILITY_DISCOVERY_TOOLS,
    capability_search,
    make_capability_search,
)


def _invoke(**kwargs: object) -> dict:
    return json.loads(capability_search.invoke(kwargs))


def _invoke_role(role: str | None, **kwargs: object) -> dict:
    return json.loads(make_capability_search(role).invoke(kwargs))


def test_capability_search_is_wired_into_bash_tools() -> None:
    # Every bash-running agent spreads BASH_TOOLS, so discovery ships with it.
    assert capability_search in BASH_TOOLS
    assert CAPABILITY_DISCOVERY_TOOLS == [capability_search]


def test_returns_structured_matches_with_reach() -> None:
    result = _invoke(query="secretsdump")
    assert result["count"] >= 1
    impacket = next(c for c in result["capabilities"] if c["id"] == "impacket")
    assert "impacket-secretsdump" in impacket["binaries"]
    assert impacket["reach"]
    assert impacket["risk"] == "intrusive"


def test_category_filter() -> None:
    result = _invoke(category="recon")
    assert result["count"] >= 1
    assert all(c["category"] == "recon" for c in result["capabilities"])


def test_sidecar_reach_is_not_bash() -> None:
    result = _invoke(query="ghidra", include_planned=True)
    ghidra = next(c for c in result["capabilities"] if c["id"] == "ghidra")
    assert ghidra["delivery"] == "sidecar"
    assert "NOT bash" in ghidra["reach"]


def test_no_match_returns_guidance_note() -> None:
    result = _invoke(query="definitely-not-a-real-tool-xyz")
    assert result["count"] == 0
    assert result["capabilities"] == []
    assert "note" in result


def test_invalid_max_risk_returns_error_and_valid_values() -> None:
    result = _invoke(max_risk="bogus")
    assert "error" in result
    assert "passive" in result["valid_max_risk"]


def test_planned_hidden_by_default() -> None:
    default = _invoke(query="certipy")
    planned = _invoke(query="certipy", include_planned=True)
    assert default["count"] == 0
    assert planned["count"] >= 1


# ── Role scoping (make_capability_search) ───────────────────────────────


def test_role_scoped_tool_name_matches_default() -> None:
    # build_tools swaps by name, and prompts reference "capability_search".
    assert make_capability_search("recon").name == capability_search.name == "capability_search"


def test_role_applies_default_risk_ceiling() -> None:
    # recon's ceiling is bounded_active — an intrusive tool the unscoped
    # tool returns must be filtered out, and the default surfaced.
    unscoped = _invoke(query="secretsdump")
    assert unscoped["count"] >= 1  # impacket is intrusive
    scoped = _invoke_role("recon", query="secretsdump")
    assert scoped["count"] == 0
    assert scoped["applied_defaults"]["max_risk"] == "bounded_active"
    assert scoped["role"] == "recon"
    assert scoped["role_risk_ceiling"] == "bounded_active"


def test_explicit_max_risk_overrides_role_ceiling() -> None:
    scoped = _invoke_role("recon", query="secretsdump", max_risk="intrusive")
    assert scoped["count"] >= 1
    assert "applied_defaults" not in scoped


def test_role_highlights_recommended_for_phase() -> None:
    scoped = _invoke_role("recon", category="recon")
    assert scoped["count"] >= 1
    assert "TA0043" in scoped["role_phases"]
    # recon tools are TA0043 — every returned recon-category tool qualifies.
    assert scoped["recommended_for_role"]


def test_recommended_survives_result_cap(monkeypatch) -> None:
    # With a tiny cap, a role's phase-relevant tool that sorts late in the
    # registry must still be pulled into the shown slice and recommended —
    # not truncated away. recon → TA0043 (recon-category tools).
    from buggy.tools import discovery

    monkeypatch.setattr(discovery, "_RESULT_CAP", 3)
    scoped = json.loads(discovery.make_capability_search("recon").invoke({"max_risk": "intrusive"}))
    assert scoped["count"] > 3
    assert scoped["returned"] == 3
    # Every shown tool is phase-relevant (recommended sorted first), and the
    # recommended list only names tools actually present in the payload.
    shown_ids = {c["id"] for c in scoped["capabilities"]}
    assert scoped["recommended_for_role"]
    assert set(scoped["recommended_for_role"]) <= shown_ids
    assert all("TA0043" in c["phases"] for c in scoped["capabilities"])


def test_unmapped_role_has_no_defaults() -> None:
    scoped = _invoke_role("buggy", query="secretsdump")
    assert scoped["count"] >= 1  # no risk ceiling applied
    assert "applied_defaults" not in scoped
    assert "role_risk_ceiling" not in scoped
    assert scoped["role"] == "buggy"
