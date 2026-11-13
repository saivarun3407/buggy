"""Unit tests for the bug-bounty intake clients and scope-rule folding.

API-only by design — no live network calls. The platform clients are
exercised by monkeypatching the single ``_get_json`` HTTP seam with canned
JSON:API / Bugcrowd payloads; the pure parsing / rule-derivation helpers
are tested directly; and the ``ingest_bounty_scope`` rule-folding is tested
against a throwaway workspace.

Credential hygiene is asserted explicitly: a token value placed in the
environment must never appear in any tool output.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from buggy.middleware.roe import _load_rules_for_workspace
from buggy.tools.research import bounty_intake as bi
from buggy.tools.research.bounty_scope import ingest_bounty_scope

_H1_USER = "1234abcd"
_H1_TOKEN = "h1-supersecret-token-value"
_BC_USER = "bc-id-0001"
_BC_TOKEN = "bc-supersecret-token-value"


@pytest.fixture
def _h1_creds(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("H1_API_USERNAME", _H1_USER)
    monkeypatch.setenv("H1_API_TOKEN", _H1_TOKEN)


@pytest.fixture
def _bc_creds(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("BUGCROWD_API_USERNAME", _BC_USER)
    monkeypatch.setenv("BUGCROWD_API_TOKEN", _BC_TOKEN)


@pytest.fixture
def _no_creds(monkeypatch: pytest.MonkeyPatch) -> None:
    for var in (
        "H1_API_USERNAME",
        "H1_API_TOKEN",
        "BUGCROWD_API_USERNAME",
        "BUGCROWD_API_TOKEN",
    ):
        monkeypatch.delenv(var, raising=False)


# ── Pure helpers ──────────────────────────────────────────────────────────


def test_norm_host_strips_scheme_path_port() -> None:
    assert bi._norm_host("https://API.Example.com:443/a/b?x=1") == "api.example.com"
    assert bi._norm_host("*.Example.com") == "*.example.com"
    # CIDR is preserved intact.
    assert bi._norm_host("203.0.113.0/24") == "203.0.113.0/24"


def test_clamp_bounds_and_default() -> None:
    assert bi._clamp(0) == 1
    assert bi._clamp(9999) == 200
    assert bi._clamp("not-an-int") == 50  # pyright: ignore[reportArgumentType]


def test_derive_rules_detects_no_automation_and_rate() -> None:
    rules = bi._derive_rules_from_policy("No automated scanning. Max 10 requests per second.")
    assert rules["no_automated_tools"] is True
    assert rules["forbidden_command_patterns"] == list(bi.SCANNER_COMMAND_PATTERNS)
    assert rules["min_inter_request_delay_ms"] == 100  # 1000 / 10
    assert rules["notes"]


def test_derive_rules_benign_policy_has_no_constraints() -> None:
    rules = bi._derive_rules_from_policy("Please test responsibly and report findings.")
    assert rules["no_automated_tools"] is False
    assert rules["forbidden_command_patterns"] == []
    assert rules["min_inter_request_delay_ms"] == 0


def test_partition_h1_scopes_splits_by_eligibility_and_type() -> None:
    scopes = [
        {
            "attributes": {
                "asset_identifier": "https://api.example.com",
                "asset_type": "url",
                "eligible_for_submission": True,
                "max_severity": "critical",
            }
        },
        {"attributes": {"asset_identifier": "*.example.com", "asset_type": "wildcard"}},
        {
            "attributes": {
                "asset_identifier": "legacy.example.com",
                "asset_type": "domain",
                "eligible_for_submission": False,
            }
        },
        {
            "attributes": {
                "asset_identifier": "com.example.app",
                "asset_type": "google_play_app_id",
                "eligible_for_submission": True,
            }
        },
    ]
    in_scope, out_scope, non_network, caps = bi._partition_h1_scopes(scopes)
    assert in_scope == ["api.example.com", "*.example.com"]
    assert out_scope == ["legacy.example.com"]
    assert non_network == ["com.example.app (google_play_app_id)"]
    assert caps == {"api.example.com": "critical"}


def test_partition_bc_targets_uses_group_scope_flag() -> None:
    included = [
        {"type": "target_group", "id": "g1", "attributes": {"in_scope": True}},
        {"type": "target_group", "id": "g2", "attributes": {"in_scope": False}},
        {
            "type": "target",
            "attributes": {"name": "https://www.example.com", "category": "website"},
            "relationships": {"target_group": {"data": {"id": "g1"}}},
        },
        {
            "type": "target",
            "attributes": {"name": "api.example.com", "category": "api"},
            "relationships": {"target_group": {"data": {"id": "g2"}}},
        },
        {
            "type": "target",
            "attributes": {"name": "com.example.app", "category": "android"},
            "relationships": {"target_group": {"data": {"id": "g1"}}},
        },
    ]
    in_scope, out_scope, non_network = bi._partition_bc_targets(included)
    assert in_scope == ["www.example.com"]
    assert out_scope == ["api.example.com"]
    assert non_network == ["com.example.app (android)"]


# ── Credential gating ─────────────────────────────────────────────────────


@pytest.mark.usefixtures("_no_creds")
def test_tools_report_missing_credentials() -> None:
    for tool, args in (
        (bi.h1_list_programs, {}),
        (bi.h1_get_program_scope, {"program_handle": "acme"}),
        (bi.bugcrowd_list_programs, {}),
        (bi.bugcrowd_get_program_scope, {"program": "acme"}),
    ):
        payload = json.loads(tool.invoke(args))
        assert payload["error"] == "missing_credentials"
        assert payload["needed_env"]


@pytest.mark.usefixtures("_no_creds")
def test_intake_status_reports_unavailable() -> None:
    status = json.loads(bi.bounty_intake_status.invoke({}))
    assert status["hackerone"]["available"] is False
    assert status["bugcrowd"]["available"] is False
    assert status["hackerone"]["needed_env"] == ["H1_API_USERNAME", "H1_API_TOKEN"]


# ── HackerOne client (mocked HTTP) ────────────────────────────────────────


def _patch_get_json(
    monkeypatch: pytest.MonkeyPatch, router: dict[str, tuple[int, Any]]
) -> list[Any]:
    """Replace ``_get_json`` with a URL-substring router; record auth used."""
    seen_auth: list[Any] = []

    def fake(
        url: str, *, auth: Any = None, headers: Any = None, params: Any = None
    ) -> tuple[int, Any]:
        seen_auth.append(auth or (headers or {}).get("Authorization"))
        for needle, response in router.items():
            if needle in url:
                return response
        return 404, {"_error": "no route"}

    monkeypatch.setattr(bi, "_get_json", fake)
    return seen_auth


@pytest.mark.usefixtures("_h1_creds")
def test_h1_list_programs_filters_to_bounty_programs(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_get_json(
        monkeypatch,
        {
            "/programs": (
                200,
                {
                    "data": [
                        {"attributes": {"handle": "acme", "name": "Acme", "offers_bounties": True}},
                        {
                            "attributes": {
                                "handle": "beta",
                                "name": "Beta",
                                "offers_bounties": False,
                            }
                        },
                    ],
                    "links": {},
                },
            )
        },
    )
    out = json.loads(bi.h1_list_programs.invoke({"only_bounties": True}))
    assert out["count"] == 1
    assert out["programs"][0]["handle"] == "acme"


@pytest.mark.usefixtures("_h1_creds")
def test_h1_get_program_scope_builds_structured_payload(monkeypatch: pytest.MonkeyPatch) -> None:
    seen_auth = _patch_get_json(
        monkeypatch,
        {
            "/structured_scopes": (
                200,
                {
                    "data": [
                        {
                            "attributes": {
                                "asset_identifier": "*.example.com",
                                "asset_type": "wildcard",
                                "eligible_for_submission": True,
                                "max_severity": "high",
                            }
                        }
                    ],
                    "links": {},
                },
            ),
            "/scope_exclusions": (
                200,
                {"data": [{"attributes": {"name": "Self-XSS"}}], "links": {}},
            ),
            "/programs/acme": (
                200,
                {
                    "data": {
                        "attributes": {
                            "name": "Acme",
                            "offers_bounties": True,
                            "policy": "No automated scanning permitted. 5 requests per second.",
                        }
                    }
                },
            ),
        },
    )
    out = json.loads(bi.h1_get_program_scope.invoke({"program_handle": "acme"}))
    assert out["platform"] == "hackerone"
    assert out["in_scope"] == ["*.example.com"]
    assert out["severity_caps"] == {"*.example.com": "high"}
    assert out["excluded_classes"] == ["Self-XSS"]
    assert out["suggested_rules"]["no_automated_tools"] is True
    assert out["suggested_rules"]["min_inter_request_delay_ms"] == 200  # 1000 / 5
    # Auth was sent as the basic-auth tuple (identifier, token).
    assert (_H1_USER, _H1_TOKEN) in seen_auth


# ── Bugcrowd client (mocked HTTP) ─────────────────────────────────────────


@pytest.mark.usefixtures("_bc_creds")
def test_bugcrowd_get_program_scope_builds_payload(monkeypatch: pytest.MonkeyPatch) -> None:
    seen_auth = _patch_get_json(
        monkeypatch,
        {
            "/programs/acme": (
                200,
                {
                    "data": {
                        "attributes": {
                            "name": "Acme",
                            "code": "acme",
                            "scope": "Manual testing only.",
                        }
                    },
                    "included": [
                        {"type": "target_group", "id": "g1", "attributes": {"in_scope": True}},
                        {
                            "type": "target",
                            "attributes": {
                                "name": "https://www.example.com",
                                "category": "website",
                            },
                            "relationships": {"target_group": {"data": {"id": "g1"}}},
                        },
                    ],
                },
            )
        },
    )
    out = json.loads(bi.bugcrowd_get_program_scope.invoke({"program": "acme"}))
    assert out["platform"] == "bugcrowd"
    assert out["in_scope"] == ["www.example.com"]
    assert out["suggested_rules"]["no_automated_tools"] is True
    # Bugcrowd auth is a header token, never the basic-auth tuple.
    assert any(a and "Token" in str(a) for a in seen_auth)


# ── Credential hygiene ────────────────────────────────────────────────────


@pytest.mark.usefixtures("_h1_creds")
def test_token_never_appears_in_tool_output(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_get_json(
        monkeypatch,
        {
            "/programs": (
                200,
                {"data": [{"attributes": {"handle": "acme", "name": "Acme"}}], "links": {}},
            )
        },
    )
    raw = bi.h1_list_programs.invoke({})
    assert _H1_TOKEN not in raw
    assert _H1_USER not in raw


# ── Rule folding through ingest_bounty_scope ──────────────────────────────


def test_ingest_bounty_scope_folds_rules_into_enforcement(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Any
) -> None:
    monkeypatch.setenv("BUGGY_WORKSPACE_PATH", str(tmp_path))
    out = json.loads(
        ingest_bounty_scope.invoke(
            {
                "in_scope": '["*.example.com"]',
                "out_of_scope": '["blog.example.com"]',
                "platform": "hackerone",
                "program_handle": "acme",
                "mode": "enforce",
                "no_automated_tools": True,
                "forbidden_command_patterns": '["(?i)\\\\bcustomtool\\\\b"]',
                "min_inter_request_delay_ms": 250,
                "max_concurrent_connections": 4,
            }
        )
    )
    patterns = out["forbidden_command_patterns"]
    assert r"(?i)\bnuclei\b" in patterns
    assert r"(?i)\bcustomtool\b" in patterns
    assert out["min_inter_request_delay_ms"] == 250
    assert out["max_concurrent_connections"] == 4
    assert out["hard_enforced"] is True

    roe = json.loads((tmp_path / "plan" / "roe.json").read_text(encoding="utf-8"))
    enforced = roe["machine_enforcement"]
    assert enforced["min_inter_request_delay_ms"] == 250
    assert enforced["max_concurrent_connections"] == 4
    assert r"(?i)\bnuclei\b" in enforced["forbidden_command_patterns"]


@pytest.mark.parametrize("delay_ms", [3_600_001, 10**309], ids=["over-limit", "overflow"])
@pytest.mark.parametrize("existing_policy", [False, True], ids=["new", "existing"])
@pytest.mark.parametrize("mode", ["audit", "warn", "enforce"])
def test_ingest_rejects_excessive_delay_without_writing(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    delay_ms: int,
    existing_policy: bool,
    mode: str,
) -> None:
    monkeypatch.setenv("BUGGY_WORKSPACE_PATH", str(tmp_path))
    roe_path = tmp_path / "plan" / "roe.json"
    original = '{"machine_enforcement": {"mode": "enforce", "in_scope": ["old.example"]}}'
    if existing_policy:
        roe_path.parent.mkdir()
        roe_path.write_text(original, encoding="utf-8")

    response = json.loads(
        ingest_bounty_scope.invoke(
            {"in_scope": '["new.example"]', "min_inter_request_delay_ms": delay_ms, "mode": mode}
        )
    )
    assert response["error"] == "invalid_min_inter_request_delay"
    assert response["hard_enforced"] is False
    assert response["roe_path"] is None
    assert "3600000" in response["detail"]
    if existing_policy:
        assert roe_path.read_text(encoding="utf-8") == original
    else:
        assert not roe_path.parent.exists()


@pytest.mark.parametrize("delay_ms", [0, 1, 3_600_000])
def test_ingest_supported_delay_loads_unchanged(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, delay_ms: int
) -> None:
    monkeypatch.setenv("BUGGY_WORKSPACE_PATH", str(tmp_path))
    response = json.loads(
        ingest_bounty_scope.invoke(
            {"in_scope": '["allowed.example"]', "min_inter_request_delay_ms": delay_ms}
        )
    )
    assert response["hard_enforced"] is True
    assert response["min_inter_request_delay_ms"] == delay_ms
    assert _load_rules_for_workspace(str(tmp_path)).min_inter_request_delay_ms == delay_ms
