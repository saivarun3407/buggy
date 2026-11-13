"""``buggy-cli engage`` — scope parsing, plan bundle, defaults."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from buggy.cli.engage import (
    _host_from_target,
    _load_scope_file,
    _split_patterns,
    _validate_scope_entries,
    _write_plan_bundle,
    main,
)

# ── scope-file parsing ────────────────────────────────────────────────


def test_scope_file_json(tmp_path: Path) -> None:
    f = tmp_path / "scope.json"
    f.write_text(
        json.dumps(
            {
                "in_scope": ["*.example.com", "example.com"],
                "out_of_scope": ["admin.example.com"],
            }
        )
    )
    ins, outs = _load_scope_file(f)
    assert ins == ["*.example.com", "example.com"]
    assert outs == ["admin.example.com"]


def test_scope_file_text_prefixes(tmp_path: Path) -> None:
    f = tmp_path / "scope.txt"
    f.write_text(
        "# engagement scope\n"
        "in: *.example.com\n"
        "out: admin.example.com\n"
        "-staging.example.com\n"
        "bare.example.com\n"
    )
    ins, outs = _load_scope_file(f)
    assert ins == ["*.example.com", "bare.example.com"]
    assert outs == ["admin.example.com", "staging.example.com"]


def test_scope_file_missing_errors(tmp_path: Path) -> None:
    with pytest.raises(RuntimeError, match="failed to read"):
        _load_scope_file(tmp_path / "nope.json")


def test_scope_file_bad_json_errors(tmp_path: Path) -> None:
    f = tmp_path / "s.json"
    f.write_text("{ not json")
    with pytest.raises(RuntimeError, match="not valid JSON"):
        _load_scope_file(f)


# ── pattern handling ──────────────────────────────────────────────────


def test_split_patterns_flattens_commas() -> None:
    assert _split_patterns(["a.com,b.com", " c.com "]) == ["a.com", "b.com", "c.com"]


def test_host_from_target() -> None:
    assert _host_from_target("https://api.example.com/app?q=1") == "api.example.com"
    assert _host_from_target("10.0.0.5") == "10.0.0.5"
    assert _host_from_target("example.com") == "example.com"


def test_validate_scope_entries_catches_bad() -> None:
    errors = _validate_scope_entries(["ok.example.com", ""], ["10.0.0.0/33"])
    assert errors  # empty entry + invalid CIDR both surface
    assert any("in_scope" in e for e in errors)
    assert any("out_of_scope" in e for e in errors)


def test_validate_scope_entries_clean() -> None:
    assert _validate_scope_entries(["*.example.com"], ["10.0.0.0/24"]) == []


# ── plan bundle ───────────────────────────────────────────────────────


def test_write_plan_bundle(tmp_path: Path) -> None:
    plan = _write_plan_bundle(
        root=tmp_path,
        slug="eng-1",
        targets=["api.example.com"],
        in_scope=["*.example.com"],
        out_of_scope=["admin.example.com"],
        mode="enforce",
        forbidden_commands=["rm -rf /"],
        instruction="focus the API",
    )
    roe = json.loads((plan / "roe.json").read_text())
    me = roe["machine_enforcement"]
    assert me["mode"] == "enforce"
    assert me["in_scope"] == ["*.example.com"]
    assert me["out_of_scope"] == ["admin.example.com"]
    assert me["forbidden_command_patterns"] == ["rm -rf /"]

    # The document must load through the real middleware parser.
    from buggy_core.types.roe import MachineEnforcement

    rules = MachineEnforcement.from_dict(me)
    assert rules.mode.value == "enforce"
    assert len(rules.in_scope) == 1

    conops = (plan / "conops.md").read_text()
    assert "api.example.com" in conops
    assert "focus the API" in conops


# ── end-to-end (plan-only path; no SDK) ───────────────────────────────


def test_main_plan_only_derives_default_scope(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    rc = main(
        [
            "--target",
            "https://api.example.com",
            "--workspace-root",
            str(tmp_path),
            "--engagement-name",
            "t1",
            "--plan-only",
        ]
    )
    assert rc == 0
    roe = json.loads((tmp_path / "t1" / "plan" / "roe.json").read_text())
    # No --in-scope: boundary = the target itself, never auto-widened.
    assert roe["machine_enforcement"]["in_scope"] == ["api.example.com"]
    assert roe["machine_enforcement"]["mode"] == "enforce"


def test_main_rejects_bad_scope(tmp_path: Path) -> None:
    rc = main(
        [
            "--target",
            "example.com",
            "--out-of-scope",
            "10.0.0.0/33",
            "--workspace-root",
            str(tmp_path),
            "--engagement-name",
            "t2",
            "--plan-only",
        ]
    )
    assert rc == 2
