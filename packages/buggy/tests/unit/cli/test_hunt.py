"""``buggy-cli hunt`` — flag translation + plan-only end to end."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from buggy.cli.hunt import _build_parser, _to_engage_argv
from buggy.cli.hunt import main as hunt_main


def _parse(argv: list[str]) -> argparse.Namespace:
    return _build_parser().parse_args(argv)


def test_targets_are_positional_and_repeatable() -> None:
    argv = _to_engage_argv(_parse(["a.example.com", "b.example.com"]))
    assert argv.count("--target") == 2
    assert "a.example.com" in argv
    assert "b.example.com" in argv


def test_default_scope_is_not_widened() -> None:
    # No --scope / --include-subdomains → no --in-scope passed, so engage
    # applies its conservative "scope == targets exactly" default.
    argv = _to_engage_argv(_parse(["example.com"]))
    assert "--in-scope" not in argv


def test_include_subdomains_adds_host_and_wildcard() -> None:
    argv = _to_engage_argv(_parse(["https://api.example.com/app", "--include-subdomains"]))
    # host is derived from the URL, then both host and *.host are added.
    pairs = [argv[i + 1] for i, a in enumerate(argv) if a == "--in-scope"]
    assert "api.example.com" in pairs
    assert "*.api.example.com" in pairs


def test_exclude_maps_to_out_of_scope() -> None:
    argv = _to_engage_argv(_parse(["example.com", "--exclude", "admin.example.com"]))
    i = argv.index("--out-of-scope")
    assert argv[i + 1] == "admin.example.com"


def test_scope_and_instruction_and_mode_passthrough() -> None:
    argv = _to_engage_argv(
        _parse(
            [
                "example.com",
                "--scope",
                "*.example.com",
                "--instruction",
                "focus auth",
                "--mode",
                "warn",
            ]
        )
    )
    assert argv[argv.index("--in-scope") + 1] == "*.example.com"
    assert argv[argv.index("--instruction") + 1] == "focus auth"
    assert argv[argv.index("--mode") + 1] == "warn"


def test_main_plan_only_into_tmp(tmp_path: Path) -> None:
    # engage accepts --workspace-root; hunt doesn't expose it, so drive the
    # bundle location via the env var engage reads.
    import os

    os.environ["BUGGY_ENGAGEMENT_WORKSPACE"] = str(tmp_path)
    try:
        rc = hunt_main(["https://api.example.com", "--engagement-name", "h2", "--plan-only"])
    finally:
        del os.environ["BUGGY_ENGAGEMENT_WORKSPACE"]
    assert rc == 0
    roe = json.loads((tmp_path / "h2" / "plan" / "roe.json").read_text())
    assert roe["machine_enforcement"]["in_scope"] == ["api.example.com"]
