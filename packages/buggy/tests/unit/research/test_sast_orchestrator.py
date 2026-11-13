"""Unit tests for the SAST orchestrator tools.

No live scanner invocation — subprocess.run is monkeypatched. Tests verify
tech-stack detection, rule selection, SARIF counting, and graceful
degradation when scanner binaries are unavailable.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

from buggy.tools.research import sast_orchestrator as so

# ── Helpers ──────────────────────────────────────────────────────────────


def _make_tree(tmp_path: Path, files: dict[str, str]) -> str:
    """Create a directory tree from a {relative_path: content} mapping."""
    for rel, content in files.items():
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content)
    return str(tmp_path)


_SAMPLE_SARIF = json.dumps(
    {
        "$schema": "https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "semgrep"}},
                "results": [
                    {"level": "error", "message": {"text": "SQL injection"}, "ruleId": "sqli-1"},
                    {"level": "warning", "message": {"text": "Weak hash"}, "ruleId": "hash-1"},
                    {"level": "note", "message": {"text": "Debug info"}, "ruleId": "info-1"},
                ],
            }
        ],
    }
)


# ── Tech stack detection ─────────────────────────────────────────────────


class TestDetectStack:
    def test_python_project(self, tmp_path: Path) -> None:
        root = _make_tree(
            tmp_path,
            {
                "pyproject.toml": "[project]\nname = 'myapp'\n",
                "app/main.py": "import flask\n",
                "app/utils.py": "pass\n",
                "tests/test_main.py": "pass\n",
            },
        )
        result = so._detect_stack(root)
        assert result["primary_language"] == "python"
        assert any(entry["language"] == "python" for entry in result["languages"])

    def test_js_project_with_framework(self, tmp_path: Path) -> None:
        root = _make_tree(
            tmp_path,
            {
                "package.json": '{"dependencies": {"express": "^4.18.0"}}',
                "src/index.js": "const app = require('express');\n",
                "src/routes.ts": "export const routes = [];\n",
            },
        )
        result = so._detect_stack(root)
        assert result["primary_language"] in ("javascript", "typescript")
        assert "express" in result["frameworks"]

    def test_bad_root(self) -> None:
        result = so._detect_stack("/nonexistent/path")
        assert "error" in result

    def test_skips_hidden_dirs(self, tmp_path: Path) -> None:
        root = _make_tree(
            tmp_path,
            {
                ".git/objects/pack/a.py": "pass\n",
                "node_modules/lodash/index.js": "pass\n",
                "src/app.py": "pass\n",
            },
        )
        result = so._detect_stack(root)
        assert result["primary_language"] == "python"
        # node_modules js files should not be counted
        lang_map = {entry["language"]: entry["file_count"] for entry in result["languages"]}
        assert lang_map.get("javascript", 0) == 0


# ── Rule selection ───────────────────────────────────────────────────────


class TestRuleSelection:
    def test_auto_python(self) -> None:
        stack = {"primary_language": "python", "frameworks": ["django"]}
        configs = so._pick_semgrep_config(stack, "auto")
        assert "p/python" in configs
        assert "p/security-audit" in configs

    def test_user_override(self) -> None:
        stack = {"primary_language": "python"}
        configs = so._pick_semgrep_config(stack, "p/my-custom-rules")
        assert configs == ["p/my-custom-rules"]

    def test_unknown_language(self) -> None:
        stack = {"primary_language": "brainfuck"}
        configs = so._pick_semgrep_config(stack, "auto")
        assert "auto" in configs


# ── SARIF counting ───────────────────────────────────────────────────────


class TestSarifCounting:
    def test_valid_sarif(self, tmp_path: Path) -> None:
        sarif_file = tmp_path / "test.sarif"
        sarif_file.write_text(_SAMPLE_SARIF)
        counts = so._count_sarif_results(str(sarif_file))
        assert counts["error"] == 1
        assert counts["warning"] == 1
        assert counts["note"] == 1
        assert counts["total"] == 3

    def test_missing_file(self) -> None:
        counts = so._count_sarif_results("/nonexistent.sarif")
        assert counts["total"] == 0

    def test_malformed_json(self, tmp_path: Path) -> None:
        bad = tmp_path / "bad.sarif"
        bad.write_text("not json")
        counts = so._count_sarif_results(str(bad))
        assert counts["total"] == 0


# ── Scanner unavailability ───────────────────────────────────────────────


class TestScannerUnavailable:
    def test_semgrep_not_found(self, tmp_path: Path) -> None:
        root = _make_tree(tmp_path, {"app.py": "pass\n"})
        with patch.object(so, "_which", return_value=None):
            result = json.loads(so.sast_run_semgrep.invoke({"root": root}))
        assert result["error"] == "scanner_unavailable"
        assert result["scanner"] == "semgrep"

    def test_bandit_not_found(self, tmp_path: Path) -> None:
        root = _make_tree(tmp_path, {"app.py": "pass\n"})
        with patch.object(so, "_which", return_value=None):
            result = json.loads(so.sast_run_bandit.invoke({"root": root}))
        assert result["error"] == "scanner_unavailable"

    def test_gitleaks_not_found(self, tmp_path: Path) -> None:
        root = _make_tree(tmp_path, {"app.py": "pass\n"})
        with patch.object(so, "_which", return_value=None):
            result = json.loads(so.sast_run_gitleaks.invoke({"root": root}))
        assert result["error"] == "scanner_unavailable"


# ── sast_detect_stack tool wrapper ───────────────────────────────────────


class TestSastDetectStackTool:
    def test_returns_json(self, tmp_path: Path) -> None:
        root = _make_tree(tmp_path, {"main.go": "package main\n", "go.mod": "module example\n"})
        result = json.loads(so.sast_detect_stack.invoke({"root": root}))
        assert result["primary_language"] == "go"


# ── sast_scan_all ────────────────────────────────────────────────────────


class TestSastScanAll:
    def test_all_unavailable(self, tmp_path: Path) -> None:
        root = _make_tree(tmp_path, {"app.py": "pass\n"})
        with patch.object(so, "_which", return_value=None):
            result = json.loads(so.sast_scan_all.invoke({"root": root}))
        assert result["detected_stack"]["primary_language"] == "python"
        unavailable = [s for s in result["scanners_run"] if s.get("status") == "unavailable"]
        assert len(unavailable) >= 2  # semgrep + gitleaks at minimum
