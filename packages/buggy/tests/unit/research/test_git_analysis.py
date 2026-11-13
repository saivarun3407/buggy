"""Unit tests for git history analysis tools.

Git commands are monkeypatched — no live git operations.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

from buggy.tools.research import git_analysis as ga


def _make_git_repo(tmp_path: Path) -> str:
    """Create a minimal directory with a .git marker."""
    (tmp_path / ".git").mkdir()
    return str(tmp_path)


class TestGitHotFiles:
    def test_not_git_repo(self, tmp_path: Path) -> None:
        result = json.loads(ga.git_hot_files.invoke({"root": str(tmp_path)}))
        assert result["error"] == "not_a_git_repo"

    def test_parses_output(self, tmp_path: Path) -> None:
        root = _make_git_repo(tmp_path)
        fake_log = (
            "COMMIT_MSG:fix sql injection in user handler\n"
            "src/handlers/user.py\n"
            "src/models/user.py\n"
            "\n"
            "COMMIT_MSG:add feature logging\n"
            "src/utils/log.py\n"
            "\n"
            "COMMIT_MSG:patch auth bypass vulnerability\n"
            "src/handlers/user.py\n"
            "src/middleware/auth.py\n"
        )
        with patch.object(ga, "_run_git", return_value=(0, fake_log, "")):
            result = json.loads(ga.git_hot_files.invoke({"root": root}))
        assert result["total_files_with_security_commits"] >= 2
        files = [f["file"] for f in result["hot_files"]]
        assert "src/handlers/user.py" in files


class TestGitSecurityCommits:
    def test_not_git_repo(self, tmp_path: Path) -> None:
        result = json.loads(ga.git_security_commits.invoke({"root": str(tmp_path)}))
        assert result["error"] == "not_a_git_repo"

    def test_classifies_commits(self, tmp_path: Path) -> None:
        root = _make_git_repo(tmp_path)
        fake_log = (
            "COMMIT:abc123def456|dev|2024-01-15|fix XSS vulnerability in comments\n"
            "src/views/comments.py\n"
            "\n"
            "COMMIT:def789ghi012|dev|2024-01-10|add input sanitization for forms\n"
            "src/forms.py\n"
        )
        with patch.object(ga, "_run_git", return_value=(0, fake_log, "")):
            result = json.loads(ga.git_security_commits.invoke({"root": root}))
        assert result["total_security_commits"] == 2
        classifications = [c["classification"] for c in result["commits"]]
        assert "fix" in classifications
        assert "refactor" in classifications


class TestGitFindSilentPatches:
    def test_not_git_repo(self, tmp_path: Path) -> None:
        result = json.loads(ga.git_find_silent_patches.invoke({"root": str(tmp_path)}))
        assert result["error"] == "not_a_git_repo"

    def test_detects_silent_patch(self, tmp_path: Path) -> None:
        root = _make_git_repo(tmp_path)
        fake_diff = (
            "COMMIT:aaa111bbb222|improve user handler\n"
            "diff --git a/src/user.py b/src/user.py\n"
            "+    sanitize_input(user_data)\n"
            "+    validate_email(email)\n"
            "\n"
            "COMMIT:ccc333ddd444|CVE-2024-1234 fix buffer overflow\n"
            "diff --git a/src/parser.py b/src/parser.py\n"
            "+    bounds_check(input_len)\n"
        )
        with patch.object(ga, "_run_git", return_value=(0, fake_diff, "")):
            result = json.loads(ga.git_find_silent_patches.invoke({"root": root}))
        # The CVE-referenced commit should NOT be flagged as silent
        # The "improve user handler" commit with sanitization IS silent
        assert result["total_silent_patch_candidates"] >= 1
        commits = [c["commit"] for c in result["candidates"]]
        assert "aaa111bbb222"[:12] in commits
        # CVE commit should be excluded
        assert "ccc333ddd444"[:12] not in commits
