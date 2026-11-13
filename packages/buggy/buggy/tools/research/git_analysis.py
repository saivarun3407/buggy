"""Git history analysis — silent-patch detection, hot-file ranking.

Structured tooling for the analyst's most powerful white-box hunting
lane: finding security-relevant commits, ranking files by security
change frequency, and detecting silent patches (commits that quietly
add sanitisation / auth / bounds checks without a CVE disclosure).
"""

from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path
from typing import Any

from langchain_core.tools import tool

from buggy_core.utils.logging import get_logger

log = get_logger("research.git_analysis")

_TIMEOUT = 120

# ── Security keywords ────────────────────────────────────────────────────

_SECURITY_KEYWORDS = re.compile(
    r"(?i)\b(fix|patch|vuln|cve-|secur|sanitiz|escap|xss|sqli|inject|overflow"
    r"|auth|bypass|priv|race|csrf|ssrf|idor|deserializ|rce|exploit|traversal"
    r"|credential|password|token|leak|expos|permiss|access.control|validat"
    r"|bounds?.check|null.check|safe|unsafe|hardcod)"
)

_FIX_INDICATORS = re.compile(
    r"(?i)\b(fix|patch|resolv|repair|correct|address|mitigat|prevent|block)"
)

_SANITIZATION_PATTERNS = re.compile(
    r"(?i)\b(sanitiz|escap|encod|filter|strip|clean|purif|validat|whitelist|allowlist|denylist|blocklist)"
)


def _run_git(args: list[str], cwd: str, timeout: int = _TIMEOUT) -> tuple[int, str, str]:
    """Run a git command; return (exit_code, stdout, stderr)."""
    try:
        proc = subprocess.run(
            ["git", *args],
            capture_output=True,
            text=True,
            cwd=cwd,
            timeout=timeout,
        )
        return proc.returncode, proc.stdout, proc.stderr
    except subprocess.TimeoutExpired:
        return -1, "", "git command timed out"
    except FileNotFoundError:
        return -2, "", "git binary not found"


def _json(data: Any) -> str:
    return json.dumps(data, indent=2, default=str)


# ── @tool wrappers ───────────────────────────────────────────────────────


@tool
def git_hot_files(root: str = "/workspace/target", days: int = 180, top_k: int = 30) -> str:
    """Rank files by security-relevant commit frequency.

    Analyses git log for the last ``days`` days and counts how many
    commits per file contain security-related keywords (fix, vuln, auth,
    sanitize, etc.). Returns the top ``top_k`` files — these are the
    highest-value targets for manual review because they're where
    security bugs keep happening.
    """
    if not Path(root, ".git").is_dir():
        return _json({"error": "not_a_git_repo", "detail": f"{root} has no .git directory"})

    # Count security-relevant commits per file
    file_sec_count: dict[str, int] = {}
    file_total_count: dict[str, int] = {}
    current_msg_is_security = False
    in_files = False

    code, log_out, stderr = _run_git(
        [
            "log",
            f"--since={days} days ago",
            "--pretty=format:COMMIT_MSG:%s",
            "--name-only",
        ],
        cwd=root,
    )
    if code != 0:
        return _json({"error": "git_error", "detail": stderr[:300]})

    for line in log_out.splitlines():
        line = line.strip()
        if not line:
            in_files = False
            continue
        if line.startswith("COMMIT_MSG:"):
            msg = line[11:]
            current_msg_is_security = bool(_SECURITY_KEYWORDS.search(msg))
            in_files = True
            continue
        if in_files and not line.startswith("COMMIT_MSG:"):
            file_total_count[line] = file_total_count.get(line, 0) + 1
            if current_msg_is_security:
                file_sec_count[line] = file_sec_count.get(line, 0) + 1

    ranked = sorted(file_sec_count.items(), key=lambda x: x[1], reverse=True)[:top_k]
    return _json(
        {
            "root": root,
            "days_analyzed": days,
            "total_files_with_security_commits": len(file_sec_count),
            "hot_files": [
                {
                    "file": f,
                    "security_commits": sc,
                    "total_commits": file_total_count.get(f, sc),
                    "security_ratio": round(sc / max(file_total_count.get(f, 1), 1), 2),
                }
                for f, sc in ranked
            ],
        }
    )


@tool
def git_security_commits(
    root: str = "/workspace/target",
    since: str = "90 days ago",
    max_commits: int = 100,
) -> str:
    """Find commits with security-related keywords.

    Searches git log for commits whose message contains words like fix,
    vuln, auth, sanitize, bypass, inject, etc. Classifies each as
    ``fix`` (contains fix/patch/resolve), ``refactor`` (contains
    sanitize/validate), or ``other``. Returns the most recent matches
    with affected files.
    """
    if not Path(root, ".git").is_dir():
        return _json({"error": "not_a_git_repo"})

    code, stdout, stderr = _run_git(
        [
            "log",
            f"--since={since}",
            f"--max-count={max_commits}",
            "--pretty=format:COMMIT:%H|%an|%ai|%s",
            "--name-only",
        ],
        cwd=root,
    )
    if code != 0:
        return _json({"error": "git_error", "detail": stderr[:300]})

    commits: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    for line in stdout.splitlines():
        line = line.strip()
        if line.startswith("COMMIT:"):
            if current and _SECURITY_KEYWORDS.search(current.get("message", "")):
                commits.append(current)
            parts = line[7:].split("|", 3)
            if len(parts) == 4:
                msg = parts[3]
                classification = "other"
                if _FIX_INDICATORS.search(msg):
                    classification = "fix"
                elif _SANITIZATION_PATTERNS.search(msg):
                    classification = "refactor"
                current = {
                    "hash": parts[0][:12],
                    "author": parts[1],
                    "date": parts[2][:10],
                    "message": msg[:200],
                    "classification": classification,
                    "files": [],
                }
        elif current and line:
            current["files"].append(line)

    if current and _SECURITY_KEYWORDS.search(current.get("message", "")):
        commits.append(current)

    return _json(
        {
            "root": root,
            "since": since,
            "total_security_commits": len(commits),
            "commits": commits[:max_commits],
        }
    )


@tool
def git_find_silent_patches(
    root: str = "/workspace/target",
    tag_from: str = "",
    tag_to: str = "",
    path_filter: str = "",
) -> str:
    """Detect silent security patches between two git refs.

    Diffs commits between ``tag_from`` and ``tag_to``, looking for
    additions of sanitisation, validation, auth checks, or bounds checks
    without an accompanying CVE reference. These are strong indicators
    of quietly-fixed vulnerabilities — the pre-patch version is a
    potential N-day target.

    If ``tag_from``/``tag_to`` are empty, compares the last 50 commits.
    """
    if not Path(root, ".git").is_dir():
        return _json({"error": "not_a_git_repo"})

    if tag_from and tag_to:
        range_spec = f"{tag_from}..{tag_to}"
    else:
        range_spec = "HEAD~50..HEAD"

    cmd = [
        "log",
        range_spec,
        "--pretty=format:COMMIT:%H|%s",
        "-p",
        "--no-color",
        "--diff-filter=M",
    ]
    if path_filter:
        cmd.extend(["--", path_filter])

    code, stdout, stderr = _run_git(cmd, cwd=root, timeout=180)
    if code != 0:
        return _json({"error": "git_error", "detail": stderr[:300]})

    candidates: list[dict[str, Any]] = []
    current_commit = ""
    current_msg = ""
    current_file = ""
    added_sanitization: list[str] = []

    for line in stdout.splitlines():
        if line.startswith("COMMIT:"):
            # Flush previous
            if (
                current_commit
                and added_sanitization
                and not re.search(r"CVE-\d{4}-\d+", current_msg)
            ):
                candidates.append(
                    {
                        "commit": current_commit[:12],
                        "message": current_msg[:200],
                        "sanitization_added": added_sanitization[:5],
                        "file": current_file,
                        "likely_silent_patch": True,
                    }
                )
            parts = line[7:].split("|", 1)
            current_commit = parts[0] if parts else ""
            current_msg = parts[1] if len(parts) > 1 else ""
            added_sanitization = []
            current_file = ""
        elif line.startswith("diff --git"):
            parts = line.split()
            current_file = parts[-1].removeprefix("b/") if len(parts) >= 4 else ""
        elif line.startswith("+") and not line.startswith("+++"):
            if _SANITIZATION_PATTERNS.search(line):
                added_sanitization.append(line[:120].strip())

    # Flush last
    if current_commit and added_sanitization and not re.search(r"CVE-\d{4}-\d+", current_msg):
        candidates.append(
            {
                "commit": current_commit[:12],
                "message": current_msg[:200],
                "sanitization_added": added_sanitization[:5],
                "file": current_file,
                "likely_silent_patch": True,
            }
        )

    return _json(
        {
            "root": root,
            "range": range_spec,
            "total_silent_patch_candidates": len(candidates),
            "candidates": candidates[:50],
        }
    )


GIT_ANALYSIS_TOOLS = [git_hot_files, git_security_commits, git_find_silent_patches]
