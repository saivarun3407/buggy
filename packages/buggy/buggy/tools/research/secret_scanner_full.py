"""Full-codebase secret scanning — filesystem, git history, CI/CD configs.

Extends the existing ``secret_scanner.py`` (JS-only, live-validation)
with broad filesystem walking, git history scanning, and CI/CD config
secret detection.  Uses the same regex table architecture but covers
*all* file types, not just JS bundles.

Designed to complement ``gitleaks`` (SARIF output → KG ingestion) when
gitleaks is unavailable, and to add CI/CD-specific patterns that
gitleaks doesn't cover (GitHub Actions secret refs, Docker build args,
env-file leaks).
"""

from __future__ import annotations

import json
import os
import re
import subprocess
from pathlib import Path
from typing import Any

from langchain_core.tools import tool

from buggy_core.utils.logging import get_logger

log = get_logger("research.secret_scanner_full")

_MAX_FILES = 20_000
_MAX_BYTES = 256 * 1024  # 256 KB per file

# ── Secret patterns (superset of secret_scanner.py) ──────────────────────

_SECRET_PATTERNS: dict[str, re.Pattern[str]] = {
    "aws_access_key": re.compile(
        r"(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}"
    ),
    "aws_secret_key": re.compile(r"""(?i)aws[^\n]{0,30}?['"]([A-Za-z0-9/+=]{40})['"]"""),
    "github_token": re.compile(r"gh[pousr]_[A-Za-z0-9]{36}"),
    "github_fine_grained": re.compile(r"github_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59}"),
    "gitlab_pat": re.compile(r"glpat-[A-Za-z0-9_-]{20}"),
    "slack_token": re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,48}"),
    "slack_webhook": re.compile(
        r"https://hooks\.slack\.com/services/T[A-Za-z0-9_]+/B[A-Za-z0-9_]+/[A-Za-z0-9_]+"
    ),
    "openai_api_key": re.compile(r"sk-(?:proj-)?[A-Za-z0-9_-]{20,}"),
    "stripe_key": re.compile(r"(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{24,}"),
    "google_api_key": re.compile(r"AIza[0-9A-Za-z_-]{35}"),
    "twilio_api_key": re.compile(r"SK[0-9a-fA-F]{32}"),
    "sendgrid_api_key": re.compile(r"SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}"),
    "private_key": re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"),
    "jwt": re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
    "generic_secret": re.compile(
        r"""(?i)(?:api[_-]?key|secret|token|password|passwd|auth)\s*[:=]\s*['"]([A-Za-z0-9/+=_-]{16,})['"]"""
    ),
    "connection_string": re.compile(r"(?i)(?:mongodb|postgres|mysql|redis|amqp)://[^'\"\s]{10,}"),
    "bearer_token": re.compile(r"""(?i)bearer\s+[A-Za-z0-9_-]{20,}"""),
}

# Files / directories to skip entirely
_SKIP_DIRS = frozenset(
    {
        ".git",
        "node_modules",
        "vendor",
        "__pycache__",
        ".venv",
        "venv",
        ".tox",
        ".mypy_cache",
        ".pytest_cache",
        "dist",
        "build",
    }
)

_SKIP_EXTENSIONS = frozenset(
    {
        ".pyc",
        ".pyo",
        ".class",
        ".o",
        ".so",
        ".dll",
        ".exe",
        ".png",
        ".jpg",
        ".jpeg",
        ".gif",
        ".ico",
        ".svg",
        ".woff",
        ".woff2",
        ".ttf",
        ".eot",
        ".mp3",
        ".mp4",
        ".zip",
        ".tar",
        ".gz",
        ".bz2",
        ".xz",
        ".7z",
        ".jar",
        ".war",
        ".ear",
    }
)

# ── CI/CD-specific patterns ──────────────────────────────────────────────

_CICD_PATTERNS: dict[str, re.Pattern[str]] = {
    "gha_secret_ref": re.compile(r"\$\{\{\s*secrets\.[A-Z_]+\s*\}\}"),
    "docker_build_arg_secret": re.compile(r"(?i)ARG\s+(?:password|secret|token|api_key)\s*="),
    "env_file_secret": re.compile(
        r"""(?i)^(?:password|secret|token|api_key|private_key)\s*=\s*[^\s]+""", re.MULTILINE
    ),
    "hardcoded_credential": re.compile(r"""(?i)(?:password|passwd)\s*[:=]\s*['"][^'"]{4,}['"]"""),
}

_CICD_FILES = frozenset(
    {
        ".github/workflows",
        ".gitlab-ci.yml",
        "Jenkinsfile",
        ".circleci/config.yml",
        ".travis.yml",
        "bitbucket-pipelines.yml",
        "azure-pipelines.yml",
        "Dockerfile",
        "docker-compose.yml",
        "docker-compose.yaml",
        ".env",
        ".env.example",
        ".env.local",
    }
)


def _is_cicd_file(rel_path: str) -> bool:
    """Check if a path is a CI/CD configuration or secrets-adjacent file."""
    for cicd in _CICD_FILES:
        if rel_path.startswith(cicd) or rel_path.endswith(cicd.split("/")[-1]):
            return True
    return False


# ── Scanning logic ───────────────────────────────────────────────────────


def _scan_file(path: Path, patterns: dict[str, re.Pattern[str]]) -> list[dict[str, Any]]:
    """Scan a single file for secret patterns; return findings."""
    try:
        content = path.read_text(errors="replace")[:_MAX_BYTES]
    except OSError:
        return []

    findings: list[dict[str, Any]] = []
    for line_no, line in enumerate(content.splitlines(), start=1):
        for name, pat in patterns.items():
            match = pat.search(line)
            if match:
                # Redact the actual secret value
                secret_preview = match.group(0)
                redacted = (
                    secret_preview[:8] + "..." + secret_preview[-4:]
                    if len(secret_preview) > 16
                    else "***REDACTED***"
                )
                findings.append(
                    {
                        "pattern": name,
                        "line": line_no,
                        "preview": redacted,
                        "file": str(path),
                    }
                )
    return findings


def _walk_and_scan(root: str, patterns: dict[str, re.Pattern[str]]) -> list[dict[str, Any]]:
    """Walk directory tree and scan all text files for secrets."""
    root_path = Path(root)
    all_findings: list[dict[str, Any]] = []
    file_count = 0

    for dirpath, dirnames, filenames in os.walk(root_path):
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
        for fname in filenames:
            if file_count >= _MAX_FILES:
                break
            fpath = Path(dirpath) / fname
            if fpath.suffix.lower() in _SKIP_EXTENSIONS:
                continue
            file_count += 1
            all_findings.extend(_scan_file(fpath, patterns))
        if file_count >= _MAX_FILES:
            break

    return all_findings


def _json(data: Any) -> str:
    return json.dumps(data, indent=2, default=str)


# ── @tool wrappers ───────────────────────────────────────────────────────


@tool
def scan_secrets_filesystem(root: str = "/workspace/target") -> str:
    """Scan the full filesystem for secrets — all file types, not just JS.

    Walks the target directory and matches every text file against a
    comprehensive secret-pattern table (AWS keys, GitHub tokens, private
    keys, JWTs, connection strings, generic secrets, etc.). Secret values
    are redacted in the output. Returns findings sorted by pattern name.
    """
    findings = _walk_and_scan(root, _SECRET_PATTERNS)
    findings.sort(key=lambda x: (x["pattern"], x["file"], x["line"]))
    return _json(
        {
            "root": root,
            "pattern_count": len(_SECRET_PATTERNS),
            "total_findings": len(findings),
            "findings": findings[:200],
        }
    )


@tool
def scan_secrets_git_history(root: str = "/workspace/target", max_commits: int = 500) -> str:
    """Scan git commit history for previously-committed secrets.

    Uses ``git log -p`` to scan diffs for secrets that were committed and
    then removed. These are still exploitable if not rotated. Secret
    values are redacted in output.
    """
    root_path = Path(root)
    if not (root_path / ".git").is_dir():
        return _json({"error": "not_a_git_repo", "detail": f"{root} has no .git directory"})

    try:
        proc = subprocess.run(
            ["git", "log", "-p", f"--max-count={max_commits}", "--no-color"],
            capture_output=True,
            text=True,
            cwd=root,
            timeout=120,
        )
        if proc.returncode != 0:
            return _json({"error": "git_error", "detail": proc.stderr[:300]})
    except (subprocess.TimeoutExpired, FileNotFoundError) as exc:
        return _json({"error": "git_unavailable", "detail": str(exc)})

    findings: list[dict[str, Any]] = []
    current_commit = ""
    current_file = ""
    for line in proc.stdout.splitlines():
        if line.startswith("commit "):
            current_commit = line.split()[1][:12]
        elif line.startswith("diff --git"):
            parts = line.split()
            current_file = parts[-1].removeprefix("b/") if len(parts) >= 4 else ""
        elif line.startswith("+") and not line.startswith("+++"):
            for name, pat in _SECRET_PATTERNS.items():
                match = pat.search(line)
                if match:
                    secret = match.group(0)
                    redacted = (
                        secret[:8] + "..." + secret[-4:] if len(secret) > 16 else "***REDACTED***"
                    )
                    findings.append(
                        {
                            "pattern": name,
                            "commit": current_commit,
                            "file": current_file,
                            "preview": redacted,
                            "note": "Found in removed diff — secret may still be live if not rotated",
                        }
                    )

    findings = findings[:200]
    return _json(
        {
            "root": root,
            "commits_scanned": max_commits,
            "total_findings": len(findings),
            "findings": findings,
        }
    )


@tool
def scan_secrets_cicd(root: str = "/workspace/target") -> str:
    """Scan CI/CD configs for hardcoded secrets and misconfigurations.

    Checks GitHub Actions workflows, Dockerfiles, docker-compose files,
    .env files, Jenkinsfiles, and other CI configs for hardcoded
    credentials, insecure secret references, and build-arg leaks.
    """
    root_path = Path(root)
    if not root_path.is_dir():
        return _json({"error": "bad_request", "detail": f"{root} is not a directory"})

    findings: list[dict[str, Any]] = []
    scanned_files: list[str] = []

    for dirpath, dirnames, filenames in os.walk(root_path):
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
        rel_dir = str(Path(dirpath).relative_to(root_path))
        for fname in filenames:
            rel_path = str(Path(rel_dir) / fname)
            if not _is_cicd_file(rel_path):
                continue
            fpath = Path(dirpath) / fname
            scanned_files.append(rel_path)
            file_findings = _scan_file(fpath, {**_CICD_PATTERNS, **_SECRET_PATTERNS})
            findings.extend(file_findings)

    findings.sort(key=lambda x: (x["file"], x["line"]))
    return _json(
        {
            "root": root,
            "cicd_files_scanned": scanned_files,
            "total_findings": len(findings),
            "findings": findings[:200],
        }
    )


SECRET_SCANNER_FULL_TOOLS = [
    scan_secrets_filesystem,
    scan_secrets_git_history,
    scan_secrets_cicd,
]
