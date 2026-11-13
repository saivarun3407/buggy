"""Structured SAST orchestration — tech-stack-aware scanner invocation.

Replaces ad-hoc "run semgrep via bash" with a first-class tool surface
that auto-detects the target's language/framework stack, picks the right
scanner configs, invokes the scanner, and returns a structured summary.
The agent then calls ``kg_ingest_sarif`` to lift results into the KG.

Supported scanners (all output SARIF):
- **semgrep** — polyglot, pattern + taint rules, ``--config auto`` or custom
- **bandit** — Python-specific SAST
- **gitleaks** — secrets across all file types and git history

Each scanner is invoked via subprocess with a timeout. When a binary is
unavailable the tool returns a ``scanner_unavailable`` payload so the
agent can install it or skip gracefully.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any

from langchain_core.tools import tool

from buggy_core.utils.logging import get_logger

log = get_logger("research.sast_orchestrator")

_SCAN_TIMEOUT = 600  # 10 min default per scanner run

# ── Tech stack detection ─────────────────────────────────────────────────

_MANIFEST_TO_LANG: list[tuple[str, str, str]] = [
    ("Cargo.toml", "rust", "cargo"),
    ("go.mod", "go", "go"),
    ("pom.xml", "java", "maven"),
    ("build.gradle", "java", "gradle"),
    ("build.gradle.kts", "kotlin", "gradle"),
    ("pyproject.toml", "python", "pyproject"),
    ("setup.py", "python", "setuptools"),
    ("requirements.txt", "python", "pip"),
    ("Pipfile", "python", "pipenv"),
    ("package.json", "javascript", "npm"),
    ("composer.json", "php", "composer"),
    ("Gemfile", "ruby", "bundler"),
    ("mix.exs", "elixir", "mix"),
    ("Package.swift", "swift", "spm"),
    ("*.csproj", "csharp", "dotnet"),
    ("*.sln", "csharp", "dotnet"),
]

_EXT_TO_LANG: dict[str, str] = {
    ".py": "python",
    ".js": "javascript",
    ".ts": "typescript",
    ".jsx": "javascript",
    ".tsx": "typescript",
    ".go": "go",
    ".rs": "rust",
    ".java": "java",
    ".kt": "kotlin",
    ".php": "php",
    ".rb": "ruby",
    ".cs": "csharp",
    ".c": "c",
    ".cpp": "cpp",
    ".cc": "cpp",
    ".h": "c",
    ".swift": "swift",
    ".sol": "solidity",
    ".sh": "shell",
}

_FRAMEWORK_MARKERS: list[tuple[str, str, str]] = [
    ("django", "python", "django"),
    ("flask", "python", "flask"),
    ("fastapi", "python", "fastapi"),
    ("express", "javascript", "express"),
    ("next", "javascript", "nextjs"),
    ("react", "javascript", "react"),
    ("vue", "javascript", "vue"),
    ("angular", "javascript", "angular"),
    ("spring", "java", "spring"),
    ("rails", "ruby", "rails"),
    ("laravel", "php", "laravel"),
]


def _detect_stack(root: str) -> dict[str, Any]:
    """Walk the target directory and detect languages + frameworks."""
    root_path = Path(root)
    if not root_path.is_dir():
        return {"error": "bad_request", "detail": f"{root} is not a directory"}

    languages: dict[str, int] = {}
    frameworks: list[str] = []
    manifests: list[str] = []
    file_count = 0
    max_walk = 50_000

    for dirpath, _dirnames, filenames in os.walk(root_path):
        rel = Path(dirpath).relative_to(root_path)
        if any(
            p.startswith(".") or p in ("node_modules", "vendor", "__pycache__", "venv", ".venv")
            for p in rel.parts
        ):
            continue
        for fname in filenames:
            file_count += 1
            if file_count > max_walk:
                break
            ext = Path(fname).suffix.lower()
            if ext in _EXT_TO_LANG:
                lang = _EXT_TO_LANG[ext]
                languages[lang] = languages.get(lang, 0) + 1
            for manifest, lang, pm in _MANIFEST_TO_LANG:
                if fname == manifest or (manifest.startswith("*") and fname.endswith(manifest[1:])):
                    languages[lang] = languages.get(lang, 0) + 1
                    manifests.append(str(Path(dirpath) / fname))
            if fname in ("package.json", "pyproject.toml", "Gemfile", "composer.json", "pom.xml"):
                try:
                    content = (Path(dirpath) / fname).read_text(errors="replace")[:8192].lower()
                    for keyword, fw_lang, fw_name in _FRAMEWORK_MARKERS:
                        if keyword in content and fw_name not in frameworks:
                            frameworks.append(fw_name)
                except OSError:
                    pass
        if file_count > max_walk:
            break

    ranked = sorted(languages.items(), key=lambda x: x[1], reverse=True)
    return {
        "languages": [{"language": lang, "file_count": c} for lang, c in ranked],
        "primary_language": ranked[0][0] if ranked else "unknown",
        "frameworks": frameworks,
        "manifests": manifests[:20],
        "total_files_scanned": min(file_count, max_walk),
    }


# ── Semgrep rule config selection ────────────────────────────────────────

_SEMGREP_CONFIGS: dict[str, list[str]] = {
    "python": ["p/python", "p/django", "p/flask", "p/owasp-top-ten"],
    "javascript": ["p/javascript", "p/react", "p/nodejs", "p/owasp-top-ten"],
    "typescript": ["p/typescript", "p/react", "p/nodejs", "p/owasp-top-ten"],
    "java": ["p/java", "p/spring", "p/owasp-top-ten"],
    "go": ["p/golang", "p/owasp-top-ten"],
    "ruby": ["p/ruby", "p/owasp-top-ten"],
    "php": ["p/php", "p/owasp-top-ten"],
    "csharp": ["p/csharp", "p/owasp-top-ten"],
    "rust": ["p/rust"],
    "solidity": ["p/smart-contracts"],
}


def _pick_semgrep_config(stack: dict[str, Any], user_config: str) -> list[str]:
    """Select semgrep rule configs based on detected stack."""
    if user_config and user_config != "auto":
        return [user_config]
    lang = stack.get("primary_language", "")
    configs = list(_SEMGREP_CONFIGS.get(lang, ["auto"]))
    configs.append("p/security-audit")
    seen: set[str] = set()
    return [c for c in configs if not (c in seen or seen.add(c))]  # type: ignore[func-returns-value]


# ── Scanner invocation ───────────────────────────────────────────────────


def _which(name: str) -> str | None:
    return shutil.which(name)


def _run_scanner(
    cmd: list[str], *, timeout: int = _SCAN_TIMEOUT, cwd: str | None = None
) -> tuple[int, str, str]:
    """Run a scanner subprocess; return (exit_code, stdout, stderr)."""
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=cwd,
            env={**os.environ, "NO_COLOR": "1"},
        )
        return proc.returncode, proc.stdout, proc.stderr
    except subprocess.TimeoutExpired:
        return -1, "", f"scanner timed out after {timeout}s"
    except FileNotFoundError:
        return -2, "", f"binary not found: {cmd[0]}"


def _count_sarif_results(sarif_path: str) -> dict[str, int]:
    """Quick severity tally from a SARIF file without full parse."""
    counts: dict[str, int] = {"error": 0, "warning": 0, "note": 0, "total": 0}
    try:
        data = json.loads(Path(sarif_path).read_text())
        for run in data.get("runs", []):
            for result in run.get("results", []):
                level = str(result.get("level", "warning")).lower()
                counts[level] = counts.get(level, 0) + 1
                counts["total"] += 1
    except (OSError, json.JSONDecodeError, KeyError):
        pass
    return counts


def _json(data: Any) -> str:
    return json.dumps(data, indent=2, default=str)


# ── @tool wrappers ───────────────────────────────────────────────────────


@tool
def sast_detect_stack(root: str = "/workspace/target") -> str:
    """Detect the target's language and framework stack.

    Walks the target directory, identifies languages by file extension and
    package manifests, and detects frameworks from dependency declarations.
    Returns the primary language, all detected languages with file counts,
    framework names, and manifest file paths. Use this FIRST to decide
    which scanners and rule configs to run.
    """
    return _json(_detect_stack(root))


@tool
def sast_run_semgrep(
    root: str = "/workspace/target",
    config: str = "auto",
    focus_paths: str = "",
    timeout: int = _SCAN_TIMEOUT,
) -> str:
    """Run semgrep with tech-stack-aware rule selection.

    If ``config`` is ``"auto"`` (default), detects the target stack and
    selects appropriate rule packs (e.g. ``p/python``, ``p/django``,
    ``p/owasp-top-ten``). Outputs SARIF to ``/workspace/semgrep.sarif``.
    Returns a severity summary and the SARIF path — call
    ``kg_ingest_sarif`` with that path to lift findings into the KG.
    """
    if not _which("semgrep"):
        return _json(
            {
                "error": "scanner_unavailable",
                "scanner": "semgrep",
                "install": "pip install semgrep   # or: pipx install semgrep",
            }
        )

    stack = _detect_stack(root)
    if "error" in stack:
        return _json(stack)

    configs = _pick_semgrep_config(stack, config)
    sarif_path = "/workspace/semgrep.sarif"
    cmd = ["semgrep", "--sarif", f"--output={sarif_path}", "--no-git-ignore"]
    for c in configs:
        cmd.extend(["--config", c])
    if focus_paths:
        cmd.extend(["--include", focus_paths])
    cmd.append(root)

    code, _stdout, stderr = _run_scanner(cmd, timeout=timeout)
    if code == -2:
        return _json({"error": "scanner_unavailable", "scanner": "semgrep"})
    counts = _count_sarif_results(sarif_path)
    return _json(
        {
            "scanner": "semgrep",
            "configs_used": configs,
            "detected_stack": stack.get("primary_language"),
            "sarif_path": sarif_path,
            "exit_code": code,
            "severity_summary": counts,
            "next_step": f"kg_ingest_sarif('{sarif_path}', scanner_hint='semgrep')"
            if counts["total"] > 0
            else "no findings",
            "stderr_excerpt": stderr[:500] if code not in (0, 1) else "",
        }
    )


@tool
def sast_run_bandit(root: str = "/workspace/target", timeout: int = _SCAN_TIMEOUT) -> str:
    """Run bandit (Python SAST) and return a severity summary.

    Only useful for Python targets. Outputs SARIF to
    ``/workspace/bandit.sarif``. Call ``kg_ingest_sarif`` with that path
    to lift findings into the KG.
    """
    if not _which("bandit"):
        return _json(
            {
                "error": "scanner_unavailable",
                "scanner": "bandit",
                "install": "pip install bandit",
            }
        )
    sarif_path = "/workspace/bandit.sarif"
    cmd = ["bandit", "-r", root, "-f", "sarif", "-o", sarif_path, "-ll"]
    code, _stdout, stderr = _run_scanner(cmd, timeout=timeout)
    if code == -2:
        return _json({"error": "scanner_unavailable", "scanner": "bandit"})
    counts = _count_sarif_results(sarif_path)
    return _json(
        {
            "scanner": "bandit",
            "sarif_path": sarif_path,
            "exit_code": code,
            "severity_summary": counts,
            "next_step": f"kg_ingest_sarif('{sarif_path}', scanner_hint='bandit')"
            if counts["total"] > 0
            else "no findings",
            "stderr_excerpt": stderr[:500] if code not in (0, 1) else "",
        }
    )


@tool
def sast_run_gitleaks(
    root: str = "/workspace/target", scan_git_history: bool = False, timeout: int = _SCAN_TIMEOUT
) -> str:
    """Run gitleaks for secrets detection across all file types.

    By default scans the filesystem (``--no-git``). Set
    ``scan_git_history=True`` to also scan git commit history for
    previously-committed secrets. Outputs SARIF to
    ``/workspace/gitleaks.sarif``.
    """
    if not _which("gitleaks"):
        return _json(
            {
                "error": "scanner_unavailable",
                "scanner": "gitleaks",
                "install": "brew install gitleaks   # or download from github.com/gitleaks/gitleaks/releases",
            }
        )
    sarif_path = "/workspace/gitleaks.sarif"
    cmd = ["gitleaks", "detect", "--report-format=sarif", f"--report-path={sarif_path}"]
    if scan_git_history:
        cmd.extend(["--source", root])
    else:
        cmd.extend(["--no-git", "--source", root])
    code, _stdout, stderr = _run_scanner(cmd, timeout=timeout)
    if code == -2:
        return _json({"error": "scanner_unavailable", "scanner": "gitleaks"})
    counts = _count_sarif_results(sarif_path)
    return _json(
        {
            "scanner": "gitleaks",
            "mode": "git_history" if scan_git_history else "filesystem",
            "sarif_path": sarif_path,
            "exit_code": code,
            "severity_summary": counts,
            "next_step": f"kg_ingest_sarif('{sarif_path}', scanner_hint='gitleaks')"
            if counts["total"] > 0
            else "no findings",
            "stderr_excerpt": stderr[:500] if code not in (0, 1) else "",
        }
    )


@tool
def sast_scan_all(root: str = "/workspace/target") -> str:
    """Detect the tech stack, then run all appropriate SAST scanners.

    Meta-orchestrator: calls ``sast_detect_stack`` then runs semgrep
    (always), bandit (if Python), and gitleaks (if available). Returns
    a unified summary with paths to each SARIF file. The agent should
    then call ``kg_ingest_sarif`` for each non-empty result.
    """
    stack = _detect_stack(root)
    if "error" in stack:
        return _json(stack)

    results: dict[str, Any] = {"detected_stack": stack, "scanners_run": []}

    # Always try semgrep
    if _which("semgrep"):
        configs = _pick_semgrep_config(stack, "auto")
        sarif_path = "/workspace/semgrep.sarif"
        cmd = ["semgrep", "--sarif", f"--output={sarif_path}", "--no-git-ignore"]
        for c in configs:
            cmd.extend(["--config", c])
        cmd.append(root)
        code, _, stderr = _run_scanner(cmd)
        counts = _count_sarif_results(sarif_path)
        results["scanners_run"].append(
            {
                "scanner": "semgrep",
                "sarif_path": sarif_path,
                "severity_summary": counts,
                "exit_code": code,
            }
        )
    else:
        results["scanners_run"].append({"scanner": "semgrep", "status": "unavailable"})

    # Bandit for Python
    if stack.get("primary_language") == "python" and _which("bandit"):
        sarif_path = "/workspace/bandit.sarif"
        cmd = ["bandit", "-r", root, "-f", "sarif", "-o", sarif_path, "-ll"]
        code, _, _ = _run_scanner(cmd)
        counts = _count_sarif_results(sarif_path)
        results["scanners_run"].append(
            {
                "scanner": "bandit",
                "sarif_path": sarif_path,
                "severity_summary": counts,
                "exit_code": code,
            }
        )

    # Gitleaks for secrets
    if _which("gitleaks"):
        sarif_path = "/workspace/gitleaks.sarif"
        cmd = [
            "gitleaks",
            "detect",
            "--no-git",
            "--report-format=sarif",
            f"--report-path={sarif_path}",
            "--source",
            root,
        ]
        code, _, _ = _run_scanner(cmd)
        counts = _count_sarif_results(sarif_path)
        results["scanners_run"].append(
            {
                "scanner": "gitleaks",
                "sarif_path": sarif_path,
                "severity_summary": counts,
                "exit_code": code,
            }
        )
    else:
        results["scanners_run"].append({"scanner": "gitleaks", "status": "unavailable"})

    ingest_steps = [
        f"kg_ingest_sarif('{s['sarif_path']}', scanner_hint='{s['scanner']}')"
        for s in results["scanners_run"]
        if s.get("severity_summary", {}).get("total", 0) > 0
    ]
    results["next_steps"] = ingest_steps or ["no findings from any scanner"]
    return _json(results)


SAST_TOOLS = [
    sast_detect_stack,
    sast_run_semgrep,
    sast_run_bandit,
    sast_run_gitleaks,
    sast_scan_all,
]
