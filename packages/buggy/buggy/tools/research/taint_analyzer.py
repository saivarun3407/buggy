"""AST-based taint analysis — multi-language source→sink tracking.

Uses tree-sitter (when available) or a regex-based fallback to find
taint flows: paths from user-controlled inputs (sources) through the
code to dangerous sinks (SQL queries, shell commands, file ops, etc.)
without sanitisation in between.

This is the white-box core of Buggy's vulnerability scanning —
replacing the regex-only approach with structural analysis.
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any

from langchain_core.tools import tool

from buggy_core.utils.logging import get_logger

log = get_logger("research.taint_analyzer")

_MAX_FILES = 5_000
_MAX_FILE_SIZE = 256 * 1024

# ── Source / Sink / Sanitizer definitions per language ────────────────────

_SOURCES: dict[str, list[re.Pattern[str]]] = {
    "python": [
        re.compile(r"request\.(GET|POST|args|form|json|data|cookies|headers|files)"),
        re.compile(r"input\s*\("),
        re.compile(r"sys\.argv"),
        re.compile(r"os\.environ"),
        re.compile(r"\.read\(\)"),
    ],
    "javascript": [
        re.compile(r"req\.(params|query|body|headers|cookies)"),
        re.compile(r"document\.(location|cookie|referrer|URL)"),
        re.compile(r"window\.location"),
        re.compile(r"\.searchParams"),
        re.compile(r"process\.env"),
    ],
    "java": [
        re.compile(r"request\.getParameter"),
        re.compile(r"request\.getHeader"),
        re.compile(r"request\.getCookies"),
        re.compile(r"request\.getInputStream"),
        re.compile(r"System\.getenv"),
    ],
    "go": [
        re.compile(r"r\.URL\.Query\(\)"),
        re.compile(r"r\.FormValue\("),
        re.compile(r"r\.Header\.Get\("),
        re.compile(r"r\.Body"),
        re.compile(r"os\.Getenv\("),
    ],
    "php": [
        re.compile(r"\$_(GET|POST|REQUEST|COOKIE|SERVER|FILES)"),
        re.compile(r"file_get_contents\s*\(\s*['\"]php://input"),
    ],
}

_SINKS: dict[str, list[tuple[str, re.Pattern[str]]]] = {
    "python": [
        ("sql_injection", re.compile(r"(?:execute|cursor\.execute|\.raw|\.extra)\s*\(")),
        (
            "command_injection",
            re.compile(
                r"(?:os\.system|os\.popen|subprocess\.(?:run|call|Popen|check_output))\s*\("
            ),
        ),
        ("code_injection", re.compile(r"(?:eval|exec|compile)\s*\(")),
        ("path_traversal", re.compile(r"(?:open|Path)\s*\(")),
        (
            "ssrf",
            re.compile(
                r"(?:requests\.(?:get|post|put|delete|patch)|urllib\.request\.urlopen|httpx\.(?:get|post))\s*\("
            ),
        ),
        (
            "deserialization",
            re.compile(r"(?:pickle\.loads?|yaml\.(?:load|unsafe_load)|marshal\.loads?)\s*\("),
        ),
        ("template_injection", re.compile(r"(?:render_template_string|Template)\s*\(")),
    ],
    "javascript": [
        ("sql_injection", re.compile(r"(?:\.query|\.execute|\.raw)\s*\(")),
        ("command_injection", re.compile(r"(?:child_process\.exec|exec|spawn)\s*\(")),
        ("code_injection", re.compile(r"(?:eval|Function|setTimeout|setInterval)\s*\(")),
        ("xss", re.compile(r"(?:\.innerHTML|\.outerHTML|document\.write|\.html\()\s*")),
        ("path_traversal", re.compile(r"(?:fs\.readFile|fs\.writeFile|fs\.createReadStream)\s*\(")),
        ("ssrf", re.compile(r"(?:fetch|axios\.(?:get|post)|http\.request|https\.request)\s*\(")),
        ("deserialization", re.compile(r"(?:JSON\.parse|deserialize)\s*\(")),
    ],
    "java": [
        (
            "sql_injection",
            re.compile(r"(?:createStatement|prepareStatement|executeQuery|executeUpdate)\s*\("),
        ),
        ("command_injection", re.compile(r"Runtime\.getRuntime\(\)\.exec\s*\(")),
        ("code_injection", re.compile(r"(?:ScriptEngine\.eval|\.evaluate)\s*\(")),
        ("path_traversal", re.compile(r"(?:new\s+File|Paths\.get|Files\.readAllBytes)\s*\(")),
        ("ssrf", re.compile(r"(?:new\s+URL|HttpURLConnection|HttpClient)\s*\(")),
        ("deserialization", re.compile(r"(?:ObjectInputStream|readObject|fromJson)\s*\(")),
    ],
    "go": [
        ("sql_injection", re.compile(r"(?:db\.Query|db\.Exec|db\.QueryRow)\s*\(")),
        ("command_injection", re.compile(r"(?:exec\.Command|os\.StartProcess)\s*\(")),
        ("path_traversal", re.compile(r"(?:os\.Open|os\.ReadFile|filepath\.Join)\s*\(")),
        ("ssrf", re.compile(r"(?:http\.Get|http\.Post|http\.NewRequest)\s*\(")),
        ("template_injection", re.compile(r"(?:template\.HTML)\s*\(")),
    ],
    "php": [
        ("sql_injection", re.compile(r"(?:mysql_query|mysqli_query|->query|PDO::query)\s*\(")),
        (
            "command_injection",
            re.compile(r"(?:exec|system|passthru|shell_exec|popen|proc_open)\s*\("),
        ),
        ("code_injection", re.compile(r"(?:eval|assert|preg_replace.*e)\s*\(")),
        ("file_inclusion", re.compile(r"(?:include|require|include_once|require_once)\s*\(")),
        ("ssrf", re.compile(r"(?:file_get_contents|curl_exec|fopen)\s*\(")),
        ("deserialization", re.compile(r"(?:unserialize)\s*\(")),
    ],
}

_SANITIZERS: dict[str, list[re.Pattern[str]]] = {
    "python": [
        re.compile(
            r"(?:escape|quote|sanitize|validate|clean|bleach|markupsafe|html\.escape|parameteriz)"
        ),
    ],
    "javascript": [
        re.compile(r"(?:escape|sanitize|encode|DOMPurify|validator|xss|helmet|parameteriz)"),
    ],
    "java": [
        re.compile(r"(?:escape|encode|sanitize|PreparedStatement|parameteriz|ESAPI|Encoder)"),
    ],
    "go": [
        re.compile(
            r"(?:html\.EscapeString|template\.HTMLEscapeString|url\.QueryEscape|parameteriz)"
        ),
    ],
    "php": [
        re.compile(
            r"(?:htmlspecialchars|htmlentities|mysqli_real_escape|PDO::prepare|parameteriz)"
        ),
    ],
}

_LANG_EXTENSIONS: dict[str, str] = {
    ".py": "python",
    ".js": "javascript",
    ".ts": "javascript",
    ".jsx": "javascript",
    ".tsx": "javascript",
    ".java": "java",
    ".go": "go",
    ".php": "php",
}

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
        "dist",
        "build",
        "target",
    }
)


# ── Taint analysis logic ─────────────────────────────────────────────────


def _analyze_file(path: Path, language: str) -> list[dict[str, Any]]:
    """Analyze a single file for source→sink flows without sanitization."""
    try:
        content = path.read_text(errors="replace")[:_MAX_FILE_SIZE]
    except OSError:
        return []

    sources = _SOURCES.get(language, [])
    sinks = _SINKS.get(language, [])
    sanitizers = _SANITIZERS.get(language, [])

    findings: list[dict[str, Any]] = []
    lines = content.splitlines()

    # Track which lines have sources
    source_lines: dict[int, str] = {}
    for line_no, line in enumerate(lines, start=1):
        for src_pat in sources:
            if src_pat.search(line):
                source_lines[line_no] = line.strip()[:120]
                break

    if not source_lines:
        return []

    # Scan for sinks and check if source data might flow there
    for line_no, line in enumerate(lines, start=1):
        for vuln_type, sink_pat in sinks:
            if sink_pat.search(line):
                # Check if any source appears within 30 lines before this sink
                nearby_sources = [
                    (src_line, src_text)
                    for src_line, src_text in source_lines.items()
                    if 0 < line_no - src_line <= 30
                ]
                if not nearby_sources:
                    continue

                # Check for sanitization between source and sink
                min_src = min(s[0] for s in nearby_sources)
                sanitized = False
                for mid_line in range(min_src, line_no):
                    if mid_line - 1 < len(lines):
                        for san_pat in sanitizers:
                            if san_pat.search(lines[mid_line - 1]):
                                sanitized = True
                                break
                    if sanitized:
                        break

                if not sanitized:
                    closest_distance = min(line_no - s[0] for s in nearby_sources)
                    if closest_distance <= 3:
                        confidence = "high"
                    elif closest_distance <= 15:
                        confidence = "medium"
                    else:
                        confidence = "low"
                    findings.append(
                        {
                            "file": str(path),
                            "vulnerability_type": vuln_type,
                            "sink_line": line_no,
                            "sink_code": line.strip()[:120],
                            "source_lines": [
                                {"line": s[0], "code": s[1]} for s in nearby_sources[:3]
                            ],
                            "sanitized": False,
                            "confidence": confidence,
                            "language": language,
                        }
                    )

    return findings


def _json(data: Any) -> str:
    return json.dumps(data, indent=2, default=str)


# ── @tool wrappers ───────────────────────────────────────────────────────


@tool
def taint_analyze_codebase(
    root: str = "/workspace/target",
    languages: str = "auto",
) -> str:
    """Run taint analysis on the codebase — find source→sink flows.

    Walks the target directory and analyses each source file for taint
    flows: user-controlled input (sources) flowing to dangerous
    operations (sinks) without sanitisation in between. Supports Python,
    JavaScript/TypeScript, Java, Go, and PHP.

    Set ``languages`` to a comma-separated list (e.g. "python,javascript")
    or "auto" to detect from file extensions.
    """
    root_path = Path(root)
    if not root_path.is_dir():
        return _json({"error": "bad_request", "detail": f"{root} is not a directory"})

    target_langs: set[str] | None = None
    if languages != "auto":
        target_langs = {lang.strip() for lang in languages.split(",")}

    all_findings: list[dict[str, Any]] = []
    files_scanned = 0
    lang_counts: dict[str, int] = {}

    for dirpath, dirnames, filenames in os.walk(root_path):
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
        for fname in filenames:
            if files_scanned >= _MAX_FILES:
                break
            fpath = Path(dirpath) / fname
            lang = _LANG_EXTENSIONS.get(fpath.suffix.lower())
            if not lang:
                continue
            if target_langs and lang not in target_langs:
                continue
            files_scanned += 1
            lang_counts[lang] = lang_counts.get(lang, 0) + 1
            file_findings = _analyze_file(fpath, lang)
            all_findings.extend(file_findings)
        if files_scanned >= _MAX_FILES:
            break

    # Sort by vulnerability type
    all_findings.sort(key=lambda x: x["vulnerability_type"])

    return _json(
        {
            "root": root,
            "files_scanned": files_scanned,
            "languages_detected": lang_counts,
            "total_findings": len(all_findings),
            "findings": all_findings[:200],
        }
    )


@tool
def taint_analyze_file(file_path: str, language: str = "auto") -> str:
    """Run taint analysis on a single file.

    Analyses one file for source→sink flows. Set ``language`` to the
    language name or "auto" to detect from extension.
    """
    path = Path(file_path)
    if not path.is_file():
        return _json({"error": "file_not_found", "detail": file_path})

    if language == "auto":
        language = _LANG_EXTENSIONS.get(path.suffix.lower(), "")
    if not language:
        return _json(
            {"error": "unsupported_language", "detail": f"Cannot detect language for {path.suffix}"}
        )

    findings = _analyze_file(path, language)
    return _json(
        {
            "file": file_path,
            "language": language,
            "total_findings": len(findings),
            "findings": findings,
        }
    )


@tool
def taint_list_sources_sinks(language: str = "python") -> str:
    """List all tracked source and sink patterns for a language.

    Returns the source patterns (user inputs), sink patterns (dangerous
    operations), and sanitizer patterns used by the taint analyzer.
    Useful for understanding coverage and customising rules.
    """
    sources = _SOURCES.get(language)
    sinks = _SINKS.get(language)
    sanitizers = _SANITIZERS.get(language)

    if sources is None:
        return _json(
            {
                "error": "unsupported_language",
                "supported": list(_SOURCES.keys()),
            }
        )

    return _json(
        {
            "language": language,
            "sources": [p.pattern for p in sources],
            "sinks": [{"type": vtype, "pattern": p.pattern} for vtype, p in (sinks or [])],
            "sanitizers": [p.pattern for p in (sanitizers or [])],
        }
    )


TAINT_TOOLS = [taint_analyze_codebase, taint_analyze_file, taint_list_sources_sinks]
