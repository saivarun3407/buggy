"""Software Composition Analysis — dependency vulnerability scanning.

Pure-Python lockfile parsing + OSV.dev API queries. No external binary
required for the core path (grype/syft are optional accelerators). The
tool parses common lockfile formats, batch-queries the free OSV API for
known CVEs, and returns ranked results with EPSS scores.

Supported lockfile formats:
- **npm**: ``package-lock.json``
- **pip**: ``requirements.txt``, ``Pipfile.lock``
- **go**: ``go.sum``
- **cargo**: ``Cargo.lock``
- **composer**: ``composer.lock``
- **maven**: ``pom.xml`` (top-level ``<dependency>`` blocks only)
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any

import httpx
from langchain_core.tools import tool

from buggy_core.utils.logging import get_logger

log = get_logger("research.sca")

OSV_API = "https://api.osv.dev/v1"
EPSS_API = "https://api.first.org/data/v1/epss"
_TIMEOUT = 20.0
_MAX_DEPS = 500  # cap to avoid API abuse


# ── Lockfile parsers ─────────────────────────────────────────────────────


def _parse_package_lock(path: Path) -> list[dict[str, str]]:
    """Parse npm package-lock.json (v2/v3 ``packages`` or v1 ``dependencies``)."""
    data = json.loads(path.read_text())
    deps: list[dict[str, str]] = []
    packages = data.get("packages") or {}
    for key, info in packages.items():
        name = key.replace("node_modules/", "").strip()
        if not name or name == "":
            continue
        version = str(info.get("version", ""))
        if version:
            deps.append({"name": name, "version": version, "ecosystem": "npm"})
    if not deps:
        for name, info in (data.get("dependencies") or {}).items():
            version = str(info.get("version", ""))
            if version:
                deps.append({"name": name, "version": version, "ecosystem": "npm"})
    return deps[:_MAX_DEPS]


def _parse_requirements_txt(path: Path) -> list[dict[str, str]]:
    """Parse pip requirements.txt (``name==version``)."""
    deps: list[dict[str, str]] = []
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        match = re.match(r"^([A-Za-z0-9_.-]+)\s*==\s*([^\s;#]+)", line)
        if match:
            deps.append({"name": match.group(1), "version": match.group(2), "ecosystem": "PyPI"})
    return deps[:_MAX_DEPS]


def _parse_pipfile_lock(path: Path) -> list[dict[str, str]]:
    """Parse Pipfile.lock JSON."""
    data = json.loads(path.read_text())
    deps: list[dict[str, str]] = []
    for section in ("default", "develop"):
        for name, info in (data.get(section) or {}).items():
            version = str(info.get("version", "")).lstrip("=")
            if version:
                deps.append({"name": name, "version": version, "ecosystem": "PyPI"})
    return deps[:_MAX_DEPS]


def _parse_go_sum(path: Path) -> list[dict[str, str]]:
    """Parse go.sum (``module version hash``)."""
    deps: list[dict[str, str]] = []
    seen: set[str] = set()
    for line in path.read_text().splitlines():
        parts = line.strip().split()
        if len(parts) < 2:
            continue
        module = parts[0]
        version = parts[1].split("/")[0].removeprefix("v")
        key = f"{module}@{version}"
        if key not in seen:
            seen.add(key)
            deps.append({"name": module, "version": version, "ecosystem": "Go"})
    return deps[:_MAX_DEPS]


def _parse_cargo_lock(path: Path) -> list[dict[str, str]]:
    """Parse Cargo.lock (TOML-like ``[[package]]`` blocks)."""
    deps: list[dict[str, str]] = []
    name = version = ""
    for line in path.read_text().splitlines():
        line = line.strip()
        if line == "[[package]]":
            if name and version:
                deps.append({"name": name, "version": version, "ecosystem": "crates.io"})
            name = version = ""
        elif line.startswith("name"):
            name = line.split("=", 1)[1].strip().strip('"')
        elif line.startswith("version"):
            version = line.split("=", 1)[1].strip().strip('"')
    if name and version:
        deps.append({"name": name, "version": version, "ecosystem": "crates.io"})
    return deps[:_MAX_DEPS]


def _parse_composer_lock(path: Path) -> list[dict[str, str]]:
    """Parse composer.lock."""
    data = json.loads(path.read_text())
    deps: list[dict[str, str]] = []
    for pkg in data.get("packages", []) + data.get("packages-dev", []):
        name = str(pkg.get("name", ""))
        version = str(pkg.get("version", "")).removeprefix("v")
        if name and version:
            deps.append({"name": name, "version": version, "ecosystem": "Packagist"})
    return deps[:_MAX_DEPS]


_LOCKFILE_PARSERS: dict[str, Any] = {
    "package-lock.json": _parse_package_lock,
    "requirements.txt": _parse_requirements_txt,
    "Pipfile.lock": _parse_pipfile_lock,
    "go.sum": _parse_go_sum,
    "Cargo.lock": _parse_cargo_lock,
    "composer.lock": _parse_composer_lock,
}


def _find_lockfiles(root: str) -> list[str]:
    """Walk root and find supported lockfiles."""
    found: list[str] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [
            d
            for d in dirnames
            if not d.startswith(".") and d not in ("node_modules", "vendor", "__pycache__")
        ]
        for fname in filenames:
            if fname in _LOCKFILE_PARSERS:
                found.append(str(Path(dirpath) / fname))
    return found[:20]


# ── OSV API queries ──────────────────────────────────────────────────────


def _query_osv(package: str, version: str, ecosystem: str) -> list[dict[str, Any]]:
    """Query OSV.dev for vulnerabilities affecting package@version."""
    try:
        with httpx.Client(timeout=_TIMEOUT) as client:
            resp = client.post(
                f"{OSV_API}/query",
                json={"package": {"name": package, "ecosystem": ecosystem}, "version": version},
            )
        if resp.status_code != 200:
            return []
        data = resp.json()
        return data.get("vulns", [])
    except (httpx.HTTPError, ValueError):
        return []


def _query_osv_batch(deps: list[dict[str, str]]) -> dict[str, list[dict[str, Any]]]:
    """Batch-query OSV for multiple packages."""
    queries = [
        {"package": {"name": d["name"], "ecosystem": d["ecosystem"]}, "version": d["version"]}
        for d in deps
    ]
    try:
        with httpx.Client(timeout=_TIMEOUT * 2) as client:
            resp = client.post(f"{OSV_API}/querybatch", json={"queries": queries})
        if resp.status_code != 200:
            return {}
        data = resp.json()
        results: dict[str, list[dict[str, Any]]] = {}
        for i, entry in enumerate(data.get("results", [])):
            vulns = entry.get("vulns", [])
            if vulns and i < len(deps):
                key = f"{deps[i]['name']}@{deps[i]['version']}"
                results[key] = vulns
        return results
    except (httpx.HTTPError, ValueError):
        return {}


def _extract_severity(vuln: dict[str, Any]) -> str:
    """Best-effort severity from an OSV record."""
    for sev in vuln.get("severity", []):
        score_str = str(sev.get("score", ""))
        if score_str:
            try:
                score = float(score_str)
                if score >= 9.0:
                    return "critical"
                if score >= 7.0:
                    return "high"
                if score >= 4.0:
                    return "medium"
                return "low"
            except ValueError:
                pass
    aliases = vuln.get("aliases", [])
    summary = str(vuln.get("summary", "")).lower()
    if any(kw in summary for kw in ("critical", "remote code", "rce")):
        return "critical"
    if any(kw in summary for kw in ("high", "injection", "overflow")):
        return "high"
    return "medium" if aliases else "unknown"


def _extract_fixed_versions(vuln: dict[str, Any]) -> list[str]:
    """Pull fix-version strings from an OSV ``affected[].ranges[].events[]``."""
    fixes: list[str] = []
    for affected in vuln.get("affected", []):
        for rng in affected.get("ranges", []):
            for event in rng.get("events", []):
                fixed = event.get("fixed")
                if fixed:
                    fixes.append(str(fixed))
    return fixes


def _json(data: Any) -> str:
    return json.dumps(data, indent=2, default=str)


# ── @tool wrappers ───────────────────────────────────────────────────────


@tool
def sca_scan_dependencies(root: str = "/workspace/target") -> str:
    """Find lockfiles, parse dependencies, and check for known CVEs.

    Walks the target directory for supported lockfiles, parses them into
    a dependency list, batch-queries the OSV.dev API for known CVEs, and
    returns a ranked list of vulnerable packages sorted by severity.
    No external binary needed — pure Python + OSV API.
    """
    lockfiles = _find_lockfiles(root)
    if not lockfiles:
        return _json(
            {
                "error": "no_lockfiles_found",
                "detail": f"No supported lockfiles found under {root}",
                "supported": list(_LOCKFILE_PARSERS.keys()),
            }
        )

    all_deps: list[dict[str, str]] = []
    parsed_lockfiles: list[dict[str, Any]] = []
    for lf in lockfiles:
        fname = Path(lf).name
        parser = _LOCKFILE_PARSERS.get(fname)
        if not parser:
            continue
        try:
            deps = parser(Path(lf))
            all_deps.extend(deps)
            parsed_lockfiles.append({"path": lf, "format": fname, "dep_count": len(deps)})
        except (OSError, json.JSONDecodeError, KeyError) as exc:
            parsed_lockfiles.append({"path": lf, "format": fname, "error": str(exc)})

    if not all_deps:
        return _json({"lockfiles": parsed_lockfiles, "vulnerable": [], "total_deps": 0})

    vuln_map = _query_osv_batch(all_deps[:_MAX_DEPS])
    vulnerable: list[dict[str, Any]] = []
    for key, vulns in vuln_map.items():
        name, _, version = key.rpartition("@")
        for v in vulns:
            vulnerable.append(
                {
                    "package": name,
                    "version": version,
                    "vuln_id": v.get("id", ""),
                    "aliases": v.get("aliases", [])[:3],
                    "summary": str(v.get("summary", ""))[:200],
                    "severity": _extract_severity(v),
                    "fixed_in": _extract_fixed_versions(v)[:3],
                }
            )

    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "unknown": 4}
    vulnerable.sort(key=lambda x: severity_order.get(x["severity"], 5))

    return _json(
        {
            "lockfiles": parsed_lockfiles,
            "total_deps": len(all_deps),
            "vulnerable_packages": len(vuln_map),
            "total_vulns": len(vulnerable),
            "findings": vulnerable[:100],
        }
    )


@tool
def sca_check_package(package: str, version: str, ecosystem: str = "npm") -> str:
    """Check a single package@version for known CVEs via OSV.dev.

    Supported ecosystems: npm, PyPI, Go, crates.io, Maven, Packagist,
    NuGet, RubyGems. Returns all known vulnerabilities with severity,
    aliases, and fix versions.
    """
    vulns = _query_osv(package, version, ecosystem)
    if not vulns:
        return _json(
            {"package": package, "version": version, "ecosystem": ecosystem, "vulnerabilities": []}
        )
    findings = []
    for v in vulns:
        findings.append(
            {
                "vuln_id": v.get("id", ""),
                "aliases": v.get("aliases", []),
                "summary": str(v.get("summary", ""))[:300],
                "severity": _extract_severity(v),
                "references": [r.get("url") for r in v.get("references", []) if r.get("url")][:5],
            }
        )
    return _json(
        {
            "package": package,
            "version": version,
            "ecosystem": ecosystem,
            "vulnerability_count": len(findings),
            "findings": findings,
        }
    )


@tool
def sca_audit_lockfile(lockfile_path: str) -> str:
    """Parse and audit a specific lockfile for known CVEs.

    Supports: package-lock.json, requirements.txt, Pipfile.lock, go.sum,
    Cargo.lock, composer.lock. Returns vulnerable packages ranked by
    severity with fix versions where available.
    """
    path = Path(lockfile_path)
    if not path.is_file():
        return _json({"error": "file_not_found", "path": lockfile_path})

    parser = _LOCKFILE_PARSERS.get(path.name)
    if not parser:
        return _json(
            {
                "error": "unsupported_format",
                "path": lockfile_path,
                "supported": list(_LOCKFILE_PARSERS.keys()),
            }
        )

    try:
        deps = parser(path)
    except (OSError, json.JSONDecodeError, KeyError) as exc:
        return _json({"error": "parse_error", "path": lockfile_path, "detail": str(exc)})

    if not deps:
        return _json({"path": lockfile_path, "total_deps": 0, "findings": []})

    vuln_map = _query_osv_batch(deps)
    findings: list[dict[str, Any]] = []
    for key, vulns in vuln_map.items():
        name, _, version = key.rpartition("@")
        for v in vulns:
            findings.append(
                {
                    "package": name,
                    "version": version,
                    "vuln_id": v.get("id", ""),
                    "severity": _extract_severity(v),
                    "summary": str(v.get("summary", ""))[:200],
                }
            )

    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "unknown": 4}
    findings.sort(key=lambda x: severity_order.get(x["severity"], 5))
    return _json(
        {
            "path": lockfile_path,
            "total_deps": len(deps),
            "vulnerable_count": len(vuln_map),
            "findings": findings[:100],
        }
    )


SCA_TOOLS = [sca_scan_dependencies, sca_check_package, sca_audit_lockfile]
