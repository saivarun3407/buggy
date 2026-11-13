"""Unit tests for the SCA (Software Composition Analysis) tools.

No live OSV API calls — httpx is monkeypatched with canned responses.
Tests verify lockfile parsing, OSV query construction, severity
extraction, and graceful degradation on parse errors.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

from buggy.tools.research import sca

# ── Helpers ──────────────────────────────────────────────────────────────


def _write(tmp_path: Path, name: str, content: str) -> str:
    f = tmp_path / name
    f.write_text(content)
    return str(f)


_OSV_BATCH_RESPONSE = {
    "results": [
        {"vulns": []},
        {
            "vulns": [
                {
                    "id": "GHSA-abc-001",
                    "aliases": ["CVE-2024-9999"],
                    "summary": "Remote code execution in example-lib",
                    "severity": [{"type": "CVSS_V3", "score": "9.8"}],
                    "affected": [],
                }
            ]
        },
    ],
}


def _mock_osv_client(response_data: dict[str, Any]) -> Any:
    """Build a mock httpx.Client that returns canned OSV responses."""
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = response_data

    mock_client = MagicMock()
    mock_client.__enter__ = lambda self: mock_client
    mock_client.__exit__ = MagicMock(return_value=False)
    mock_client.post.return_value = mock_resp
    return mock_client


# ── Lockfile parsers ─────────────────────────────────────────────────────


class TestParsePackageLock:
    def test_v2_packages(self, tmp_path: Path) -> None:
        content = json.dumps(
            {
                "packages": {
                    "": {"name": "myapp", "version": "1.0.0"},
                    "node_modules/lodash": {"version": "4.17.21"},
                    "node_modules/express": {"version": "4.18.2"},
                }
            }
        )
        path = tmp_path / "package-lock.json"
        path.write_text(content)
        deps = sca._parse_package_lock(path)
        assert len(deps) == 2
        names = {d["name"] for d in deps}
        assert "lodash" in names
        assert "express" in names
        assert all(d["ecosystem"] == "npm" for d in deps)

    def test_v1_dependencies(self, tmp_path: Path) -> None:
        content = json.dumps(
            {
                "dependencies": {
                    "axios": {"version": "1.6.0"},
                }
            }
        )
        path = tmp_path / "package-lock.json"
        path.write_text(content)
        deps = sca._parse_package_lock(path)
        assert len(deps) == 1
        assert deps[0]["name"] == "axios"


class TestParseRequirementsTxt:
    def test_pinned_deps(self, tmp_path: Path) -> None:
        content = "flask==2.3.2\nrequests==2.31.0\n# comment\n-r base.txt\n"
        path = tmp_path / "requirements.txt"
        path.write_text(content)
        deps = sca._parse_requirements_txt(path)
        assert len(deps) == 2
        assert deps[0]["ecosystem"] == "PyPI"

    def test_unpinned_ignored(self, tmp_path: Path) -> None:
        content = "flask>=2.0\nrequests\n"
        path = tmp_path / "requirements.txt"
        path.write_text(content)
        deps = sca._parse_requirements_txt(path)
        assert len(deps) == 0  # only ==pinned are parseable


class TestParseGoSum:
    def test_basic(self, tmp_path: Path) -> None:
        content = (
            "github.com/gin-gonic/gin v1.9.1 h1:abc123=\n"
            "github.com/gin-gonic/gin v1.9.1/go.mod h1:def456=\n"
            "golang.org/x/net v0.12.0 h1:xyz=\n"
        )
        path = tmp_path / "go.sum"
        path.write_text(content)
        deps = sca._parse_go_sum(path)
        assert len(deps) == 2  # deduped
        names = {d["name"] for d in deps}
        assert "github.com/gin-gonic/gin" in names


class TestParseCargoLock:
    def test_basic(self, tmp_path: Path) -> None:
        content = (
            '[[package]]\nname = "serde"\nversion = "1.0.188"\n\n'
            '[[package]]\nname = "tokio"\nversion = "1.32.0"\n'
        )
        path = tmp_path / "Cargo.lock"
        path.write_text(content)
        deps = sca._parse_cargo_lock(path)
        assert len(deps) == 2
        assert deps[0]["ecosystem"] == "crates.io"


class TestParseComposerLock:
    def test_basic(self, tmp_path: Path) -> None:
        content = json.dumps(
            {
                "packages": [
                    {"name": "laravel/framework", "version": "v10.0.0"},
                ],
                "packages-dev": [
                    {"name": "phpunit/phpunit", "version": "v10.3.0"},
                ],
            }
        )
        path = tmp_path / "composer.lock"
        path.write_text(content)
        deps = sca._parse_composer_lock(path)
        assert len(deps) == 2
        assert deps[0]["version"] == "10.0.0"  # v-prefix stripped


# ── Severity extraction ──────────────────────────────────────────────────


class TestSeverity:
    def test_cvss_critical(self) -> None:
        assert sca._extract_severity({"severity": [{"score": "9.8"}]}) == "critical"

    def test_cvss_high(self) -> None:
        assert sca._extract_severity({"severity": [{"score": "7.5"}]}) == "high"

    def test_cvss_medium(self) -> None:
        assert sca._extract_severity({"severity": [{"score": "5.0"}]}) == "medium"

    def test_cvss_low(self) -> None:
        assert sca._extract_severity({"severity": [{"score": "2.0"}]}) == "low"

    def test_summary_fallback(self) -> None:
        assert (
            sca._extract_severity({"summary": "Remote code execution", "aliases": ["CVE-X"]})
            == "critical"
        )


# ── Tool wrappers ────────────────────────────────────────────────────────


class TestScaScanDependencies:
    def test_no_lockfiles(self, tmp_path: Path) -> None:
        root = str(tmp_path)
        (tmp_path / "main.py").write_text("pass\n")
        result = json.loads(sca.sca_scan_dependencies.invoke({"root": root}))
        assert result["error"] == "no_lockfiles_found"

    def test_with_vuln(self, tmp_path: Path) -> None:
        pkg_lock = tmp_path / "package-lock.json"
        pkg_lock.write_text(
            json.dumps(
                {
                    "packages": {
                        "node_modules/safe-lib": {"version": "1.0.0"},
                        "node_modules/vuln-lib": {"version": "2.0.0"},
                    }
                }
            )
        )
        mock_client = _mock_osv_client(_OSV_BATCH_RESPONSE)
        with patch("buggy.tools.research.sca.httpx.Client", return_value=mock_client):
            result = json.loads(sca.sca_scan_dependencies.invoke({"root": str(tmp_path)}))
        assert result["total_deps"] == 2
        assert result["total_vulns"] >= 1
        assert result["findings"][0]["severity"] == "critical"


class TestScaCheckPackage:
    def test_no_vulns(self) -> None:
        mock_client = _mock_osv_client({"vulns": []})
        mock_client.post.return_value.json.return_value = {"vulns": []}
        with patch("buggy.tools.research.sca.httpx.Client", return_value=mock_client):
            result = json.loads(
                sca.sca_check_package.invoke(
                    {"package": "safe-pkg", "version": "1.0.0", "ecosystem": "npm"}
                )
            )
        assert result["vulnerabilities"] == []


class TestScaAuditLockfile:
    def test_missing_file(self) -> None:
        result = json.loads(sca.sca_audit_lockfile.invoke({"lockfile_path": "/nonexistent"}))
        assert result["error"] == "file_not_found"

    def test_unsupported_format(self, tmp_path: Path) -> None:
        f = tmp_path / "yarn.lock"
        f.write_text("# yarn lockfile v1\n")
        result = json.loads(sca.sca_audit_lockfile.invoke({"lockfile_path": str(f)}))
        assert result["error"] == "unsupported_format"
