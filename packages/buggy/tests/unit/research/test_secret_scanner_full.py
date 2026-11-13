"""Unit tests for full-codebase secret scanning tools.

No live filesystem or git operations outside tmp_path — all paths
are constructed in temporary directories.
"""

from __future__ import annotations

import json
from pathlib import Path

from buggy.tools.research import secret_scanner_full as ssf


def _make_tree(tmp_path: Path, files: dict[str, str]) -> str:
    for rel, content in files.items():
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content)
    return str(tmp_path)


class TestScanFile:
    def test_finds_aws_key(self, tmp_path: Path) -> None:
        f = tmp_path / "config.py"
        f.write_text("AWS_KEY = 'AKIAIOSFODNN7EXAMPLE'\n")
        findings = ssf._scan_file(f, ssf._SECRET_PATTERNS)
        assert len(findings) >= 1
        assert any(fnd["pattern"] == "aws_access_key" for fnd in findings)
        # Ensure the actual secret is redacted
        for fnd in findings:
            assert "AKIAIOSFODNN7EXAMPLE" not in fnd["preview"]

    def test_finds_private_key(self, tmp_path: Path) -> None:
        f = tmp_path / "key.pem"
        f.write_text("-----BEGIN RSA PRIVATE KEY-----\nMIIE...\n-----END RSA PRIVATE KEY-----\n")
        findings = ssf._scan_file(f, ssf._SECRET_PATTERNS)
        assert any(fnd["pattern"] == "private_key" for fnd in findings)

    def test_no_false_positive_on_clean(self, tmp_path: Path) -> None:
        f = tmp_path / "clean.py"
        f.write_text("# This is a clean file\nprint('hello')\n")
        findings = ssf._scan_file(f, ssf._SECRET_PATTERNS)
        assert len(findings) == 0


class TestWalkAndScan:
    def test_skips_node_modules(self, tmp_path: Path) -> None:
        root = _make_tree(
            tmp_path,
            {
                "node_modules/pkg/secret.js": "const key = 'AKIAIOSFODNN7EXAMPLE';\n",
                "src/app.py": "# clean\n",
            },
        )
        findings = ssf._walk_and_scan(root, ssf._SECRET_PATTERNS)
        # node_modules should be skipped
        assert all("node_modules" not in f["file"] for f in findings)

    def test_skips_binary_extensions(self, tmp_path: Path) -> None:
        root = _make_tree(
            tmp_path,
            {
                "image.png": "AKIAIOSFODNN7EXAMPLE",
                "src/config.py": "KEY = 'AKIAIOSFODNN7EXAMPLE'\n",
            },
        )
        findings = ssf._walk_and_scan(root, ssf._SECRET_PATTERNS)
        assert all(".png" not in f["file"] for f in findings)


class TestScanSecretsFilesystem:
    def test_finds_secrets(self, tmp_path: Path) -> None:
        root = _make_tree(
            tmp_path,
            {
                "config.py": "TOKEN = 'ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh'\n",
            },
        )
        result = json.loads(ssf.scan_secrets_filesystem.invoke({"root": root}))
        assert result["total_findings"] >= 1


class TestScanSecretsCicd:
    def test_finds_dockerfile_secrets(self, tmp_path: Path) -> None:
        root = _make_tree(
            tmp_path,
            {
                "Dockerfile": "FROM python:3.11\nARG password=mysecret123\nRUN echo $password\n",
            },
        )
        result = json.loads(ssf.scan_secrets_cicd.invoke({"root": root}))
        assert result["total_findings"] >= 1

    def test_finds_env_file_secrets(self, tmp_path: Path) -> None:
        root = _make_tree(
            tmp_path,
            {
                ".env": "SECRET=my-api-key-value-here\nDATABASE_URL=postgres://user:pass@host/db\n",
            },
        )
        result = json.loads(ssf.scan_secrets_cicd.invoke({"root": root}))
        assert result["total_findings"] >= 1

    def test_no_cicd_files(self, tmp_path: Path) -> None:
        root = _make_tree(tmp_path, {"app.py": "pass\n"})
        result = json.loads(ssf.scan_secrets_cicd.invoke({"root": root}))
        assert result["total_findings"] == 0


class TestScanSecretsGitHistory:
    def test_not_git_repo(self, tmp_path: Path) -> None:
        root = _make_tree(tmp_path, {"app.py": "pass\n"})
        result = json.loads(ssf.scan_secrets_git_history.invoke({"root": root}))
        assert result["error"] == "not_a_git_repo"
