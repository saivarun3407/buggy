"""Unit tests for the IaC scanner."""

from __future__ import annotations

import json
from pathlib import Path

from buggy.tools.research import iac_scanner as iac


def _write_file(tmp_path: Path, name: str, content: str) -> Path:
    f = tmp_path / name
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_text(content)
    return f


class TestClassifyFile:
    def test_terraform(self, tmp_path: Path) -> None:
        f = _write_file(tmp_path, "main.tf", "resource {}")
        assert iac._classify_file(f) == "terraform"

    def test_dockerfile(self, tmp_path: Path) -> None:
        f = _write_file(tmp_path, "Dockerfile", "FROM python:3.11")
        assert iac._classify_file(f) == "docker"

    def test_k8s_deployment(self, tmp_path: Path) -> None:
        f = _write_file(tmp_path, "deployment.yaml", "apiVersion: apps/v1\nkind: Deployment\n")
        assert iac._classify_file(f) == "kubernetes"

    def test_gha_workflow(self, tmp_path: Path) -> None:
        f = _write_file(tmp_path, ".github/workflows/ci.yml", "on: push\njobs:\n")
        assert iac._classify_file(f) == "cicd"

    def test_unknown(self, tmp_path: Path) -> None:
        f = _write_file(tmp_path, "app.py", "pass\n")
        assert iac._classify_file(f) is None


class TestTerraformChecks:
    def test_public_s3(self, tmp_path: Path) -> None:
        f = _write_file(
            tmp_path,
            "storage.tf",
            'resource "aws_s3_bucket" "public" {\n  acl = "public-read"\n}\n',
        )
        findings = iac._scan_iac_file(f, "terraform")
        assert any(fnd["check_id"] == "tf_public_s3" for fnd in findings)

    def test_wildcard_iam(self, tmp_path: Path) -> None:
        f = _write_file(
            tmp_path,
            "iam.tf",
            'resource "aws_iam_policy" "admin" {\n  actions = ["*"]\n}\n',
        )
        findings = iac._scan_iac_file(f, "terraform")
        assert any(fnd["check_id"] == "tf_wildcard_iam" for fnd in findings)

    def test_open_security_group(self, tmp_path: Path) -> None:
        f = _write_file(
            tmp_path,
            "network.tf",
            'ingress {\n  cidr_blocks = ["0.0.0.0/0"]\n}\n',
        )
        findings = iac._scan_iac_file(f, "terraform")
        assert any(fnd["check_id"] == "tf_open_sg" for fnd in findings)

    def test_clean_tf(self, tmp_path: Path) -> None:
        f = _write_file(
            tmp_path,
            "clean.tf",
            'resource "aws_instance" "web" {\n  instance_type = "t3.micro"\n}\n',
        )
        findings = iac._scan_iac_file(f, "terraform")
        assert len(findings) == 0


class TestKubernetesChecks:
    def test_privileged_container(self, tmp_path: Path) -> None:
        f = _write_file(
            tmp_path,
            "pod.yaml",
            "apiVersion: v1\nkind: Pod\nspec:\n  containers:\n  - securityContext:\n      privileged: true\n",
        )
        findings = iac._scan_iac_file(f, "kubernetes")
        assert any(fnd["check_id"] == "k8s_privileged" for fnd in findings)

    def test_host_network(self, tmp_path: Path) -> None:
        f = _write_file(
            tmp_path,
            "pod.yaml",
            "apiVersion: v1\nkind: Pod\nspec:\n  hostNetwork: true\n",
        )
        findings = iac._scan_iac_file(f, "kubernetes")
        assert any(fnd["check_id"] == "k8s_host_network" for fnd in findings)


class TestDockerChecks:
    def test_no_user(self, tmp_path: Path) -> None:
        f = _write_file(
            tmp_path,
            "Dockerfile",
            "FROM python:3.11\nRUN pip install flask\nCMD python app.py\n",
        )
        findings = iac._scan_iac_file(f, "docker")
        assert any(fnd["check_id"] == "docker_run_as_root" for fnd in findings)

    def test_has_user(self, tmp_path: Path) -> None:
        f = _write_file(
            tmp_path,
            "Dockerfile",
            "FROM python:3.11\nRUN pip install flask\nUSER appuser\nCMD python app.py\n",
        )
        findings = iac._scan_iac_file(f, "docker")
        assert not any(fnd["check_id"] == "docker_run_as_root" for fnd in findings)

    def test_secret_env(self, tmp_path: Path) -> None:
        f = _write_file(
            tmp_path,
            "Dockerfile",
            "FROM python:3.11\nENV PASSWORD=supersecret\nUSER app\n",
        )
        findings = iac._scan_iac_file(f, "docker")
        assert any(fnd["check_id"] == "docker_secret_env" for fnd in findings)


class TestCicdChecks:
    def test_pull_request_target(self, tmp_path: Path) -> None:
        f = _write_file(
            tmp_path,
            ".github/workflows/pr.yml",
            "on:\n  pull_request_target:\njobs:\n  build:\n    runs-on: ubuntu-latest\n",
        )
        findings = iac._scan_iac_file(f, "cicd")
        assert any(fnd["check_id"] == "cicd_pull_request_target" for fnd in findings)


class TestIacScanDirectory:
    def test_finds_issues(self, tmp_path: Path) -> None:
        _write_file(tmp_path, "main.tf", 'acl = "public-read"\n')
        _write_file(tmp_path, "Dockerfile", "FROM python:latest\nRUN echo hi\n")
        result = json.loads(iac.iac_scan_directory.invoke({"root": str(tmp_path)}))
        assert result["files_scanned"] == 2
        assert result["total_findings"] >= 2

    def test_bad_root(self) -> None:
        result = json.loads(iac.iac_scan_directory.invoke({"root": "/nonexistent"}))
        assert result["error"] == "bad_request"


class TestIacScanFile:
    def test_single_file(self, tmp_path: Path) -> None:
        f = _write_file(tmp_path, "deploy.tf", 'cidr_blocks = ["0.0.0.0/0"]\n')
        result = json.loads(iac.iac_scan_file.invoke({"file_path": str(f)}))
        assert result["category"] == "terraform"
        assert result["total_findings"] >= 1

    def test_unsupported_file(self, tmp_path: Path) -> None:
        f = _write_file(tmp_path, "app.py", "pass\n")
        result = json.loads(iac.iac_scan_file.invoke({"file_path": str(f)}))
        assert result["error"] == "unsupported_file"

    def test_file_not_found(self) -> None:
        result = json.loads(iac.iac_scan_file.invoke({"file_path": "/nonexistent.tf"}))
        assert result["error"] == "file_not_found"
