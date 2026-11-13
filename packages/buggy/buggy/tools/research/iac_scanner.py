"""Infrastructure-as-Code (IaC) scanner — Terraform, K8s, Docker, CI/CD.

Scans IaC configuration files for security misconfigurations:
- **Terraform**: overly permissive IAM, public S3 buckets, unencrypted
  resources, security group rules allowing 0.0.0.0/0
- **Kubernetes**: privileged containers, host networking, missing
  resource limits, default namespace usage
- **Docker**: running as root, latest tag, exposed secrets, missing
  health checks
- **CI/CD**: insecure pipeline configs

No external binary required — pure regex/JSON/YAML analysis.
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any

from langchain_core.tools import tool

from buggy_core.utils.logging import get_logger

log = get_logger("research.iac_scanner")

_SKIP_DIRS = frozenset(
    {
        ".git",
        "node_modules",
        "__pycache__",
        ".venv",
        "venv",
        "dist",
        "build",
    }
)


# ── Terraform checks ────────────────────────────────────────────────────

_TF_CHECKS: list[tuple[str, str, re.Pattern[str]]] = [
    (
        "tf_public_s3",
        "S3 bucket ACL allows public access",
        re.compile(r'acl\s*=\s*"(public-read|public-read-write|authenticated-read)"'),
    ),
    (
        "tf_wildcard_iam",
        'IAM policy uses wildcard ("*") action or resource',
        re.compile(r"""(?:actions?|resources?)\s*=\s*\[\s*"\*"\s*\]"""),
    ),
    (
        "tf_open_sg",
        "Security group allows ingress from 0.0.0.0/0",
        re.compile(r'cidr_blocks\s*=\s*\[\s*"0\.0\.0\.0/0"\s*\]'),
    ),
    (
        "tf_no_encryption",
        "Resource missing encryption configuration",
        re.compile(r"encrypted\s*=\s*false"),
    ),
    (
        "tf_hardcoded_secret",
        "Hardcoded secret in Terraform variable default",
        re.compile(r"""default\s*=\s*"(?:password|secret|token|key)[^"]*\w{8,}""", re.IGNORECASE),
    ),
    (
        "tf_public_subnet",
        "Subnet configured with public IP mapping",
        re.compile(r"map_public_ip_on_launch\s*=\s*true"),
    ),
    (
        "tf_no_logging",
        "Resource missing logging/monitoring configuration",
        re.compile(r"logging\s*\{\s*\}|enable_logging\s*=\s*false"),
    ),
]


# ── Kubernetes checks ────────────────────────────────────────────────────

_K8S_CHECKS: list[tuple[str, str, re.Pattern[str]]] = [
    (
        "k8s_privileged",
        "Container running in privileged mode",
        re.compile(r"privileged:\s*true"),
    ),
    (
        "k8s_host_network",
        "Pod using host networking",
        re.compile(r"hostNetwork:\s*true"),
    ),
    (
        "k8s_host_pid",
        "Pod sharing host PID namespace",
        re.compile(r"hostPID:\s*true"),
    ),
    (
        "k8s_run_as_root",
        "Container running as root",
        re.compile(r"runAsUser:\s*0\b"),
    ),
    (
        "k8s_no_readonly_root",
        "Container filesystem not read-only",
        re.compile(r"readOnlyRootFilesystem:\s*false"),
    ),
    (
        "k8s_cap_sys_admin",
        "Container has SYS_ADMIN capability",
        re.compile(r"SYS_ADMIN"),
    ),
    (
        "k8s_default_namespace",
        "Resource deployed in default namespace",
        re.compile(r"namespace:\s*default\b"),
    ),
    (
        "k8s_latest_tag",
        "Container image using 'latest' tag",
        re.compile(r"image:\s*\S+:latest\b"),
    ),
    (
        "k8s_no_resource_limits",
        "Container missing resource limits",
        re.compile(r"resources:\s*\{\s*\}"),
    ),
]


# ── Dockerfile checks ───────────────────────────────────────────────────

_DOCKER_CHECKS: list[tuple[str, str, re.Pattern[str]]] = [
    (
        "docker_run_as_root",
        "Dockerfile does not specify a non-root USER",
        re.compile(r"^FROM\s+", re.MULTILINE),  # checked separately for USER absence
    ),
    (
        "docker_latest_tag",
        "Base image uses 'latest' tag or no tag",
        re.compile(r"^FROM\s+\S+?:latest(?:\s|$)|^FROM\s+(?!\S*:)\S+(?:\s|$)", re.MULTILINE),
    ),
    (
        "docker_add_instead_copy",
        "ADD used instead of COPY (may fetch remote URLs or auto-extract)",
        re.compile(r"^ADD\s+", re.MULTILINE),
    ),
    (
        "docker_secret_env",
        "Secret passed via ENV instruction",
        re.compile(
            r"^ENV\s+(?:PASSWORD|SECRET|TOKEN|API_KEY|PRIVATE_KEY)\s*=",
            re.MULTILINE | re.IGNORECASE,
        ),
    ),
    (
        "docker_secret_arg",
        "Secret passed via ARG with default",
        re.compile(
            r"^ARG\s+(?:PASSWORD|SECRET|TOKEN|API_KEY)\s*=\S+", re.MULTILINE | re.IGNORECASE
        ),
    ),
    (
        "docker_expose_sensitive",
        "Exposing potentially sensitive port",
        re.compile(r"^EXPOSE\s+(?:22|3306|5432|6379|27017)\b", re.MULTILINE),
    ),
]


# ── CI/CD checks ─────────────────────────────────────────────────────────

_CICD_CHECKS: list[tuple[str, str, re.Pattern[str]]] = [
    (
        "cicd_pull_request_target",
        "GitHub Actions uses pull_request_target (potential code injection)",
        re.compile(r"pull_request_target"),
    ),
    (
        "cicd_script_injection",
        "User-controlled input in run step (potential injection)",
        re.compile(r"run:.*\$\{\{\s*github\.event\.(?:issue|pull_request|comment)"),
    ),
    (
        "cicd_wildcard_permissions",
        "GitHub Actions workflow has write-all permissions",
        re.compile(r"permissions:\s*write-all"),
    ),
    (
        "cicd_untrusted_action",
        "Using action pinned to branch/tag instead of SHA",
        re.compile(r"uses:\s+\S+@(?:master|main|v\d+)\b"),
    ),
]


# ── Scanning logic ───────────────────────────────────────────────────────


def _classify_file(path: Path) -> str | None:
    """Classify a file as terraform, kubernetes, docker, or cicd."""
    name = path.name.lower()
    suffix = path.suffix.lower()

    if suffix in (".tf", ".tfvars"):
        return "terraform"
    if name == "dockerfile" or name.startswith("dockerfile."):
        return "docker"
    if name in ("docker-compose.yml", "docker-compose.yaml"):
        return "docker"
    if suffix in (".yml", ".yaml"):
        rel = str(path)
        if ".github/workflows" in rel:
            return "cicd"
        if any(
            kw in name
            for kw in (
                "deployment",
                "service",
                "ingress",
                "pod",
                "statefulset",
                "daemonset",
                "cronjob",
            )
        ):
            return "kubernetes"
        # Check content for K8s API version marker
        try:
            head = path.read_text(errors="replace")[:500]
            if "apiVersion:" in head and "kind:" in head:
                return "kubernetes"
        except OSError:
            pass
    if name in (
        ".gitlab-ci.yml",
        "jenkinsfile",
        ".circleci",
        ".travis.yml",
        "bitbucket-pipelines.yml",
        "azure-pipelines.yml",
    ):
        return "cicd"
    return None


def _check_dockerfile_user(content: str) -> bool:
    """Check if a Dockerfile specifies a non-root USER."""
    return bool(re.search(r"^USER\s+(?!root\b)\S+", content, re.MULTILINE))


def _scan_iac_file(path: Path, category: str) -> list[dict[str, Any]]:
    """Scan a single IaC file for misconfigurations."""
    try:
        content = path.read_text(errors="replace")[: 256 * 1024]
    except OSError:
        return []

    checks_map = {
        "terraform": _TF_CHECKS,
        "kubernetes": _K8S_CHECKS,
        "docker": _DOCKER_CHECKS,
        "cicd": _CICD_CHECKS,
    }
    checks = checks_map.get(category, [])
    findings: list[dict[str, Any]] = []

    for check_id, description, pattern in checks:
        if check_id == "docker_run_as_root":
            # Special case: check for absence of USER instruction
            if re.search(r"^FROM\s+", content, re.MULTILINE) and not _check_dockerfile_user(
                content
            ):
                findings.append(
                    {
                        "check_id": check_id,
                        "description": description,
                        "file": str(path),
                        "category": category,
                        "severity": "medium",
                    }
                )
            continue

        for line_no, line in enumerate(content.splitlines(), start=1):
            if pattern.search(line):
                findings.append(
                    {
                        "check_id": check_id,
                        "description": description,
                        "file": str(path),
                        "line": line_no,
                        "code": line.strip()[:120],
                        "category": category,
                        "severity": _severity_for_check(check_id),
                    }
                )
                break  # One finding per check per file

    return findings


def _severity_for_check(check_id: str) -> str:
    """Map check IDs to severity levels."""
    critical = {"tf_wildcard_iam", "k8s_privileged", "k8s_cap_sys_admin", "cicd_script_injection"}
    high = {
        "tf_public_s3",
        "tf_open_sg",
        "k8s_host_network",
        "k8s_host_pid",
        "docker_secret_env",
        "docker_secret_arg",
        "cicd_pull_request_target",
        "cicd_wildcard_permissions",
    }
    if check_id in critical:
        return "critical"
    if check_id in high:
        return "high"
    return "medium"


def _json(data: Any) -> str:
    return json.dumps(data, indent=2, default=str)


# ── @tool wrappers ───────────────────────────────────────────────────────


@tool
def iac_scan_directory(root: str = "/workspace/target") -> str:
    """Scan a directory for IaC misconfigurations.

    Walks the target directory looking for Terraform, Kubernetes, Docker,
    and CI/CD configuration files. Applies security checks for each
    category and returns findings sorted by severity.
    """
    root_path = Path(root)
    if not root_path.is_dir():
        return _json({"error": "bad_request", "detail": f"{root} is not a directory"})

    all_findings: list[dict[str, Any]] = []
    category_counts: dict[str, int] = {}
    files_scanned: list[str] = []

    for dirpath, dirnames, filenames in os.walk(root_path):
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
        for fname in filenames:
            fpath = Path(dirpath) / fname
            category = _classify_file(fpath)
            if not category:
                continue
            category_counts[category] = category_counts.get(category, 0) + 1
            rel = str(fpath.relative_to(root_path))
            files_scanned.append(rel)
            findings = _scan_iac_file(fpath, category)
            all_findings.extend(findings)

    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    all_findings.sort(key=lambda x: severity_order.get(x.get("severity", "low"), 4))

    return _json(
        {
            "root": root,
            "files_scanned": len(files_scanned),
            "categories": category_counts,
            "total_findings": len(all_findings),
            "findings": all_findings[:200],
        }
    )


@tool
def iac_scan_file(file_path: str) -> str:
    """Scan a single IaC file for security misconfigurations.

    Auto-detects the file type (Terraform, K8s, Docker, CI/CD) and
    applies the appropriate security checks.
    """
    path = Path(file_path)
    if not path.is_file():
        return _json({"error": "file_not_found", "detail": file_path})

    category = _classify_file(path)
    if not category:
        return _json({"error": "unsupported_file", "detail": f"Cannot classify {path.name} as IaC"})

    findings = _scan_iac_file(path, category)
    return _json(
        {
            "file": file_path,
            "category": category,
            "total_findings": len(findings),
            "findings": findings,
        }
    )


IAC_TOOLS = [iac_scan_directory, iac_scan_file]
