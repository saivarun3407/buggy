"""Run artifact-only web/API coverage assessments against an explicit local workspace."""

from __future__ import annotations

import argparse
import json
import os
import sqlite3
import stat
import sys
from hashlib import sha256
from pathlib import Path
from typing import Any

from buggy.assessment_import import (
    MAX_IMPORT_BYTES,
    AssessmentImportError,
    prepare_import,
    render_report,
)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="buggy-cli assessment")
    parser.add_argument("--workspace", required=True, type=Path)
    parser.add_argument("--expected-revision", type=int)
    commands = parser.add_subparsers(dest="action", required=True)
    snapshot = commands.add_parser(
        "snapshot", help="Print a redacted engagement-metadata Markdown snapshot"
    )
    snapshot.add_argument("--engagement", help="Required when no assessment ledger is available")
    snapshot.add_argument("--max-rows", type=int, default=1000)
    snapshot.add_argument(
        "--include-kg",
        action="store_true",
        help="Read metadata using the configured Neo4j connection",
    )
    snapshot.add_argument("--kg-scope", help="Explicit graph partition; required with --include-kg")
    snapshot.add_argument(
        "--require-complete",
        action="store_true",
        help="Exit 3 if requested metadata is unavailable or omitted",
    )
    asvs = commands.add_parser(
        "asvs-catalog", help="Read the pinned OWASP ASVS 5.0.0 catalog; no assessment claims"
    )
    asvs.add_argument("--level", type=int, choices=[1, 2, 3], default=2)
    asvs.add_argument("--offset", type=int, default=0)
    asvs.add_argument("--limit", type=int, default=50)
    asvs_init = commands.add_parser(
        "asvs-init", help="Create an application-level, initially unreviewed ASVS plan"
    )
    asvs_init.add_argument("--asset", required=True)
    asvs_init.add_argument("--level", type=int, choices=[1, 2, 3], default=2)
    asvs_init.add_argument(
        "--prerequisites", help="Workspace-relative JSON: requirement ID to roles/source_required"
    )
    asvs_record = commands.add_parser(
        "asvs-record", help="Record an evidence-backed ASVS reviewer attestation"
    )
    asvs_record.add_argument("--plan", required=True)
    asvs_record.add_argument("--requirement", required=True)
    asvs_record.add_argument(
        "--status",
        required=True,
        choices=["pass", "fail", "not_applicable", "blocked", "inconclusive"],
    )
    asvs_record.add_argument(
        "--method",
        required=True,
        choices=[
            "code_review",
            "config_review",
            "supplied_capture",
            "manual_review",
            "applicability_review",
        ],
    )
    asvs_record.add_argument("--rationale", required=True)
    asvs_record.add_argument("--evidence", action="append", default=[])
    for name in ("asvs-report", "asvs-next", "asvs-list"):
        command = commands.add_parser(name)
        if name != "asvs-list":
            command.add_argument("--plan", required=True)
        command.add_argument("--offset", type=int, default=0)
        command.add_argument("--limit", type=int, default=50)
        if name == "asvs-report":
            command.add_argument("--fail-on-gaps", action="store_true")
            command.add_argument("--format", choices=["json", "markdown"], default="json")
    commands.add_parser(
        "scenarios", help="List sourced defensive scenarios and their artifact contracts"
    )
    scenario = commands.add_parser(
        "evaluate-scenario", help="Check a supplied artifact; exits 0=pass, 1=fail, 3=inconclusive"
    )
    scenario.add_argument("scenario_id")
    scenario.add_argument(
        "--evidence", required=True, help="Workspace-relative JSON artifact; no target requests"
    )
    kev = commands.add_parser(
        "prioritize-kev",
        help="Prioritize supplied CVE assertions against a supplied KEV catalog",
        description="Observations require schema_version=1, an HTTP(S) asset URL, a timezone-aware "
        "observed_at, evidence_kind=scanner_export|vendor_advisory|operator_attestation, and a "
        "vulnerabilities array. Each record requires cve_id and "
        "basis=vendor_advisory|scanner_result|manual_review; "
        "applicability=affected|not_affected|unknown defaults to unknown. "
        "This is supplied-artifact prioritization, not independent vulnerability verification.",
    )
    kev.add_argument(
        "--catalog", required=True, help="Workspace-relative CISA JSON snapshot (max 16 MiB)"
    )
    kev.add_argument(
        "--observations", required=True, help="Workspace-relative normalized CVE observations"
    )
    kev.add_argument("--offset", type=int, default=0)
    kev.add_argument("--limit", type=int, default=50)
    kev.add_argument(
        "--fail-on-urgent",
        action="store_true",
        help="Exit 1 for urgent records, 3 for incomplete intelligence/applicability",
    )
    initialize = commands.add_parser("init", help="Initialize a scoped assessment baseline")
    initialize.add_argument("--name", required=True)
    initialize.add_argument("--scope", action="append", required=True)
    initialize.add_argument(
        "--exclude-host",
        action="append",
        default=[],
        help="Excluded host, wildcard, or CIDR; repeatable",
    )
    initialize.add_argument(
        "--profile", choices=["external", "authenticated", "source-assisted"], default="external"
    )
    initialize.add_argument("--require-role", action="append")
    initialize.add_argument("--role", action="append", default=[])
    initialize.add_argument("--source-available", action="store_true")
    for kind in ("openapi", "traffic", "observations", "source-status"):
        command = commands.add_parser(
            f"import-{kind}", help="Import an explicit local JSON/YAML artifact"
        )
        command.add_argument("path")
        command.add_argument("--source-id")
        if kind in {"openapi", "observations"}:
            command.add_argument("--base-url", required=kind == "openapi", default="")
        else:
            command.set_defaults(base_url="")
    access = commands.add_parser(
        "access", help="Set the roles and source material currently available"
    )
    access.add_argument("--role", action="append", default=[])
    access.add_argument("--source-available", action="store_true")
    record = commands.add_parser(
        "record", help="Record an explicit evidence-backed reviewer attestation"
    )
    record.add_argument("--case", required=True)
    record.add_argument(
        "--status",
        required=True,
        choices=["pass", "fail", "blocked", "inconclusive", "not_applicable"],
    )
    record.add_argument(
        "--evidence",
        action="append",
        default=[],
        help="Workspace-relative evidence path; repeatable",
    )
    record.add_argument("--rationale", required=True)
    headers = commands.add_parser(
        "check-headers", help="Evaluate a supplied response artifact without requests"
    )
    headers.add_argument("--case", required=True)
    headers.add_argument(
        "--evidence", required=True, help="Workspace-relative JSON response artifact path"
    )
    for action in ("report", "gaps", "inventory", "next"):
        command = commands.add_parser(action)
        command.add_argument("--offset", type=int, default=0)
        command.add_argument("--limit", type=int, default=50)
        if action in {"report", "gaps"}:
            command.add_argument("--format", choices=["json", "markdown"], default="json")
            command.add_argument("--fail-on-gaps", action="store_true")
    return parser


def _read_artifact(value: str) -> tuple[Path, str]:
    if value == "-" or "://" in value:
        raise AssessmentImportError("Import requires an explicit local file, not a URL or stdin")
    try:
        path = Path(value).resolve(strict=True)
        with os.fdopen(os.open(path, os.O_RDONLY | os.O_NONBLOCK), "rb") as artifact:
            metadata = os.fstat(artifact.fileno())
            if not stat.S_ISREG(metadata.st_mode):
                raise AssessmentImportError("Artifact must be a regular local file")
            if metadata.st_size > MAX_IMPORT_BYTES:
                raise AssessmentImportError("Artifact exceeds the 16 MiB input limit")
            content = artifact.read(MAX_IMPORT_BYTES + 1)
        if len(content) > MAX_IMPORT_BYTES:
            raise AssessmentImportError("Artifact exceeds the 16 MiB input limit")
        return path, content.decode("utf-8-sig")
    except UnicodeError:
        raise AssessmentImportError("Artifact must contain valid UTF-8 text") from None
    except (OSError, ValueError) as exc:
        if isinstance(exc, AssessmentImportError):
            raise
        raise AssessmentImportError(
            "Artifact is missing, unreadable, or not a regular local file"
        ) from None


def _payload(args: argparse.Namespace) -> tuple[str, dict[str, Any]]:
    action = args.action
    if action == "snapshot":
        payload: dict[str, Any] = {"max_rows": args.max_rows}
        if args.engagement is not None:
            payload["engagement_name"] = args.engagement
        return "context_sources", payload
    if action == "asvs-catalog":
        return "asvs_catalog", {"level": args.level, "offset": args.offset, "limit": args.limit}
    if action == "asvs-init":
        return "asvs_init", {
            "asset": args.asset,
            "level": args.level,
            "prerequisites_path": args.prerequisites,
        }
    if action == "asvs-record":
        return "asvs_record", {
            "plan_id": args.plan,
            "requirement_id": args.requirement,
            "status": args.status,
            "method": args.method,
            "rationale": args.rationale,
            "evidence_paths": args.evidence,
        }
    if action in {"asvs-report", "asvs-next", "asvs-list"}:
        return action.replace("-", "_"), {
            "plan_id": getattr(args, "plan", None),
            "offset": args.offset,
            "limit": args.limit,
        }
    if action == "scenarios":
        return "scenario_catalog", {}
    if action == "evaluate-scenario":
        return "evaluate_scenario", {
            "scenario_id": args.scenario_id,
            "evidence_path": args.evidence,
        }
    if action == "prioritize-kev":
        return "prioritize_kev", {
            "catalog_path": args.catalog,
            "observation_path": args.observations,
            "offset": args.offset,
            "limit": args.limit,
        }
    if action == "init":
        payload = {
            "engagement_name": args.name,
            "profile": args.profile,
            "allowed_hosts": args.scope,
            "denied_hosts": args.exclude_host,
            "available_roles": args.role,
            "source_available": args.source_available,
        }
        if args.require_role is not None:
            payload["required_roles"] = args.require_role
        return "initialize", payload
    if action.startswith("import-"):
        kind = action.removeprefix("import-")
        path, content = _read_artifact(args.path)
        source_id = args.source_id
        if source_id is None:
            source_id = f"{kind}:{sha256(str(path).encode('utf-8')).hexdigest()}"
        return "import", prepare_import(kind, content, source_id, args.base_url)
    if action == "access":
        return action, {"available_roles": args.role, "source_available": args.source_available}
    if action == "record":
        return action, {
            "case_id": args.case,
            "status": args.status,
            "evidence_paths": args.evidence,
            "rationale": args.rationale,
        }
    if action == "check-headers":
        return "check_headers", {"case_id": args.case, "evidence_path": args.evidence}
    return action, {"offset": args.offset, "limit": args.limit}


def main(argv: list[str] | None = None) -> int:
    from buggy.sandbox_kernel.assessment import AssessmentError, AssessmentStore

    args = _parser().parse_args(argv)
    snapshot_mode = args.action == "snapshot"
    markdown = snapshot_mode or getattr(args, "format", "json") == "markdown"
    snapshot = None
    try:
        action, payload = _payload(args)
        if args.expected_revision is not None and action in {
            "initialize",
            "import",
            "access",
            "record",
            "check_headers",
            "asvs_init",
            "asvs_record",
        }:
            payload["expected_revision"] = args.expected_revision
        result = AssessmentStore(args.workspace).dispatch(action, payload)
        if snapshot_mode:
            from buggy.context_export import ContextExportError, export_snapshot

            if args.include_kg and not args.kg_scope:
                raise AssessmentError("--include-kg requires an explicit --kg-scope")
            try:
                snapshot = export_snapshot(
                    result,
                    include_graph=args.include_kg,
                    graph_scope=args.kg_scope,
                    max_rows=args.max_rows,
                )
            except ContextExportError as exc:
                raise AssessmentError(str(exc)) from exc
            output = snapshot["markdown"]
        else:
            output = render_report(result) if markdown else json.dumps(result, indent=2)
    except (AssessmentError, AssessmentImportError, OSError, sqlite3.Error) as exc:
        print(f"Assessment failed: {exc}", file=sys.stderr)
        return 2
    print(output, end="" if markdown else "\n")
    if snapshot is not None:
        return 3 if args.require_complete and snapshot["partial"] else 0
    if action == "evaluate_scenario":
        return {"pass": 0, "fail": 1, "inconclusive": 3}.get(result.get("status"), 3)
    if action == "prioritize_kev" and args.fail_on_urgent:
        if result["priority_counts"]["urgent"]:
            return 1
        if not result["total"] or result["priority_counts"]["investigate"]:
            return 3
    return int(bool(getattr(args, "fail_on_gaps", False)) and result.get("complete") is not True)
