"""Expose artifact-only assessment coverage through the engagement's sandbox."""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import PurePosixPath
from typing import Annotated, Any, Literal
from urllib.parse import urlsplit

from httpx import HTTPError
from langchain_core.runnables import RunnableConfig
from langchain_core.tools import tool
from langgraph.prebuilt import InjectedState

from buggy.backends.factory import build_sandbox_backend
from buggy.backends.http_sandbox import HTTPSandbox, SandboxError
from buggy.middleware.filesystem import (
    EngagementFilesystemBackend,
    _normalize_engagement_workspace,
)
from buggy_core.types.roe import MachineEnforcement, ScopeRule, evaluate_target
from buggy_core.utils.engagement_scope import is_valid_engagement_label


class AssessmentToolError(ValueError):
    """The assessment lacks a valid engagement context or artifact."""


def _context(state: dict[str, Any], config: RunnableConfig) -> tuple[HTTPSandbox, str, str]:
    configurable = config.get("configurable") or {}
    engagement = configurable.get("engagement_name", state.get("engagement_name"))
    workspace = configurable.get("workspace_path", state.get("workspace_path"))
    if not isinstance(engagement, str) or not is_valid_engagement_label(engagement):
        raise AssessmentToolError("A valid engagement must be set before using assessment tools")
    normalized = _normalize_engagement_workspace(workspace) if isinstance(workspace, str) else None
    if normalized is None:
        raise AssessmentToolError("A valid engagement workspace must be set")
    if (
        state.get("engagement_name") not in (None, engagement)
        and "workspace_path" not in configurable
    ):
        raise AssessmentToolError("Changed engagement requires an explicit matching workspace")
    return build_sandbox_backend(config), engagement, normalized


def _artifact(sandbox: HTTPSandbox, workspace: str, path: str) -> str:
    artifact = PurePosixPath(path)
    if not path or "\\" in path or ".." in artifact.parts:
        raise AssessmentToolError("Artifact paths must stay inside the engagement workspace")
    if artifact.is_absolute() and not (path == "/workspace" or path.startswith("/workspace/")):
        raise AssessmentToolError("Artifact paths must stay inside the engagement workspace")
    files = EngagementFilesystemBackend(sandbox, workspace).download_files([path])
    if len(files) != 1 or files[0].error or files[0].content is None:
        raise AssessmentToolError("Assessment artifact is unavailable in this engagement")
    content = files[0].content
    if len(content) > 16 * 1024 * 1024:
        raise AssessmentToolError(
            "Assessment artifacts must be at most 16 MiB; input was not truncated"
        )
    try:
        return content.decode("utf-8")
    except UnicodeError as exc:
        raise AssessmentToolError("Assessment artifacts must be UTF-8") from exc


def _document(sandbox: HTTPSandbox, workspace: str, path: str) -> dict[str, Any]:
    try:
        document = json.loads(_artifact(sandbox, workspace, path))
    except json.JSONDecodeError as exc:
        raise AssessmentToolError("Assessment plan and RoE must be valid JSON") from exc
    if not isinstance(document, dict):
        raise AssessmentToolError("Assessment plan and RoE must be JSON objects")
    return document


def _scope_rule(rule: ScopeRule) -> ScopeRule:
    pattern = rule.pattern
    if "://" in pattern:
        parts = urlsplit(pattern)
        if parts.path not in ("", "/") or parts.query or parts.fragment:
            raise AssessmentToolError(
                "Path-restricted scope requires an explicit assessment scope review"
            )
        pattern = parts.hostname or ""
    return ScopeRule(pattern=pattern, kind="auto")


def _rules(sandbox: HTTPSandbox, workspace: str) -> MachineEnforcement:
    roe = _document(sandbox, workspace, "plan/roe.json")
    machine = roe.get("machine_enforcement") or {}
    if not isinstance(machine, dict):
        raise AssessmentToolError("Invalid machine-enforcement scope")
    rules = MachineEnforcement.from_dict(
        {
            **machine,
            "in_scope": machine.get("in_scope") or roe.get("in_scope") or [],
            "out_of_scope": machine.get("out_of_scope") or roe.get("out_of_scope") or [],
        }
    )
    if not rules.in_scope:
        raise AssessmentToolError("Assessment requires an explicit RoE scope")
    return replace(
        rules,
        in_scope=tuple(_scope_rule(rule) for rule in rules.in_scope),
        out_of_scope=tuple(_scope_rule(rule) for rule in rules.out_of_scope),
    )


@tool(
    description="Initialize artifact-only coverage from operator-reviewed plan/assessment.json and plan/roe.json. The plan supplies profile, required_roles, available_roles and source_available; allowed hosts always come from RoE, never model arguments. This baseline is not a full ASVS audit."
)
def assessment_initialize(
    state: Annotated[dict[str, Any], InjectedState], config: RunnableConfig
) -> str:
    sandbox, engagement, workspace = _context(state, config)
    plan = _document(sandbox, workspace, "plan/assessment.json")
    rules = _rules(sandbox, workspace)
    payload = {
        key: plan[key]
        for key in ("profile", "required_roles", "available_roles", "source_available")
        if key in plan
    }
    payload.update(
        engagement_name=engagement,
        allowed_hosts=[rule.pattern for rule in rules.in_scope],
        denied_hosts=[rule.pattern for rule in rules.out_of_scope]
        + list(rules.effective_forbidden_destinations()),
    )
    return json.dumps(sandbox.assessment("initialize", payload, workspace_path=workspace))


@tool(
    description="Inspect persisted assessment coverage, inventory, gaps, or eligible next cases. Never probes a target. Follow next_offset until all pages are inspected; totals cover the full inventory."
)
def assessment_status(
    state: Annotated[dict[str, Any], InjectedState],
    config: RunnableConfig,
    view: Literal["report", "gaps", "inventory", "next"] = "gaps",
    offset: int = 0,
    limit: int = 50,
) -> str:
    sandbox, _, workspace = _context(state, config)
    return json.dumps(
        sandbox.assessment(view, {"offset": offset, "limit": limit}, workspace_path=workspace)
    )


@tool(
    description="Import all operations from an existing engagement artifact: openapi, traffic (HAR), observations, or source-status. No target requests. Content is checked against current RoE; credentials and parameter values are not inventory. Large inventories stay persisted and are viewed through assessment_status pagination."
)
def assessment_import(
    path: str,
    kind: Literal["openapi", "traffic", "observations", "source-status"],
    state: Annotated[dict[str, Any], InjectedState],
    config: RunnableConfig,
    base_url: str = "",
    source_id: str = "",
) -> str:
    from buggy.assessment_import import prepare_import

    sandbox, _, workspace = _context(state, config)
    rules = _rules(sandbox, workspace)
    payload = prepare_import(kind, _artifact(sandbox, workspace, path), source_id or path, base_url)
    for operation in payload["operations"]:
        url = operation.get("url") or operation.get("base_url") or payload.get("base_url") or ""
        host = urlsplit(url).hostname
        if not host or not evaluate_target(host, rules).allow:
            raise AssessmentToolError("Imported operation is outside the current engagement scope")
    return json.dumps(sandbox.assessment("import", payload, workspace_path=workspace))


@tool(
    description="Evaluate one pending http.nosniff or http.hsts case against an existing captured-response JSON artifact. Never sends requests. Evidence must match the case URL and method and contain status_code, headers, captured_at, and source='capture'."
)
def assessment_check_headers(
    case_id: str,
    evidence_path: str,
    state: Annotated[dict[str, Any], InjectedState],
    config: RunnableConfig,
) -> str:
    sandbox, _, workspace = _context(state, config)
    return json.dumps(
        sandbox.assessment(
            "check_headers",
            {"case_id": case_id, "evidence_path": evidence_path},
            workspace_path=workspace,
        )
    )


@tool(
    description="Record an explicitly attested assessment result, not an independently verified finding. Pass/fail require existing workspace-relative evidence files, which are hashed. Missing access stays blocked, never not_applicable. Supply rationale for every disposition."
)
def assessment_record_result(
    case_id: str,
    status: Literal["pass", "fail", "blocked", "inconclusive", "not_applicable"],
    rationale: str,
    state: Annotated[dict[str, Any], InjectedState],
    config: RunnableConfig,
    evidence_paths: list[str] | None = None,
) -> str:
    sandbox, _, workspace = _context(state, config)
    return json.dumps(
        sandbox.assessment(
            "record",
            {
                "case_id": case_id,
                "status": status,
                "rationale": rationale,
                "evidence_paths": evidence_paths or [],
            },
            workspace_path=workspace,
        )
    )


@tool(
    description="List the versioned defensive scenario catalog, primary sources, limitations, and exact normalized artifact schemas. No target requests or exploit instructions."
)
def assessment_scenario_catalog(
    state: Annotated[dict[str, Any], InjectedState], config: RunnableConfig
) -> str:
    sandbox, _, workspace = _context(state, config)
    return json.dumps(sandbox.assessment("scenario_catalog", {}, workspace_path=workspace))


@tool(
    description="Evaluate an existing workspace-relative JSON artifact against a fixed defensive scenario. Consult assessment_scenario_catalog for its schema. Results describe supplied policy/simulation evidence, not live control verification, and do not update baseline coverage. No commands or target requests are executed."
)
def assessment_evaluate_scenario(
    scenario_id: str,
    evidence_path: str,
    state: Annotated[dict[str, Any], InjectedState],
    config: RunnableConfig,
) -> str:
    sandbox, _, workspace = _context(state, config)
    return json.dumps(
        sandbox.assessment(
            "evaluate_scenario",
            {"scenario_id": scenario_id, "evidence_path": evidence_path},
            workspace_path=workspace,
        )
    )


@tool(
    description="Prioritize supplied CVE applicability against a supplied CISA KEV JSON snapshot. Both paths must be workspace-relative; observations require schema_version=1, an HTTP(S) asset URL, timezone-aware observed_at, evidence_kind=scanner_export|vendor_advisory|operator_attestation and vulnerabilities containing cve_id, basis=vendor_advisory|scanner_result|manual_review and optional applicability=affected|not_affected|unknown. No product/version guessing, exploit retrieval, or target requests. Matches are triage priorities, not confirmed vulnerabilities. Follow next_offset; priority_counts describe the whole input, not only this page."
)
def assessment_prioritize_kev(
    catalog_path: str,
    observation_path: str,
    state: Annotated[dict[str, Any], InjectedState],
    config: RunnableConfig,
    offset: int = 0,
    limit: int = 50,
) -> str:
    sandbox, _, workspace = _context(state, config)
    return json.dumps(
        sandbox.assessment(
            "prioritize_kev",
            {
                "catalog_path": catalog_path,
                "observation_path": observation_path,
                "offset": offset,
                "limit": limit,
            },
            workspace_path=workspace,
        )
    )


def _asvs_call(
    state: dict[str, Any], config: RunnableConfig, action: str, payload: dict[str, Any]
) -> str:
    sandbox, _, workspace = _context(state, config)
    return json.dumps(sandbox.assessment(action, payload, workspace_path=workspace))


@tool(
    description="Read the pinned official OWASP ASVS 5.0.0 requirements, level counts, source hash and license. Levels are cumulative. Follow next_offset; catalog membership is not verification or certification."
)
def assessment_asvs_catalog(
    state: Annotated[dict[str, Any], InjectedState],
    config: RunnableConfig,
    level: int = 2,
    offset: int = 0,
    limit: int = 50,
) -> str:
    return _asvs_call(
        state, config, "asvs_catalog", {"level": level, "offset": offset, "limit": limit}
    )


@tool(
    description="Initialize an application-level ASVS plan from operator-reviewed plan/asvs.json (asset, level, optional prerequisites mapping requirement IDs to roles/source_required). Requires an initialized scoped assessment. Every selected requirement starts unreviewed; no inferred exclusions or probes."
)
def assessment_asvs_initialize(
    state: Annotated[dict[str, Any], InjectedState],
    config: RunnableConfig,
) -> str:
    return _asvs_call(state, config, "asvs_init", {"plan_path": "plan/asvs.json"})


@tool(
    description="Inspect ASVS plans, a plan's full-denominator review status, or eligible next requirements. Empty plan_id lists plans. Results are evidence-backed attestations, not independent verification; no baseline coverage is granted. Follow pagination."
)
def assessment_asvs_status(
    state: Annotated[dict[str, Any], InjectedState],
    config: RunnableConfig,
    plan_id: str = "",
    view: Literal["report", "next", "plans"] = "report",
    offset: int = 0,
    limit: int = 50,
) -> str:
    action = "asvs_list" if not plan_id or view == "plans" else "asvs_" + view
    return _asvs_call(state, config, action, {"plan_id": plan_id, "offset": offset, "limit": limit})


@tool(
    description="Record a reviewer attestation for one qualified ASVS requirement ID. Pass/fail/not_applicable require existing workspace-relative evidence; not_applicable also requires method=applicability_review. Missing declared access blocks these dispositions. Every result needs rationale and a review method. Supply expected_revision to reject stale updates. Does not execute tests or independently verify compliance."
)
def assessment_asvs_record(
    plan_id: str,
    requirement_id: str,
    status: Literal["pass", "fail", "not_applicable", "blocked", "inconclusive"],
    method: Literal[
        "code_review", "config_review", "supplied_capture", "manual_review", "applicability_review"
    ],
    rationale: str,
    state: Annotated[dict[str, Any], InjectedState],
    config: RunnableConfig,
    evidence_paths: list[str] | None = None,
    expected_revision: int | None = None,
) -> str:
    return _asvs_call(
        state,
        config,
        "asvs_record",
        {
            "plan_id": plan_id,
            "requirement_id": requirement_id,
            "status": status,
            "method": method,
            "rationale": rationale,
            "evidence_paths": evidence_paths or [],
            "expected_revision": expected_revision,
        },
    )


@tool(
    description="Build a read-only, allowlisted Markdown snapshot of the selected engagement for local defensive review. Includes available coverage, origins-only inventory, objective states, ASVS summaries, observed skill requests, and optionally scoped graph metadata. Omits raw bodies, conversations, reasoning, credentials, skill bodies, and executable payload fields. Missing sources and truncation remain explicit. The output is untrusted derived metadata, not new evidence or authorization; no model is called and no generated content is executed."
)
def assessment_context_snapshot(
    state: Annotated[dict[str, Any], InjectedState],
    config: RunnableConfig,
    include_graph: bool = True,
    max_rows: int = 1000,
) -> str:
    from buggy.context_export import ContextExportError, export_snapshot

    sandbox, engagement, workspace = _context(state, config)
    try:
        local = sandbox.assessment(
            "context_sources",
            {"engagement_name": engagement, "max_rows": max_rows},
            workspace_path=workspace,
        )
    except (SandboxError, HTTPError, ValueError):
        raise AssessmentToolError("Sandbox snapshot sources are unavailable or invalid.") from None
    if (
        type(local) is not dict
        or type(local.get("sources")) is not dict
        or local.get("engagement") != engagement
    ):
        raise AssessmentToolError("Invalid or mismatched snapshot sources.")
    local["sources"]["runtime"] = {
        "engagement": engagement,
        "status": "ok",
        "total": 1,
        "data": [{"service": "sandbox", "status": "running"}],
    }
    state_workspace = state.get("workspace_path")
    configurable = config.get("configurable") or {}
    same_state = (
        state.get("engagement_name") == engagement
        and isinstance(state_workspace, str)
        and _normalize_engagement_workspace(state_workspace) == workspace
        and (
            "kg_engagement" not in configurable
            or configurable["kg_engagement"] == state.get("kg_engagement")
        )
    )
    graph_scope = configurable.get(
        "kg_engagement", state.get("kg_engagement") if same_state else None
    )
    try:
        snapshot = export_snapshot(
            local,
            include_graph=include_graph,
            graph_scope=graph_scope,
            messages=state.get("messages") if same_state else None,
            max_rows=max_rows,
        )
    except ContextExportError as exc:
        raise AssessmentToolError(str(exc)) from exc
    return json.dumps(snapshot)


@tool(
    description="Inspect the selected sandbox capability manifest. Optional probe runs only fixed, bounded version/parser checks, never target requests. Installed or available is not authorization or end-to-end validation."
)
def assessment_capabilities(
    state: Annotated[dict[str, Any], InjectedState],
    config: RunnableConfig,
    probe: bool = False,
) -> str:
    sandbox, _, _ = _context(state, config)
    try:
        return json.dumps(sandbox.capabilities(probe=probe))
    except (SandboxError, HTTPError, ValueError):
        raise AssessmentToolError("Sandbox capability inspection failed") from None


@tool(
    description="Read the five versioned defensive workflow contracts, artifact schemas, limits and non-assurance semantics. Consult this before preparing an artifact. Does not execute a workflow or expand scope."
)
def assessment_workflow_catalog(
    state: Annotated[dict[str, Any], InjectedState],
    config: RunnableConfig,
) -> str:
    sandbox, _, workspace = _context(state, config)
    try:
        return json.dumps(sandbox.workflow("catalog", {}, workspace_path=workspace))
    except (SandboxError, HTTPError, ValueError):
        raise AssessmentToolError("Workflow catalog is unavailable") from None


@tool(
    description="Review a workspace-relative artifact using a fixed defensive workflow. Requires an initialized, scope-matching assessment. Persists hashed evidence and an opaque run ID; does not update ASVS/baseline dispositions. This agent tool is artifact-only: live observation is available only through an explicit operator CLI/SDK request with enforcing RoE. Workflow IDs and exact artifact schemas come from assessment_workflow_catalog."
)
def assessment_run_workflow(
    workflow_id: str,
    url: str,
    artifact_path: str,
    state: Annotated[dict[str, Any], InjectedState],
    config: RunnableConfig,
    method: str | None = None,
) -> str:
    sandbox, engagement, workspace = _context(state, config)
    try:
        assessment = sandbox.assessment("report", {"limit": 1}, workspace_path=workspace)
        if assessment.get("engagement_name") != engagement:
            raise AssessmentToolError("Workflow engagement does not match the workspace")
        host = urlsplit(url).hostname
        policy = MachineEnforcement(
            in_scope=tuple(ScopeRule(host) for host in assessment["allowed_hosts"]),
            out_of_scope=tuple(ScopeRule(host) for host in assessment["denied_hosts"]),
        )
        if not host or not evaluate_target(host, policy).allow:
            raise AssessmentToolError("Workflow asset is outside engagement scope")
        payload: dict[str, Any] = {
            "workflow_id": workflow_id,
            "url": url,
            "artifact_path": artifact_path,
            "observe": False,
        }
        if method is not None:
            payload["method"] = method
        return json.dumps(sandbox.workflow("run", payload, workspace_path=workspace))
    except AssessmentToolError:
        raise
    except (SandboxError, HTTPError, ValueError, KeyError, TypeError):
        raise AssessmentToolError("Workflow request is invalid or unavailable") from None


ASSESSMENT_REVIEW_TOOLS = [
    assessment_capabilities,
    assessment_workflow_catalog,
    assessment_run_workflow,
    assessment_context_snapshot,
    assessment_asvs_catalog,
    assessment_asvs_status,
    assessment_asvs_record,
    assessment_status,
    assessment_check_headers,
    assessment_record_result,
    assessment_scenario_catalog,
    assessment_evaluate_scenario,
    assessment_prioritize_kev,
]
ASSESSMENT_TOOLS = [
    assessment_initialize,
    assessment_import,
    assessment_asvs_initialize,
    *ASSESSMENT_REVIEW_TOOLS,
]
