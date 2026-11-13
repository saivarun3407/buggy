"""Pure preparation of local assessment artifacts for CLI and agent callers."""

from __future__ import annotations

import html
import json
import re
from datetime import datetime
from typing import Any
from urllib.parse import parse_qsl, urlsplit, urlunsplit

import yaml

MAX_IMPORT_BYTES = 16 * 1024 * 1024


class AssessmentImportError(ValueError):
    """An artifact cannot safely be converted to assessment inventory."""


def _object(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise AssessmentImportError("Expected an object in assessment artifact")
    return value


def _array(value: Any) -> list[Any]:
    if not isinstance(value, list):
        raise AssessmentImportError("Expected an array in assessment artifact")
    return value


def _text(value: Any) -> str:
    if not isinstance(value, str) or not value.strip() or any(ord(char) < 32 for char in value):
        raise AssessmentImportError("Expected a nonempty text field in assessment artifact")
    return value.strip()


def _document(content: str) -> dict[str, Any]:
    if not isinstance(content, str) or not content.strip():
        raise AssessmentImportError("Artifact content must be nonempty JSON or YAML text")
    try:
        size = len(content.encode("utf-8"))
    except UnicodeError:
        raise AssessmentImportError("Artifact must contain valid UTF-8 text") from None
    if size > MAX_IMPORT_BYTES:
        raise AssessmentImportError("Artifact exceeds the 16 MiB input limit")
    try:
        try:
            document = json.loads(content)
        except json.JSONDecodeError:
            document = yaml.safe_load(content)
    except (ValueError, yaml.YAMLError, RecursionError):
        raise AssessmentImportError("Artifact is not valid JSON or safe YAML") from None
    return _object(document)


def _parameter(name: Any, location: str) -> dict[str, Any]:
    return {"name": _text(name), "in": location, "required": False}


def _target(value: Any, absolute: bool) -> tuple[str, list[dict[str, Any]]]:
    target = _text(value)
    try:
        parts = urlsplit(target)
        host = parts.hostname
        port = parts.port
    except ValueError:
        raise AssessmentImportError("Malformed operation URL") from None
    if absolute:
        if parts.scheme not in {"http", "https"} or not host or any(c.isspace() for c in host):
            raise AssessmentImportError("Operation URL must be an absolute HTTP or HTTPS URL")
        netloc = f"[{host}]" if ":" in host else host
        if port is not None:
            netloc += f":{port}"
    else:
        if parts.scheme or parts.netloc or not target.startswith("/") or target.startswith("//"):
            raise AssessmentImportError("Operation path must start with a single slash")
        netloc = ""
    parameters = [
        _parameter(name, "query") for name, _ in parse_qsl(parts.query, keep_blank_values=True)
    ]
    return urlunsplit((parts.scheme, netloc, parts.path, "", "")), parameters


def _base_url(value: Any) -> str:
    target, _ = _target(value, absolute=True)
    parts = urlsplit(value)
    if parts.query or parts.fragment or "@" in parts.netloc:
        raise AssessmentImportError(
            "Base URL must not contain credentials, query parameters, or a fragment"
        )
    return target


def _operation(value: Any, base_url: str) -> dict[str, Any]:
    operation = _object(value)
    method = _text(operation.get("method")).upper()
    if not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Z-]+", method):
        raise AssessmentImportError("Operation method must be an HTTP method name")
    targets = [key for key in ("url", "path") if key in operation]
    if len(targets) != 1:
        raise AssessmentImportError("Operation must specify exactly one URL or path")
    key = targets[0]
    target, parameters = _target(operation[key], absolute=key == "url")
    result: dict[str, Any] = {key: target, "method": method}
    if key == "path":
        if "base_url" in operation:
            result["base_url"] = _base_url(operation["base_url"])
        elif not base_url:
            raise AssessmentImportError("Path operations require an explicit base URL")
    for value in _array(operation.get("parameters", [])):
        parameter = _object(value)
        name = _text(parameter.get("name"))
        location = _text(parameter.get("in"))
        if location not in {"query", "path", "header", "cookie", "body", "formData"}:
            raise AssessmentImportError("Parameter location is not supported")
        required = parameter.get("required", False)
        if not isinstance(required, bool):
            raise AssessmentImportError("Parameter required flag must be a boolean")
        parameters.append({"name": name, "in": location, "required": required})
    result["parameters"] = parameters
    return result


def _traffic_records(document: dict[str, Any]) -> list[dict[str, Any]]:
    entries = _array(_object(document.get("log")).get("entries"))
    records = []
    for entry in entries:
        request = _object(_object(entry).get("request"))
        parameters = [
            _parameter(_object(item).get("name"), "query")
            for item in _array(request.get("queryString", []))
        ]
        if "postData" in request:
            body = _object(request["postData"])
            parameters.extend(
                _parameter(_object(item).get("name"), "body")
                for item in _array(body.get("params", []))
            )
            mime_type = body.get("mimeType", "")
            text = body.get("text", "")
            if not isinstance(mime_type, str) or not isinstance(text, str):
                raise AssessmentImportError("HAR body metadata must contain text fields")
            mime_type = mime_type.split(";", 1)[0].strip().lower()
            if text and mime_type == "application/x-www-form-urlencoded":
                parameters.extend(
                    _parameter(name, "body") for name, _ in parse_qsl(text, keep_blank_values=True)
                )
            elif text and (mime_type == "application/json" or mime_type.endswith("+json")):
                try:
                    pending = [json.loads(text)]
                except (ValueError, RecursionError):
                    raise AssessmentImportError("HAR JSON body is malformed") from None
                while pending:
                    value = pending.pop()
                    if isinstance(value, dict):
                        parameters.extend(_parameter(name, "body") for name in value)
                        pending.extend(value.values())
                    elif isinstance(value, list):
                        pending.extend(value)
        records.append(
            {"url": request.get("url"), "method": request.get("method"), "parameters": parameters}
        )
    return records


def _status(value: Any) -> str:
    if not isinstance(value, str) or value not in {"ok", "empty", "error", "unavailable", "mock"}:
        raise AssessmentImportError(
            "Source status must explicitly be ok, empty, error, unavailable, or mock"
        )
    return value


def _source_status(document: dict[str, Any]) -> dict[str, Any]:
    status = _status(document.get("status"))
    if "detail" in document and not isinstance(document["detail"], str):
        raise AssessmentImportError("Source detail must be text")
    sources = _array(document.get("sources", []))
    errors = _array(document.get("errors", []))
    if not all(isinstance(value, str) for value in sources + errors):
        raise AssessmentImportError("Source names and errors must be arrays of text")
    provider_statuses = []
    for name, value in _object(document.get("source_status", {})).items():
        provider = _object(value)
        provider_status = _status(provider.get("status"))
        configured = provider.get("configured", True)
        if not isinstance(configured, bool):
            raise AssessmentImportError("Provider configured flag must be boolean")
        if configured or name in sources or provider_status == "mock":
            provider_statuses.append(provider_status)
    if "error" in document and not isinstance(document["error"], str):
        raise AssessmentImportError("Source error must be text")
    if "in_scope" in document and not isinstance(document["in_scope"], bool):
        raise AssessmentImportError("Source scope flag must be boolean")
    if status in {"ok", "empty"}:
        if "mock" in sources or "mock" in provider_statuses:
            status = "mock"
        elif errors or document.get("error") or "error" in provider_statuses:
            status = "error"
        elif document.get("in_scope") is False or "unavailable" in provider_statuses:
            status = "unavailable"
        elif provider_statuses and all(value == "empty" for value in provider_statuses):
            status = "empty"
    detail = {
        "ok": "OSINT source reported observations; these are not coverage evidence",
        "empty": "OSINT source returned no observations",
        "error": "OSINT source reported an error; no usable evidence",
        "unavailable": "OSINT source is unavailable; no usable evidence",
        "mock": "Mock OSINT data is not coverage evidence",
    }[status]
    source = {"kind": "osint", "status": status, "detail": detail}
    if "observed_at" in document:
        observed_at = document["observed_at"]
        if isinstance(observed_at, datetime):
            observed_at = observed_at.isoformat()
        if not isinstance(observed_at, str) or not re.fullmatch(
            r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})", observed_at
        ):
            raise AssessmentImportError(
                "Source observed_at must be an ISO 8601 timestamp with a timezone"
            )
        try:
            datetime.fromisoformat(observed_at.replace("Z", "+00:00"))
        except ValueError:
            raise AssessmentImportError(
                "Source observed_at must be an ISO 8601 timestamp"
            ) from None
        source["observed_at"] = observed_at
    return source


def prepare_import(kind: str, content: str, source_id: str, base_url: str = "") -> dict[str, Any]:
    """Return a ledger import payload without file, network, or clock access.

    Kinds are openapi, traffic (HAR), observations, and source-status (OSINT).
    JSON and safe YAML are accepted. Inventory retains all operations, leaving
    deduplication to the ledger. URLs and parameters retain names, not values;
    HAR credentials, headers, cookies, bodies, and provider error details are
    discarded. Malformed input raises AssessmentImportError without quoting it.
    Missing observation timestamps remain absent rather than using the clock.
    """
    if not isinstance(kind, str) or kind not in {
        "openapi",
        "traffic",
        "observations",
        "source-status",
    }:
        raise AssessmentImportError("Unsupported assessment artifact kind")
    source_id = _text(source_id)
    if not isinstance(base_url, str):
        raise AssessmentImportError("Base URL must be text")
    base_url = _base_url(base_url) if base_url.strip() else ""
    document = _document(content)
    if kind == "source-status":
        return {
            "operations": [],
            "base_url": base_url,
            "source": {"id": source_id, **_source_status(document)},
        }
    if kind == "openapi":
        from buggy.tools.research.api_spec import parse_openapi_document

        try:
            records = parse_openapi_document(document)
        except (ValueError, TypeError, AttributeError, KeyError, RecursionError):
            raise AssessmentImportError("Malformed OpenAPI inventory") from None
        source_kind = "openapi"
    elif kind == "traffic":
        records = _traffic_records(document)
        source_kind = "traffic"
    else:
        records = _array(document.get("operations"))
        source_kind = "manual"
    operations = [_operation(record, base_url) for record in records]
    return {
        "operations": operations,
        "base_url": base_url,
        "source": {
            "id": source_id,
            "kind": source_kind,
            "status": "ok" if operations else "empty",
            "detail": "Local artifact inventory imported"
            if operations
            else "Local inventory is empty",
        },
    }


def _markdown(value: Any) -> str:
    text = html.escape(str(value), quote=False).replace("\r", " ").replace("\n", " ")
    for character in ("\\", "|", "`", "[", "]", "*", "_"):
        text = text.replace(character, "\\" + character)
    return text


def render_report(report: dict[str, Any]) -> str:
    """Render one ledger report/gaps page without IO or inferring global coverage.

    Completeness and counts come from the ledger's whole-assessment summary,
    never from the cases on this page. Missing completeness is incomplete.
    """
    report = _object(report)
    totals = _object(report.get("totals", {}))
    counts = _object(report.get("status_counts", {}))
    complete = "Complete" if report.get("complete") is True else "Incomplete"
    asvs = isinstance(report.get("catalog"), dict) and report["catalog"].get("standard") == "ASVS"
    notice = (
        report.get("baseline_description", "Reviewer-attested ASVS review")
        if asvs
        else "not full ASVS coverage."
    )
    lines = [
        "# ASVS application review" if asvs else "# Web/API assessment",
        "",
        f"Engagement: {_markdown(report.get('engagement_name', 'unspecified'))}",
        f"Baseline: {_markdown(report.get('baseline', 'minimum web/API'))}; {_markdown(notice)}",
        f"Assessment status: **{complete}**",
        "Completion concerns only this baseline and does not mean no vulnerabilities were found.",
        "",
        "## Totals (whole assessment)",
        "",
        "| Metric | Count |",
        "| --- | ---: |",
    ]
    metrics = _object(report.get("coverage", {})) if asvs else totals
    metric_names = (
        ("total", "applicable", "assessed", "remaining", "not_applicable")
        if asvs
        else ("operations", "cases", "sources", "source_gaps", "gaps", "untrusted")
    )
    for name in metric_names:
        lines.append(f"| {name.replace('_', ' ')} | {_markdown(metrics.get(name, 'unknown'))} |")
    if asvs:
        release = report["catalog"]
        lines.extend(
            [
                "",
                f"Application: {_markdown(report.get('asset', 'unknown'))}",
                f"Attribution: {_markdown(release['attribution'])}; {_markdown(release['license'])} ({_markdown(release['license_url'])}).",
                f"Source: {_markdown(release['source_url'])}",
                _markdown(report.get("notice", "")),
            ]
        )
    lines.extend(
        ["", "## Status counts (whole assessment)", "", "| Status | Count |", "| --- | ---: |"]
    )
    for status in ("untested", "pass", "fail", "blocked", "inconclusive", "not_applicable"):
        lines.append(f"| {_markdown(status)} | {_markdown(counts.get(status, 'unknown'))} |")
    lines.extend(["", "## Source gaps", ""])
    source_gaps = _array(report.get("source_gaps", []))
    for item in source_gaps:
        source = _object(item)
        description = "; ".join(str(source[key]) for key in ("reason", "detail") if source.get(key))
        lines.append(
            f"- {_markdown(source.get('source_id', source.get('id', 'unknown')))} "
            f"({_markdown(source.get('status', 'unknown'))}): {_markdown(description)}"
        )
    if not source_gaps:
        lines.append(
            "No source gaps listed in this report; this is not a claim of complete coverage."
        )
    key = "cases" if "cases" in report else "gaps"
    label = "cases" if key == "cases" else "case gaps"
    cases = _array(report.get(key, []))
    total = report.get("total", totals.get(key, "unknown"))
    lines.extend(
        [
            "",
            f"## {label.capitalize()} (page)",
            "",
            f"Showing {len(cases)} of {_markdown(total)} {label} "
            f"(offset {_markdown(report.get('offset', 0))}, limit {_markdown(report.get('limit', 'unknown'))}).",
            "This page is not the full inventory or a claim of full coverage; use the whole-assessment summary above.",
        ]
    )
    if report.get("has_more"):
        lines.append(f"Next offset: {_markdown(report.get('next_offset', 'unknown'))}.")
    lines.extend(
        [
            "",
            "| Case | Operation | Role | Control | Status | Evaluation | Reason | Evidence |",
            "| --- | --- | --- | --- | --- | --- | --- | --- |",
        ]
    )
    for item in cases:
        case = _object(item)
        evidence = ", ".join(
            str(_object(entry).get("path", "")) for entry in _array(case.get("evidence", []))
        )
        reason = case.get("reason", case.get("rationale", ""))
        if asvs and case.get("rationale"):
            reason = f"{reason} Recorded rationale: {case['rationale']}"
        cells = [
            case.get("case_id", "unknown"),
            f"{case.get('method', '')} {case.get('url', '')}",
            case.get("role", "unknown"),
            case.get("control_id", "unknown"),
            case.get("status", "unknown"),
            case.get("evaluation_mode") or "unassessed",
            reason,
            evidence,
        ]
        lines.append("| " + " | ".join(_markdown(cell) for cell in cells) + " |")
    return "\n".join(lines) + "\n"
