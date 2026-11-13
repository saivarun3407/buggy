"""Collect bounded, metadata-only sources for a best-effort local defensive review."""

from __future__ import annotations

import hashlib
import ipaddress
import re
from contextlib import closing
from typing import Any, Protocol

from buggy.sandbox_kernel.context_snapshot import (
    ContextSnapshotError,
    Snapshot,
    render_snapshot,
)
from buggy_core.utils.engagement_scope import is_valid_engagement_label

_KINDS = "Host Service Endpoint Finding Vulnerability CVE Misconfiguration Weakness".split()
_EXCLUDED = "Credential Secret Session User Account".split()
_ENUMS = {
    "severity": "critical high medium low informational".split(),
    "status": "open confirmed suspected validated resolved mitigated accepted closed false_positive unconfirmed".split(),
    "protocol": "tcp udp http https tls ssh dns icmp icmpv6 sctp".split(),
}
_FILTER = """MATCH (n {engagement: $engagement})
WHERE any(kind IN $safe_kinds WHERE kind IN labels(n))
AND none(kind IN $excluded_kinds WHERE kind IN labels(n))
"""
_ROWS = (
    _FILTER
    + """RETURN n.engagement AS engagement, n.key AS id,
head([kind IN $safe_kinds WHERE kind IN labels(n)]) AS kind,
coalesce(n.cve_id, n.cve) AS cve_id, coalesce(n.cwe_id, n.cwe) AS cwe_id,
n.severity AS severity, n.status AS status,
coalesce(n.hostname, n.ip, n.host) AS host, n.port AS port, n.protocol AS protocol
ORDER BY kind, id, elementId(n) LIMIT $max_rows"""
)


class _ReadStore(Protocol):
    def execute_read(
        self, cypher: str, params: dict[str, Any], *, engagement: str
    ) -> list[dict[str, Any]]: ...


class ContextExportError(ValueError):
    """Invalid input to a metadata-only source collector."""


def _validate(engagement: str, max_rows: int) -> None:
    if (
        type(engagement) is not str
        or not engagement.isprintable()
        or not is_valid_engagement_label(engagement)
    ):
        raise ContextExportError("engagement and graph_scope must be safe labels.")
    if type(max_rows) is not int or not 1 <= max_rows <= 1000:
        raise ContextExportError("max_rows must be an integer from 1 to 1000.")


def _match(value: Any, pattern: str, limit: int = 253) -> str | None:
    return (
        value
        if type(value) is str and len(value) <= limit and re.fullmatch(pattern, value)
        else None
    )


def _host(value: Any) -> str | None:
    if type(value) is not str or not value.isascii() or len(value) > 253 or "%" in value:
        return None
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        name = value.lower().removesuffix(".")
        label = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
        return _match(name, rf"{label}(?:\.{label})*") if re.search("[a-z]", name) else None


def _opaque(value: Any) -> str | None:
    if type(value) is int and 0 <= value < 2**63:
        value = str(value)
    if type(value) is not str or not 1 <= len(value) <= 4096:
        return None
    return "sha256:" + hashlib.sha256(value.encode("utf-8", errors="surrogatepass")).hexdigest()


def _project(row: dict[str, Any], engagement: str) -> dict[str, Any]:
    port = row.get("port")
    return {
        "engagement": engagement,
        "id": _opaque(row.get("id")),
        "kind": row["kind"],
        "cve_id": _match(row.get("cve_id"), r"CVE-[0-9]{4}-[0-9]{4,19}"),
        "cwe_id": _match(row.get("cwe_id"), r"CWE-[1-9][0-9]{0,8}"),
        **{
            key: row.get(key) if type(row.get(key)) is str and row[key] in allowed else None
            for key, allowed in _ENUMS.items()
        },
        "host": _host(row.get("host")),
        "port": port if type(port) is int and 1 <= port <= 65535 else None,
    }


def graph_source(
    store: _ReadStore, *, engagement: str, graph_scope: str, max_rows: int = 1000
) -> dict[str, Any]:
    """Return allowlisted node metadata from separate, best-effort count and row reads."""
    _validate(engagement, max_rows)
    _validate(graph_scope, max_rows)
    failed = {
        "engagement": engagement,
        "status": "error",
        "total": 0,
        "data": [],
        "error_code": "graph_read_failed",
    }
    params = {
        "engagement": graph_scope,
        "safe_kinds": _KINDS.copy(),
        "excluded_kinds": _EXCLUDED.copy(),
        "max_rows": max_rows,
    }
    try:
        counts = store.execute_read(
            _FILTER + "RETURN count(n) AS total", params, engagement=graph_scope
        )
        if type(counts) is not list or len(counts) != 1 or type(counts[0]) is not dict:
            return failed
        total = counts[0].get("total")
        if type(total) is not int or total < 0:
            return failed
        failed["total"] = total
        rows = store.execute_read(_ROWS, params, engagement=graph_scope)
        if type(rows) is not list or len(rows) > min(total, max_rows) or (total and not rows):
            return failed
        for row in rows:
            if (
                type(row) is not dict
                or type(row.get("engagement")) is not str
                or row["engagement"] != graph_scope
                or type(row.get("kind")) is not str
                or row["kind"] not in _KINDS
                or "labels" in row
            ):
                return failed
        return {
            "engagement": engagement,
            "status": "ok",
            "total": total,
            "data": [_project(row, engagement) for row in rows],
        }
    except Exception:
        return failed


def export_snapshot(
    local: dict[str, Any],
    *,
    include_graph: bool = False,
    graph_scope: str | None = None,
    messages: list | None = None,
    max_rows: int = 1000,
) -> Snapshot:
    if (
        type(local) is not dict
        or type(local.get("sources")) is not dict
        or type(include_graph) is not bool
    ):
        raise ContextExportError("Invalid local snapshot sources or graph selection.")
    engagement = local.get("engagement")
    if (
        type(engagement) is not str
        or _match(engagement, r"[A-Za-z0-9][A-Za-z0-9_-]{0,79}", 80) is None
    ):
        raise ContextExportError("Snapshot engagement must be a safe slug.")
    _validate(engagement, max_rows)
    sources = dict(local["sources"])
    try:
        render_snapshot(engagement, sources, max_rows=max_rows)
    except ContextSnapshotError as exc:
        raise ContextExportError(str(exc)) from exc
    sources["findings"] = {
        "engagement": engagement,
        "status": "unavailable" if include_graph else "not_requested",
        "data": [],
    }
    if include_graph and graph_scope is not None:
        _validate(graph_scope, max_rows)
        try:
            from buggy.middleware.kg_internal.store import KGStore

            with closing(KGStore.from_env()) as store:
                sources["findings"] = graph_source(
                    store, engagement=engagement, graph_scope=graph_scope, max_rows=max_rows
                )
        except Exception:
            sources["findings"] = {"engagement": engagement, "status": "error", "data": []}
    sources["skills"] = skill_source(engagement, messages, max_rows=max_rows)
    try:
        return render_snapshot(engagement, sources, max_rows=max_rows)
    except ContextSnapshotError as exc:
        raise ContextExportError(str(exc)) from exc


def skill_source(engagement: str, messages: list | None, *, max_rows: int = 1000) -> dict[str, Any]:
    """Return first-seen unique identifiers while counting every observed load request."""
    _validate(engagement, max_rows)
    if messages is not None and type(messages) is not list:
        raise ContextExportError("messages must be a list or None.")
    total, names = 0, {}
    component = r"[A-Za-z0-9][A-Za-z0-9_.-]{0,79}"
    try:
        for message in messages or []:
            calls = (
                message.get("tool_calls", [])
                if type(message) is dict
                else getattr(message, "tool_calls", [])
            )
            if type(calls) is not list:
                continue
            for call in calls:
                if (
                    type(call) is not dict
                    or type(call.get("name")) is not str
                    or call["name"] != "load_skill"
                ):
                    continue
                total += 1
                args = call.get("args")
                value = args.get("name_or_path") if type(args) is dict else None
                name = _match(value, r"[A-Za-z0-9][A-Za-z0-9_-]{0,79}", 80) or _match(
                    value, rf"/skills/(?:{component}/)*{component}", 200
                )
                if name is not None and len(names) < max_rows:
                    names[name] = None
    except Exception:
        return {
            "engagement": engagement,
            "status": "error",
            "total": total,
            "data": [],
            "error_code": "skill_metadata_failed",
        }
    return {
        "engagement": engagement,
        "status": "not_requested" if messages is None else "ok",
        "total": total,
        "data": [{"name_or_path": name, "status": "requested"} for name in names],
    }
