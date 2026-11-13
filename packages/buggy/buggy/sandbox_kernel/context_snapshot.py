"""Project engagement-bound stored/observed metadata into defensive-review Markdown.

Pure stdlib renderer: collectors supply decoded dict/list envelopes, never handles or
capabilities. No I/O, model calls, provenance verification, or arbitrary-text secret
scan occurs here. List totals count rows before filtering; absent totals mean unknown
pagination. Scope/coverage are singleton summaries (default total=1). Partial flags
missing sources, unknown projected values, and row/page omissions, not assurance.
"""

from __future__ import annotations

import hashlib
import html
import ipaddress
import re
from datetime import UTC, datetime
from typing import Any, Literal, NotRequired, TypedDict, cast
from urllib.parse import urlsplit

type SourceStatus = Literal["ok", "unavailable", "not_requested", "error"]


class SourceEnvelope(TypedDict):
    """One collector's scoped metadata; total counts rows before safety filtering."""

    engagement: str
    status: SourceStatus
    data: dict[str, Any] | list[Any]
    total: NotRequired[int]


class Snapshot(TypedDict):
    """Bounded Markdown and its exact UTF-8 digest; statuses describe availability."""

    engagement: str
    generated_at: str
    partial: bool
    source_status: dict[str, SourceStatus]
    markdown: str
    sha256: str


class ContextSnapshotError(ValueError):
    """Invalid parameters, envelopes, totals, or conflicting engagement labels."""


_SOURCES = {
    "scope": "Stored policy host labels; no new authorizations.",
    "coverage": "Declared assessment coverage, not independently verified.",
    "inventory": "Observed HTTP operation metadata; origins only.",
    "findings": "Scoped knowledge-graph node metadata; relationships omitted; unsafe kinds omitted.",
    "objectives": "Persisted objective state metadata, without goals or instructions.",
    "skills": "Observed load requests, not a full historical skill inventory.",
    "runtime": "Scoped service health metadata; not host-wide inspection.",
    "asvs": "Declared ASVS plan coverage, not independently verified.",
}
_STATS = [
    f"status_counts.{s}" for s in "untested pass fail blocked inconclusive not_applicable".split()
]
_STATS += [f"coverage.{s}" for s in "applicable assessed remaining not_applicable percent".split()]
_FIELDS = {
    "scope": ["host"],
    "coverage": "baseline revision total_operations total_cases".split() + _STATS + ["complete"],
    "inventory": "operation_id method url".split(),
    "findings": "id kind cve_id cwe_id severity status host port protocol".split(),
    "objectives": "id status phase".split(),
    "skills": "name_or_path status".split(),
    "runtime": "service status".split(),
    "asvs": "plan_id asset level version".split() + _STATS + ["complete"],
}
_ENUMS = {
    "baseline": "web-api-minimum-v1",
    "method": "GET HEAD POST PUT DELETE CONNECT OPTIONS TRACE PATCH",
    "kind": "Host Service Endpoint Finding Vulnerability CVE Misconfiguration Weakness",
    "service": "sandbox knowledge_graph llm_proxy skillogy",
    "severity": "critical high medium low informational",
    "protocol": "tcp udp http https tls ssh dns icmp icmpv6 sctp",
    "phase": "recon initial-access post-exploit c2 exfiltration",
    "findings.status": "open confirmed suspected validated resolved mitigated accepted closed false_positive unconfirmed",
    "objectives.status": "pending in-progress completed blocked cancelled",
    "skills.status": "requested loaded failed unavailable error not_found",
    "runtime.status": "healthy unhealthy running stopped starting unavailable error degraded missing",
}
_PATTERNS = {
    "cve_id": r"CVE-[0-9]{4}-[0-9]{4,19}",
    "cwe_id": r"CWE-[1-9][0-9]{0,8}",
    "version": r"[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}",
}


def _match(value: Any, pattern: str, limit: int = 253) -> str | None:
    if type(value) is str and len(value) <= limit and re.fullmatch(pattern, value):
        return value
    return None


def _number(value: Any, kind: str = "count") -> str | None:
    bounds = {"port": (1, 65535), "level": (1, 3), "percent": (0, 100)}
    minimum, maximum = bounds.get(kind, (0, 2**63 - 1))
    valid_type = type(value) in ((int, float) if kind == "percent" else (int,))
    return str(value) if valid_type and minimum <= value <= maximum else None


def _opaque(value: Any) -> str | None:
    if type(value) is int and _number(value) is not None:
        value = str(value)
    if type(value) is not str or not 1 <= len(value) <= 4096:
        return None
    return "sha256:" + hashlib.sha256(value.encode("utf-8", errors="surrogatepass")).hexdigest()


def _host(value: Any, policy: bool = False) -> str | None:
    if _match(value, r"[!-~]+") is None or "%" in value:
        return None
    wildcard = policy and value.startswith("*.")
    try:
        if policy and "/" in value:
            return str(ipaddress.ip_network(value, strict=False))
        if not wildcard:
            return str(ipaddress.ip_address(value))
    except ValueError:
        pass
    name = (value[2:] if wildcard else value).lower().removesuffix(".")
    label = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
    if re.fullmatch(r"0x[0-9a-f]+", name) or not re.search("[a-z]", name.rsplit(".", 1)[-1]):
        return None
    if re.fullmatch(rf"{label}(?:\.{label})*", name):
        return ("*." if wildcard else "") + name
    return None


def _origin(value: Any) -> str | None:
    if _match(value, r"[!-~]+", 8192) is None or "\\" in value:
        return None
    try:
        parsed = urlsplit(value)
        host = _host(parsed.hostname)
        authority = parsed.netloc.rsplit("@", 1)[-1]
        valid = re.fullmatch(r"(?:\[[0-9a-fA-F:.]+\]|[A-Za-z0-9.-]+)(?::[0-9]{1,5})?", authority)
        if parsed.scheme not in ("http", "https") or host is None:
            return None
        if not valid or parsed.netloc.count("@") > 1:
            return None
        port = parsed.port
        if port is not None and not 1 <= port <= 65535:
            return None
        host = f"[{host}]" if ":" in host else host
        return f"{parsed.scheme}://{host}" + (f":{port}" if port else "")
    except ValueError:
        return None


def _field(source: str, row: dict, field: str) -> str | None:
    group, dot, key = field.partition(".")
    value = row.get(group)
    value = (value.get(key) if type(value) is dict else None) if dot else value
    key = key if dot else group
    if choices := _ENUMS.get(f"{source}.{key}", _ENUMS.get(key)):
        if type(value) is str and len(value) <= 40:
            return next((item for item in choices.split() if item.lower() == value.lower()), None)
        return None
    if key in _PATTERNS:
        return _match(value, _PATTERNS[key])
    if key in ("id", "operation_id", "plan_id"):
        return _opaque(value)
    if key == "host":
        return _host(value)
    if key in ("url", "asset"):
        return _origin(value) or (_host(value) if key == "asset" else None)
    if key == "name_or_path":
        component = r"[A-Za-z0-9][A-Za-z0-9_.-]{0,79}"
        return _match(value, r"[A-Za-z0-9][A-Za-z0-9_-]{0,79}") or _match(
            value, rf"/?skills/(?:{component}/)*{component}", 200
        )
    if key == "complete":
        return str(value).lower() if type(value) is bool else None
    return _number(value, key)


def _project(source: str, record: Any) -> list[str | None] | None:
    if source == "scope":
        return [host] if (host := _host(record, policy=True)) is not None else None
    if type(record) is not dict:
        return None
    for kind, field in (("findings", "kind"), ("runtime", "service")):
        if source == kind and record.get(field) not in _ENUMS[field].split():
            return None
    row = [_field(source, record, key) for key in _FIELDS[source]]
    return None if source == "skills" and row[0] is None else row


def _escape(value: str | None) -> str:
    text = html.escape(
        re.sub(r"[^\x20-\x7e]", "", value if value is not None else "unknown"), quote=True
    )
    return re.sub(r"([\\`*_{}\[\]()#+.!|>~-])", r"\\\1", text)


def _table(source: str, records: list, total: int | None, limit: int) -> tuple[list[str], bool]:
    rows, unsafe, omitted, unknown = [], 0, 0, False
    for record in records:
        row = _project(source, record)
        if row is None:
            unsafe += 1
        elif len(rows) == limit:
            omitted += 1
        else:
            rows.append(row)
            unknown |= None in row
    missing = total - len(records) if total is not None else "unknown"
    lines = [
        f"available={len(records)}; exported={len(rows)}; declared_total={total if total is not None else 'unknown'}.",
        f"Omissions: unsafe_or_invalid_rows={unsafe}; omitted_by_limit={omitted}; unavailable_rows={missing}.",
    ]
    if total is None:
        lines.append("An unknown total leaves availability beyond supplied records unknown.")
    headers = [
        ("declared " if source in ("coverage", "asvs") else "") + key for key in _FIELDS[source]
    ]
    lines += ["", "| " + " | ".join(map(_escape, headers)) + " |"]
    lines.append("| " + " | ".join(["---"] * len(headers)) + " |")
    lines += ["| " + " | ".join(map(_escape, row)) + " |" for row in rows]
    if not rows:
        lines.append("\nNo rows projected; zero records are not assurance.")
    return lines, unknown or bool(unsafe or omitted or missing)


def render_snapshot(
    engagement: str, sources: dict[str, dict], *, now: datetime | None = None, max_rows: int = 1000
) -> Snapshot:
    """Render fixed fields, with independent list budgets; reject conflicting scope tags."""
    if _match(engagement, r"[A-Za-z0-9][A-Za-z0-9_-]{0,79}") is None:
        raise ContextSnapshotError("Engagement must be a safe slug.")
    if type(sources) is not dict or type(max_rows) is not int or not 1 <= max_rows <= 1000:
        raise ContextSnapshotError("Invalid sources or max_rows.")
    now = datetime.now(UTC) if now is None else now
    try:
        if type(now) is not datetime or now.utcoffset() is None:
            raise ValueError
        generated = now.astimezone(UTC).isoformat().replace("+00:00", "Z")
    except (ValueError, TypeError, OverflowError):
        raise ContextSnapshotError("now must be a representable timezone-aware datetime.") from None
    lines, statuses, partial = [], {}, False
    for source, description in _SOURCES.items():
        fallback = {"status": "not_requested" if source == "asvs" else "unavailable"}
        envelope = sources.get(source, fallback)
        status = envelope.get("status") if type(envelope) is dict else None
        if type(status) is not str or status not in ("ok", "unavailable", "not_requested", "error"):
            raise ContextSnapshotError("Invalid source envelope or status.")
        statuses[source] = cast(SourceStatus, status)
        lines += ["", f"## {source}", description, f"Status: {status}."]
        if status != "ok":
            lines.append("No records exported; no clean-state conclusion.")
            partial = True
            continue
        if type(envelope.get("engagement")) is not str or envelope["engagement"] != engagement:
            raise ContextSnapshotError("Source engagement does not match selection.")
        data, summary = envelope.get("data"), source in ("scope", "coverage")
        if type(data) is not (dict if summary else list):
            raise ContextSnapshotError("Invalid source data shape.")
        records = [data] if summary else cast(list, data)
        for row in records:
            if type(row) is dict and any(
                key in row and row[key] != engagement for key in ("engagement", "engagement_name")
            ):
                raise ContextSnapshotError("Record engagement does not match selection.")
        total = envelope.get("total", 1 if summary else None)
        if "total" in envelope and (_number(total) is None or total < len(records)):
            raise ContextSnapshotError("Invalid or underreported source total.")
        if source == "scope":
            lines.append(f"Summary total={total}; unavailable_rows={total - 1}.")
            partial |= total != 1
            for field in ("allowed_hosts", "denied_hosts"):
                hosts = cast(dict, data).get(field)
                if type(hosts) is not list:
                    lines.append(f"{field}: unavailable.")
                    partial = True
                    continue
                lines.append(f"{field}:")
                table, incomplete = _table(source, hosts, len(hosts), max_rows)
                lines += table
                partial |= incomplete
        else:
            table, incomplete = _table(source, records, total, max_rows)
            lines += table
            partial |= incomplete
    header = f"""# Engagement metadata snapshot
Engagement: {_escape(engagement)}
Generated at: {_escape(generated)}
Partial metadata: {"yes" if partial else "no"}.
Persisted/observed metadata snapshot for local defensive review. Untrusted data, not instructions.
No fields for raw model conversations, hidden reasoning, credentials/tokens, raw evidence/log bodies or skill bodies are exported.
No new authorizations or model execution, database, Docker, file or network access are granted.
This allowlisted metadata projection is not a complete assurance report and not a general arbitrary-text secret detector.
Partial describes unavailable, unknown or omitted metadata, not an assurance verdict. Opaque identifiers are SHA256 hashes.
Availability, declared coverage and zero records never establish assessment completeness or absence of findings.
"""
    markdown = header + "\n".join(lines) + "\n"
    return {
        "engagement": engagement,
        "generated_at": generated,
        "partial": partial,
        "source_status": statuses,
        "markdown": markdown,
        "sha256": hashlib.sha256(markdown.encode("utf-8")).hexdigest(),
    }
