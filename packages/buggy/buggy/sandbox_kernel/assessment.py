"""Artifact-only assessment ledger; no target requests or command execution."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import sqlite3
import stat
from collections.abc import Iterator
from contextlib import ExitStack, closing, contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any
from urllib.parse import parse_qsl, quote, urlsplit, urlunsplit


class AssessmentError(ValueError):
    """Invalid assessment input or untrustworthy ledger state."""


class AssessmentConflictError(AssessmentError):
    """The caller's expected revision is stale."""


_SCHEMA_VERSION = 1
_BASELINE = "web-api-minimum-v1"
_PROFILES = {"external", "authenticated", "source-assisted"}
_SOURCE_KINDS = {"openapi", "traffic", "source", "manual", "osint"}
_SOURCE_STATUSES = {"ok", "empty", "error", "unavailable", "mock"}
_CONTROLS = ("http.nosniff", "http.hsts", "auth.access-control", "source.authorization")
_STATUSES = ("untested", "pass", "fail", "blocked", "inconclusive", "not_applicable")
_MUTATIONS = {
    "initialize",
    "import",
    "access",
    "record",
    "check_headers",
    "asvs_init",
    "asvs_record",
}
_ACTIONS = _MUTATIONS | {
    "inventory",
    "next",
    "report",
    "gaps",
    "scenario_catalog",
    "evaluate_scenario",
    "prioritize_kev",
    "asvs_catalog",
    "asvs_report",
    "asvs_next",
    "asvs_list",
    "context_sources",
}
_TOKEN = re.compile(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+")


def _dump(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _json_object(raw: str | bytes) -> dict[str, Any]:
    def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result = {}
        for key, value in pairs:
            if key in result:
                raise AssessmentError("Duplicate JSON fields are not allowed")
            result[key] = value
        return result

    def invalid_constant(value: str) -> Any:
        raise AssessmentError("Non-finite JSON values are not allowed")

    try:
        result = json.loads(raw, object_pairs_hook=unique, parse_constant=invalid_constant)
        if not isinstance(result, dict):
            raise AssessmentError("JSON must contain an object")
        return result
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise AssessmentError("Invalid JSON object") from exc


def _sha(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _identifier(prefix: str, *parts: str) -> str:
    return prefix + "_" + _sha(_dump(parts).encode())


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _text(
    value: Any, field: str, maximum: int = 4096, *, multiline: bool = False, trim: bool = True
) -> str:
    allowed_controls = "\n\r\t" if multiline else ""
    if (
        not isinstance(value, str)
        or not value.strip()
        or len(value) > maximum
        or any(
            (ord(char) < 32 and char not in allowed_controls) or ord(char) == 127 for char in value
        )
    ):
        raise AssessmentError(f"{field} must be nonempty text without control characters")
    return value.strip() if trim else value


def _integer(value: Any, field: str, minimum: int, maximum: int | None = None) -> int:
    if type(value) is not int or value < minimum or (maximum is not None and value > maximum):
        raise AssessmentError(f"Invalid {field}")
    return value


def _boolean(value: Any, field: str) -> bool:
    if type(value) is not bool:
        raise AssessmentError(f"{field} must be a boolean")
    return value


def _roles(value: Any, field: str) -> list[str]:
    if not isinstance(value, list):
        raise AssessmentError(f"{field} must be a list")
    return sorted({_text(role, field, 128) for role in value})


def _timestamp(value: Any, field: str, allow_future: bool = False) -> str:
    value = _text(value, field, 80)
    if not re.fullmatch(
        r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})", value
    ):
        raise AssessmentError(f"{field} must be an ISO-8601 timestamp with a timezone")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if not allow_future and parsed > datetime.now(timezone.utc) + timedelta(minutes=5):
            raise ValueError("future timestamp")
        return parsed.astimezone(timezone.utc).isoformat()
    except (ValueError, OverflowError) as exc:
        raise AssessmentError(f"Invalid {field}") from exc


def _host(value: Any) -> str:
    value = _text(value, "host", 253)
    if value.startswith("[") and value.endswith("]"):
        value = value[1:-1]
    if "%" in value:
        raise AssessmentError("Host zone identifiers and escapes are not allowed")
    try:
        return ipaddress.ip_address(value).compressed.lower()
    except ValueError:
        pass
    try:
        value = value.removesuffix(".").encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise AssessmentError("Invalid host") from exc
    if len(value) > 253 or not all(
        re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in value.split(".")
    ):
        raise AssessmentError("Hosts must be exact DNS/IP names or leading '*.domain' wildcards")
    return value


def _scope(value: Any, field: str = "allowed_hosts") -> list[str]:
    if not isinstance(value, list) or (not value and field == "allowed_hosts"):
        qualifier = "nonempty " if field == "allowed_hosts" else ""
        raise AssessmentError(f"{field} must be a {qualifier}list")
    hosts = set()
    for item in value:
        item = _text(item, field, 255)
        if field == "denied_hosts" and "/" in item:
            try:
                if "%" in item or not re.fullmatch(r"[0-9]+", item.partition("/")[2]):
                    raise ValueError("CIDR prefix required")
                hosts.add(str(ipaddress.ip_network(item, strict=False)))
            except ValueError as exc:
                raise AssessmentError("denied_hosts contains an invalid CIDR exclusion") from exc
            continue
        wildcard = item.startswith("*.")
        host = _host(item[2:] if wildcard else item)
        if wildcard:
            try:
                ipaddress.ip_address(host)
            except ValueError:
                pass
            else:
                raise AssessmentError("IP address wildcards are not allowed")
        hosts.add(("*." if wildcard else "") + host)
    return sorted(hosts)


def _in_scope(host: str, hosts: list[str]) -> bool:
    for pattern in hosts:
        if "/" in pattern:
            try:
                address = ipaddress.ip_address(host)
            except ValueError:
                continue
            network = ipaddress.ip_network(pattern)
            if address in network:
                return True
            if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
                if address.ipv4_mapped in network:
                    return True
        elif host.endswith("." + pattern[2:]) if pattern.startswith("*.") else host == pattern:
            return True
    return False


def _method(value: Any) -> str:
    value = _text(value, "method", 32)
    if not _TOKEN.fullmatch(value):
        raise AssessmentError("Invalid HTTP method")
    return value.upper()


def _url(value: Any, query_names: list[str] | None = None) -> str:
    text = _text(value, "url", 16384)
    if text != value or any(char.isspace() for char in text) or "\\" in text:
        raise AssessmentError("URLs cannot contain whitespace or backslashes")
    if re.search(r"%(?![0-9A-Fa-f]{2})", text):
        raise AssessmentError("URLs must use valid percent escapes")
    try:
        parts = urlsplit(value)
        if parts.scheme.lower() not in {"http", "https"} or not parts.netloc or not parts.hostname:
            raise ValueError("absolute HTTP(S) URL required")
        if parts.username is not None or parts.password is not None or "@" in parts.netloc:
            raise ValueError("userinfo is forbidden")
        if parts.fragment:
            raise ValueError("fragments are not assessment operations")
        host = _host(parts.hostname)
        port = parts.port
        if port is not None and not 1 <= port <= 65535:
            raise ValueError("invalid port")
        scheme = parts.scheme.lower()
        authority = f"[{host}]" if ":" in host else host
        if port is not None and port != {"http": 80, "https": 443}[scheme]:
            authority += f":{port}"
        names = {
            _text(name, "query parameter name", 512, trim=False)
            for name, _ in parse_qsl(
                parts.query, keep_blank_values=True, max_num_fields=2048, errors="strict"
            )
        }
        names.update(query_names or [])
        query = "&".join(quote(name, safe="") for name in sorted(names))
        return urlunsplit((scheme, authority, parts.path or "/", query, ""))
    except ValueError as exc:
        raise AssessmentError(
            "Invalid operation URL (absolute HTTP(S), no userinfo required)"
        ) from exc


def _parameters(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        raise AssessmentError("parameters must be a list")
    result = {}
    for item in value:
        if not isinstance(item, dict):
            raise AssessmentError("Each parameter must be an object")
        parameter = {
            "name": _text(item.get("name"), "parameter name", 512, trim=False),
            "in": _text(item.get("in"), "parameter location", 32),
        }
        if parameter["in"] not in {"query", "path", "header", "cookie", "body", "formData"}:
            raise AssessmentError("Invalid parameter location")
        if "required" in item:
            parameter["required"] = _boolean(item["required"], "parameter required")
        result[_dump(parameter)] = parameter
    return [result[key] for key in sorted(result)]


def _operation(
    item: Any, base_url: Any, allowed_hosts: list[str], denied_hosts: list[str]
) -> dict[str, Any]:
    if not isinstance(item, dict):
        raise AssessmentError("Each operation must be an object")
    parameters = _parameters(item.get("parameters", []))
    query_names = [p["name"] for p in parameters if p["in"] == "query"]
    if "url" in item:
        url = _url(item["url"], query_names)
    else:
        path = _text(item.get("path"), "path", 16384)
        if not path.startswith("/") or path.startswith("//"):
            raise AssessmentError("Operation paths must begin with a single '/'")
        base = _url(item.get("base_url", base_url))
        if urlsplit(base).query:
            raise AssessmentError("base_url cannot contain query parameters")
        url = _url(base.rstrip("/") + path, query_names)
    host = _host(urlsplit(url).hostname)
    if _in_scope(host, denied_hosts):
        raise AssessmentError(f"Operation host {host!r} is excluded by denied_hosts")
    if not _in_scope(host, allowed_hosts):
        raise AssessmentError(f"Operation host {host!r} is outside allowed_hosts")
    method = _method(item.get("method"))
    return {
        "operation_id": _identifier("op", method, url),
        "url": url,
        "method": method,
        "parameters": parameters,
        "provenance": [],
    }


def _initialize_payload(payload: dict[str, Any]) -> dict[str, Any]:
    name = _text(payload.get("engagement_name"), "engagement_name", 80)
    if name != payload["engagement_name"] or not re.fullmatch(
        r"[A-Za-z0-9][A-Za-z0-9_-]{0,79}", name
    ):
        raise AssessmentError("engagement_name must be a safe slug")
    profile = payload.get("profile")
    if not isinstance(profile, str) or profile not in _PROFILES:
        raise AssessmentError("Invalid assessment profile")
    return {
        "engagement_name": name,
        "profile": profile,
        "allowed_hosts": _scope(payload.get("allowed_hosts")),
        "denied_hosts": _scope(payload.get("denied_hosts", []), "denied_hosts"),
        "required_roles": _roles(
            payload.get("required_roles", ["authenticated"]), "required_roles"
        ),
        "available_roles": _roles(payload.get("available_roles", []), "available_roles"),
        "source_available": _boolean(payload.get("source_available", False), "source_available"),
    }


def _headers(value: Any) -> dict[str, list[str]]:
    if not isinstance(value, dict):
        raise AssessmentError("Artifact headers must be an object")
    headers: dict[str, list[str]] = {}
    for name, entries in value.items():
        if not isinstance(name, str) or not _TOKEN.fullmatch(name):
            raise AssessmentError("Invalid HTTP header name")
        entries = [entries] if isinstance(entries, str) else entries
        if not isinstance(entries, list) or not entries:
            raise AssessmentError("HTTP header values must be strings or nonempty string lists")
        for entry in entries:
            if not isinstance(entry, str) or any(
                ord(c) < 32 and c != "\t" or ord(c) == 127 for c in entry
            ):
                raise AssessmentError("Invalid HTTP header value")
            headers.setdefault(name.lower(), []).append(entry.strip())
    return headers


def _header_result(control: str, url: str, artifact: dict[str, Any]) -> tuple[str, str]:
    code = _integer(artifact.get("status_code"), "artifact status_code", 100, 599)
    headers = _headers(artifact.get("headers"))
    if not 200 <= code < 300:
        return (
            "inconclusive",
            f"HTTP {code} is not a successful target response; no header coverage is credited.",
        )
    challenge = (
        artifact.get("error")
        or artifact.get("challenge")
        or artifact.get("is_challenge")
        or artifact.get("is_response") is False
        or headers.get("www-authenticate")
        or headers.get("proxy-authenticate")
        or any("challenge" in value.lower() for value in headers.get("cf-mitigated", []))
        or any(
            value.lower() in {"captcha", "challenge"}
            for value in headers.get("x-amzn-waf-action", [])
        )
    )
    if challenge:
        return (
            "inconclusive",
            "The supplied artifact indicates a challenge, error, or non-response, not an assessed target response.",
        )
    if control == "http.hsts" and urlsplit(url).scheme != "https":
        return "not_applicable", "HSTS applies only to HTTPS; this supplied response is for HTTP."
    if control == "http.nosniff":
        values = headers.get("x-content-type-options", [])
        passed = len(values) == 1 and values[0].lower() == "nosniff"
        reason = (
            "A valid nosniff response header is present."
            if passed
            else "A valid nosniff response header is missing or ambiguous."
        )
    else:
        values = headers.get("strict-transport-security", [])
        age = (
            []
            if len(values) != 1
            else [
                directive.strip()
                for directive in values[0].split(";")
                if directive.split("=", 1)[0].strip().lower() == "max-age"
            ]
        )
        match = (
            re.fullmatch(r'max-age\s*=\s*(?:([0-9]+)|"([0-9]+)")', age[0], re.IGNORECASE)
            if len(age) == 1
            else None
        )
        passed = bool(match and (match[1] or match[2]).strip("0"))
        reason = (
            "A positive HSTS max-age is present."
            if passed
            else "A positive, unambiguous HSTS max-age is missing."
        )
    return ("pass" if passed else "fail"), "Supplied-artifact check: " + reason


_PATH_COMPONENT = re.compile(r"[A-Za-z0-9_.-]+")


def _relative_path(value: Any) -> PurePosixPath:
    text = _text(value, "evidence_path")
    path = PurePosixPath(text)
    if (
        text != value
        or "\\" in text
        or path.is_absolute()
        or PureWindowsPath(text).drive
        or ".." in path.parts
        or not path.parts
        or any(not _PATH_COMPONENT.fullmatch(part) for part in path.parts)
    ):
        raise AssessmentError("Evidence paths must be workspace-relative without traversal")
    if path.parent == PurePosixPath("assessment") and path.name in {
        "coverage.sqlite3",
        "coverage.sqlite3-journal",
        "coverage.sqlite3-wal",
        "coverage.sqlite3-shm",
    }:
        raise AssessmentError("The ledger cannot serve as its own evidence")
    return path


@contextmanager
def _evidence_directory(parent: int, component: str) -> Iterator[int]:
    if component in {"", ".", ".."} or not _PATH_COMPONENT.fullmatch(component):
        raise AssessmentError("Invalid evidence directory component")
    descriptor = os.open(
        os.path.basename(component), os.O_RDONLY | os.O_NOFOLLOW | os.O_DIRECTORY, dir_fd=parent
    )
    try:
        yield descriptor
    finally:
        os.close(descriptor)


def _validate_outcome(value: dict[str, Any]) -> None:
    status, mode, evidence = value["status"], value["evaluation_mode"], value["evidence"]
    if status not in _STATUSES or not isinstance(evidence, list):
        raise AssessmentError("Corrupt case outcome")
    _text(value["reason"], "case reason", 16384, multiline=True)
    if status == "untested":
        if mode is not None or evidence or value["rationale"]:
            raise AssessmentError("Untested cases cannot contain assessment results")
    else:
        _text(value["rationale"], "case rationale", 8192, multiline=True)
        if mode not in {"attested", "deterministic"}:
            raise AssessmentError("Corrupt evaluation mode")
        if (status in {"pass", "fail"} or mode == "deterministic") and not evidence:
            raise AssessmentError("Recorded outcomes are missing required evidence")
    paths = []
    for item in evidence:
        if (
            set(item) != {"path", "sha256", "size_bytes"}
            or str(_relative_path(item["path"])) != item["path"]
        ):
            raise AssessmentError("Corrupt evidence reference")
        if not re.fullmatch(r"[0-9a-f]{64}", item["sha256"]):
            raise AssessmentError("Corrupt evidence hash")
        _integer(item["size_bytes"], "evidence size_bytes", 1)
        paths.append(item["path"])
    if paths != sorted(set(paths)):
        raise AssessmentError("Corrupt or duplicate evidence paths")


def _page(items: list[dict[str, Any]], payload: dict[str, Any], key: str) -> dict[str, Any]:
    offset = _integer(payload.get("offset", 0), "offset", 0)
    limit = _integer(payload.get("limit", 50), "limit", 1, 1000)
    page = items[offset : offset + limit]
    has_more = offset + len(page) < len(items)
    return {
        "total": len(items),
        key: page,
        "offset": offset,
        "limit": limit,
        "next_offset": offset + len(page) if has_more else None,
        "has_more": has_more,
    }


class AssessmentStore:
    """Workspace-local ledger with serialized, revision-checked dispatches."""

    def __init__(self, workspace: str | Path) -> None:
        try:
            requested = Path(workspace)
            if requested.is_symlink():
                raise AssessmentError("workspace must not be a symlink")
            self.workspace = requested.resolve(strict=True)
            if not self.workspace.is_dir():
                raise AssessmentError("workspace must be an existing directory")
        except AssessmentError:
            raise
        except (OSError, TypeError, ValueError) as exc:
            raise AssessmentError("workspace must be an existing directory") from exc
        self._directory = self.workspace / "assessment"
        self._database = self._directory / "coverage.sqlite3"

    def dispatch(self, action: str, payload: dict[str, Any]) -> dict[str, Any]:
        if not isinstance(action, str) or action not in _ACTIONS:
            raise AssessmentError("Unknown assessment action")
        if not isinstance(payload, dict):
            raise AssessmentError("payload must be an object")
        if action == "context_sources":
            return self._context_sources(payload)
        if action == "scenario_catalog":
            from buggy.sandbox_kernel.threat_scenarios import list_scenarios

            return list_scenarios()
        if action == "asvs_catalog":
            from buggy.sandbox_kernel.asvs_catalog import ASVSCatalogError, catalog

            try:
                return catalog(
                    payload.get("level", 2),
                    offset=payload.get("offset", 0),
                    limit=payload.get("limit", 50),
                )
            except ASVSCatalogError as exc:
                raise AssessmentError(str(exc)) from exc
        expected = payload.get("expected_revision")
        if expected is not None:
            expected = _integer(expected, "expected_revision", 0)
        initial = _initialize_payload(payload) if action == "initialize" else {}
        try:
            if self.workspace.resolve(strict=True) != self.workspace:
                raise AssessmentError("workspace has moved or become a symlink")
            if self._directory.is_symlink() or self._database.is_symlink():
                raise AssessmentError("Assessment storage cannot be a symlink")
            existed = self._database.exists()
            if existed and not self._database.is_file():
                raise AssessmentError("Assessment storage must be a regular file")
            if not existed:
                if not initial:
                    raise AssessmentError("Assessment is not initialized")
                if expected not in (None, 0):
                    raise AssessmentConflictError("Expected revision does not match revision 0")
                self._directory.mkdir(mode=0o700, exist_ok=True)
            with (
                closing(sqlite3.connect(self._database, timeout=30, isolation_level=None)) as db,
                db,
            ):
                db.execute("BEGIN IMMEDIATE")
                tables = {
                    row[0]
                    for row in db.execute(
                        "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'"
                    )
                }
                version = db.execute("PRAGMA user_version").fetchone()[0]
                new = not tables and version == 0 and not existed and bool(initial)
                if new:
                    state = initial | {
                        "schema_version": _SCHEMA_VERSION,
                        "baseline": _BASELINE,
                        "workspace": str(self.workspace),
                        "revision": 0,
                        "operations": {},
                        "cases": {},
                        "sources": {},
                        "created_at": _now(),
                    }
                else:
                    if tables != {"ledger", "history"} or version != _SCHEMA_VERSION:
                        raise AssessmentError(
                            "Corrupt or incompatible assessment schema; refusing to reset"
                        )
                    state = self._load(db)
                if action in _MUTATIONS and expected is not None and expected != state["revision"]:
                    raise AssessmentConflictError(
                        f"Expected revision {expected}, current revision is {state['revision']}"
                    )
                before = None if new else _dump(state)
                result: dict[str, Any] = {}
                if action == "initialize":
                    for field in (
                        "engagement_name",
                        "profile",
                        "allowed_hosts",
                        "denied_hosts",
                        "required_roles",
                    ):
                        if state[field] != initial[field]:
                            raise AssessmentError(f"Immutable engagement {field} does not match")
                    result = initial.copy()
                elif action == "import":
                    result = self._import(state, payload)
                elif action == "inventory":
                    result = _page(list(state["operations"].values()), payload, "operations")
                elif action == "access":
                    access = {
                        "available_roles": _roles(
                            payload.get("available_roles"), "available_roles"
                        ),
                        "source_available": _boolean(
                            payload.get("source_available"), "source_available"
                        ),
                    }
                    state.update(access)
                    result = access.copy()
                elif action in {"next", "report", "gaps"}:
                    result = self._report(db, state, payload, action)
                elif action == "record":
                    result = self._record(state, payload)
                elif action in {"evaluate_scenario", "prioritize_kev"}:
                    result = self._evaluate_threat(state, payload, action)
                elif action == "check_headers":
                    result = self._check_headers(state, payload)
                elif action.startswith("asvs_"):
                    result = self._asvs_dispatch(state, payload, action)
                if before != _dump(state):
                    if new:
                        db.execute(
                            "CREATE TABLE ledger (id INTEGER PRIMARY KEY CHECK (id = 1), "
                            "schema_version INTEGER NOT NULL, revision INTEGER NOT NULL, "
                            "state TEXT NOT NULL, sha256 TEXT NOT NULL)"
                        )
                        db.execute(
                            "CREATE TABLE history (revision INTEGER PRIMARY KEY, action TEXT NOT NULL, "
                            "changed_at TEXT NOT NULL, details TEXT NOT NULL, state_sha256 TEXT NOT NULL)"
                        )
                        db.execute("PRAGMA user_version = 1")
                    self._save(db, state, action, result)
                if action in _MUTATIONS:
                    result.update(self._metadata(state))
                if action in {"record", "check_headers"}:
                    result["case"] = self._case_view(state, state["cases"][result["case_id"]])
                    result["status"] = result["case"]["status"]
                result["revision"] = state["revision"]
                return result
        except sqlite3.Error as exc:
            raise AssessmentError(
                "Assessment database is corrupt, incompatible, busy, or unavailable"
            ) from exc
        except OSError as exc:
            raise AssessmentError("Assessment workspace/storage is unavailable") from exc

    def _load(self, db: sqlite3.Connection) -> dict[str, Any]:
        try:
            if db.execute("PRAGMA quick_check").fetchall() != [("ok",)]:
                raise AssessmentError("Corrupt assessment database")
            rows = db.execute(
                "SELECT id, schema_version, revision, state, sha256 FROM ledger"
            ).fetchall()
            if len(rows) != 1 or rows[0][0] != 1:
                raise AssessmentError("Corrupt assessment engagement state")
            _, version, revision, raw, digest = rows[0]
            state = _json_object(raw)
            effective_state = {"denied_hosts": []} | state
            configuration = _initialize_payload(effective_state)
            if (
                version != _SCHEMA_VERSION
                or _sha(raw.encode()) != digest
                or _integer(state["schema_version"], "schema_version", 1, 1) != version
                or _integer(state["revision"], "revision", 1) != revision
                or state["workspace"] != str(self.workspace)
                or state["baseline"] != _BASELINE
                or configuration != {key: effective_state[key] for key in configuration}
                or not all(
                    isinstance(state[key], dict) for key in ("operations", "cases", "sources")
                )
            ):
                raise AssessmentError("Corrupt or mismatched engagement state; refusing to reset")
            audit = db.execute(
                "SELECT revision, action, changed_at, details, state_sha256 FROM history ORDER BY revision"
            ).fetchall()
            if len(audit) != revision or audit[-1][4] != digest:
                raise AssessmentError("Assessment history does not match engagement state")
            for index, event in enumerate(audit, 1):
                if (
                    event[0] != index
                    or event[1] not in _MUTATIONS
                    or not re.fullmatch(r"[0-9a-f]{64}", event[4])
                ):
                    raise AssessmentError("Corrupt assessment revision history")
                _timestamp(event[2], "history timestamp", allow_future=True)
                _json_object(event[3])
            initial_details = _json_object(audit[0][3])
            if (
                _scope(initial_details.get("denied_hosts", []), "denied_hosts")
                != configuration["denied_hosts"]
            ):
                raise AssessmentError("The deny policy does not match initialization history")
            initialized_asvs = {
                _json_object(row[3])["plan_id"] for row in audit if row[1] == "asvs_init"
            }
            if initialized_asvs != set(state.get("asvs_plans", {})):
                raise AssessmentError("ASVS plans do not match their initialization history")
            self._validate_state(effective_state)
            review_links = {
                event["revision"]: (
                    plan_id,
                    requirement_id,
                    event["status"],
                    event["method"],
                    event["evidence"],
                )
                for plan_id, plan in state.get("asvs_plans", {}).items()
                for requirement_id, record in plan["records"].items()
                for event in record["history"]
            }
            audit_links = {}
            for row in audit:
                if row[1] == "asvs_record":
                    details = _json_object(row[3])
                    audit_links[row[0]] = tuple(
                        details[key]
                        for key in ("plan_id", "requirement_id", "status", "method", "evidence")
                    )
            if review_links != audit_links:
                raise AssessmentError("ASVS outcomes do not match their revision history")
            return effective_state
        except (KeyError, TypeError, ValueError, AttributeError, IndexError, RecursionError) as exc:
            raise AssessmentError(
                "Corrupt or mismatched engagement state; refusing to reset"
            ) from exc

    def _validate_state(self, state: dict[str, Any]) -> None:
        if "asvs_plans" in state:
            from buggy.sandbox_kernel.asvs_review import validate_plans

            asvs_plans = state["asvs_plans"]
            validate_plans(asvs_plans, revision=state["revision"])
            for plan in asvs_plans.values():
                scoped = _operation(
                    {"url": plan["asset"], "method": "GET"},
                    None,
                    state["allowed_hosts"],
                    state["denied_hosts"],
                )
                if scoped["url"] != plan["asset"] or urlsplit(plan["asset"]).query:
                    raise AssessmentError("ASVS application identity is not canonical")
                for record in plan["records"].values():
                    for outcome in [record, *record["history"]]:
                        for reference in outcome["evidence"]:
                            _relative_path(reference["path"])
                            _integer(reference["size_bytes"], "evidence size", 1)
        for field in ("created_at", "updated_at"):
            _timestamp(state[field], field, allow_future=True)
        provenance: dict[str, set[str]] = {}
        for source_id, source in state["sources"].items():
            if (
                source_id != source["id"]
                or source["kind"] not in _SOURCE_KINDS
                or not source["history"]
            ):
                raise AssessmentError("Corrupt source identity or history")
            _text(source_id, "source.id", 128)
            if not re.fullmatch(r"[0-9a-f]{64}", source["signature"]):
                raise AssessmentError("Corrupt source observation signature")
            ids: set[str] = set()
            previous = 0
            for event in source["history"]:
                previous = _integer(
                    event["revision"], "source revision", previous + 1, state["revision"]
                )
                if (
                    event["status"] not in _SOURCE_STATUSES
                    or _roles(event["operation_ids"], "operation_ids") != event["operation_ids"]
                ):
                    raise AssessmentError("Corrupt source observation")
                _timestamp(event["observed_at"], "observed_at", allow_future=True)
                if not isinstance(event["detail"], str):
                    raise AssessmentError("Corrupt source detail")
                _integer(
                    event["reported_operations"], "reported_operations", len(event["operation_ids"])
                )
                if event["operation_ids"] and event["status"] != "ok":
                    raise AssessmentError("Unsuccessful sources cannot credit operations")
                if (
                    event["status"] == "ok"
                    and not event["operation_ids"]
                    and source["kind"] != "osint"
                ):
                    raise AssessmentError("Successful inventory sources must identify operations")
                ids.update(event["operation_ids"])
            if source["operation_ids"] != sorted(ids) or any(
                source[field] != source["history"][-1][field]
                for field in ("status", "observed_at", "detail", "revision", "reported_operations")
            ):
                raise AssessmentError("Corrupt source provenance")
            for operation_id in ids:
                if operation_id not in state["operations"]:
                    raise AssessmentError("Source references a missing operation")
                provenance.setdefault(operation_id, set()).add(source_id)
        expected = {}
        for operation_id, operation in state["operations"].items():
            canonical = _operation(operation, None, state["allowed_hosts"], state["denied_hosts"])
            canonical["provenance"] = sorted(provenance.get(operation_id, set()))
            if (
                canonical != operation
                or operation_id != canonical["operation_id"]
                or not canonical["provenance"]
            ):
                raise AssessmentError("Corrupt or out-of-scope operation identity")
            for control in _CONTROLS:
                roles = (
                    state["required_roles"]
                    if control == "auth.access-control"
                    else ["source" if control == "source.authorization" else "anonymous"]
                )
                for role in roles:
                    case_id = _identifier(
                        "case", operation["method"], operation["url"], role, control
                    )
                    expected[case_id] = (operation_id, role, control)
        if set(expected) != set(state["cases"]):
            raise AssessmentError(
                "The baseline case inventory is corrupt; refusing to regenerate it"
            )
        result_fields = ("status", "reason", "rationale", "evidence", "evaluation_mode")
        for case_id, case in state["cases"].items():
            if case_id != case["case_id"] or expected[case_id] != (
                case["operation_id"],
                case["role"],
                case["control_id"],
            ):
                raise AssessmentError("Corrupt assessment case identity")
            _validate_outcome(case)
            if not isinstance(case["history"], list) or bool(case["history"]) != (
                case["status"] != "untested"
            ):
                raise AssessmentError("Corrupt case history")
            previous = 0
            for event in case["history"]:
                previous = _integer(
                    event["revision"], "case revision", previous + 1, state["revision"]
                )
                _timestamp(event["recorded_at"], "recorded_at", allow_future=True)
                _validate_outcome(event)
                if event["action"] != {"attested": "record", "deterministic": "check_headers"}.get(
                    event["evaluation_mode"]
                ):
                    raise AssessmentError("Corrupt evaluation history")
            if case["history"] and any(
                case[field] != case["history"][-1][field] for field in result_fields
            ):
                raise AssessmentError("Case outcome does not match its history")

    def _save(
        self, db: sqlite3.Connection, state: dict[str, Any], action: str, details: dict[str, Any]
    ) -> None:
        state["revision"] += 1
        state["updated_at"] = _now()
        raw = _dump(state)
        digest = _sha(raw.encode())
        db.execute(
            "INSERT INTO ledger VALUES (1, ?, ?, ?, ?) ON CONFLICT(id) DO UPDATE SET "
            "revision=excluded.revision, state=excluded.state, sha256=excluded.sha256",
            (_SCHEMA_VERSION, state["revision"], raw, digest),
        )
        db.execute(
            "INSERT INTO history VALUES (?, ?, ?, ?, ?)",
            (state["revision"], action, state["updated_at"], _dump(details), digest),
        )

    def _metadata(self, state: dict[str, Any]) -> dict[str, Any]:
        fields = (
            "schema_version",
            "revision",
            "engagement_name",
            "profile",
            "baseline",
            "allowed_hosts",
            "denied_hosts",
            "required_roles",
            "available_roles",
            "source_available",
        )
        return {key: state[key] for key in fields} | {
            "baseline_description": "Minimum web/API baseline; not full ASVS coverage.",
            "total_operations": len(state["operations"]),
            "total_cases": len(state["cases"]),
        }

    def _context_sources(self, payload: dict[str, Any]) -> dict[str, Any]:
        maximum = _integer(payload.get("max_rows", 1000), "max_rows", 1, 1000)
        try:
            if self.workspace.resolve(strict=True) != self.workspace:
                raise AssessmentError("Snapshot workspace has moved or become a symlink")
        except OSError as exc:
            raise AssessmentError("Snapshot workspace is unavailable") from exc
        report: dict[str, Any] | None = None
        state: dict[str, Any] | None = None
        ledger_status = "unavailable"
        try:
            if self._directory.is_symlink() or self._database.is_symlink():
                raise AssessmentError("Assessment storage cannot be a symlink")
            if not stat.S_ISREG(self._database.stat().st_mode):
                raise AssessmentError("Assessment storage must be a regular file")
            with (
                closing(
                    sqlite3.connect(
                        self._database.as_uri() + "?mode=ro",
                        uri=True,
                        timeout=30,
                        isolation_level=None,
                    )
                ) as db,
                db,
            ):
                db.execute("BEGIN")
                tables = {
                    row[0]
                    for row in db.execute(
                        "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'"
                    )
                }
                if (
                    tables != {"ledger", "history"}
                    or db.execute("PRAGMA user_version").fetchone()[0] != _SCHEMA_VERSION
                ):
                    raise AssessmentError("Corrupt or incompatible assessment schema")
                state = self._load(db)
                report = self._report(db, state, {"limit": 1}, "report")
        except FileNotFoundError:
            ledger_status = "unavailable"
        except (AssessmentError, OSError, sqlite3.Error):
            ledger_status = "error"
        label = payload.get("engagement_name", report.get("engagement_name") if report else None)
        if not isinstance(label, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,79}", label):
            raise AssessmentError("A valid engagement name is required for a snapshot")
        if report and label != report["engagement_name"]:
            raise AssessmentError("Snapshot engagement does not match the selected workspace")
        sources: dict[str, Any] = {
            name: {"engagement": label, "status": "unavailable", "data": {}}
            for name in ("scope", "coverage", "inventory", "objectives", "asvs")
        }
        for name in ("scope", "coverage", "inventory", "asvs"):
            sources[name]["status"] = ledger_status
        if report is not None and state is not None:
            sources["scope"] = {
                "engagement": label,
                "status": "ok",
                "total": 1,
                "data": {key: report[key] for key in ("allowed_hosts", "denied_hosts")},
            }
            sources["coverage"] = {
                "engagement": label,
                "status": "ok",
                "total": 1,
                "data": {
                    key: report[key]
                    for key in (
                        "baseline",
                        "revision",
                        "total_operations",
                        "total_cases",
                        "status_counts",
                        "coverage",
                        "complete",
                    )
                },
            }
            for source, action, field in (
                ("inventory", "inventory", "operations"),
                ("asvs", "asvs_list", "plans"),
            ):
                try:
                    page = (
                        _page(list(state["operations"].values()), {"limit": maximum}, "operations")
                        if source == "inventory"
                        else self._asvs_dispatch(state, {"limit": maximum}, action)
                    )
                    rows = []
                    for item in page[field]:
                        if source == "inventory":
                            url = urlsplit(item["url"])
                            rows.append(
                                {
                                    "operation_id": item["operation_id"],
                                    "method": item["method"],
                                    "url": urlunsplit((url.scheme, url.netloc, "", "", "")),
                                }
                            )
                        else:
                            url = urlsplit(item["asset"])
                            rows.append(
                                {
                                    key: item[key]
                                    for key in (
                                        "plan_id",
                                        "level",
                                        "version",
                                        "status_counts",
                                        "coverage",
                                        "complete",
                                    )
                                }
                                | {"asset": urlunsplit((url.scheme, url.netloc, "", "", ""))}
                            )
                    sources[source] = {
                        "engagement": label,
                        "status": "ok",
                        "total": page["total"],
                        "data": rows,
                    }
                except AssessmentError:
                    sources[source]["status"] = "error"
        try:
            _, raw = self._evidence("plan/opplan.json", capture=True)
            plan = _json_object(raw)
            if (
                plan.get("engagement_name") != label
                or plan.get("engagement", label) != label
                or not isinstance(plan.get("objectives"), list)
            ):
                raise AssessmentError("OPPLAN does not match the selected engagement")
            for item in plan["objectives"]:
                if not isinstance(item, dict) or any(
                    key in item and item[key] != label for key in ("engagement", "engagement_name")
                ):
                    raise AssessmentError("Invalid or mismatched objective metadata")
            rows = []
            for item in plan["objectives"][:maximum]:
                identity = item.get("id")
                rows.append(
                    {
                        "id": "sha256:"
                        + _sha(str(identity).encode("utf-8", errors="surrogatepass"))
                        if type(identity) in (str, int)
                        else None,
                        "status": item.get("status")
                        if item.get("status")
                        in ("pending", "in-progress", "completed", "blocked", "cancelled")
                        else None,
                        "phase": item.get("phase")
                        if item.get("phase")
                        in ("recon", "initial-access", "post-exploit", "c2", "exfiltration")
                        else None,
                    }
                )
            sources["objectives"] = {
                "engagement": label,
                "status": "ok",
                "total": len(plan["objectives"]),
                "data": rows,
            }
        except AssessmentError as exc:
            sources["objectives"]["status"] = (
                "unavailable" if isinstance(exc.__cause__, FileNotFoundError) else "error"
            )
        return {"engagement": label, "sources": sources}

    def _asvs_plan_report(
        self, state: dict[str, Any], plan: dict[str, Any], cache: dict[str, Any]
    ) -> dict[str, Any]:
        from buggy.sandbox_kernel.asvs_review import report_plan

        for record in plan["records"].values():
            for reference in record["evidence"]:
                path = reference["path"]
                if path not in cache:
                    try:
                        cache[path] = self._evidence(path)[0]
                    except AssessmentError:
                        cache[path] = None
        report = report_plan(
            plan,
            available_roles=state["available_roles"],
            source_available=state["source_available"],
            evidence_checks=cache,
        )
        return report | {
            "engagement_name": state["engagement_name"],
            "plan_id": plan["plan_id"],
            "asset": plan["asset"],
            "level": plan["level"],
            "version": plan["catalog_version"],
            "baseline": f"asvs-{plan['catalog_version']}-L{plan['level']}",
        }

    def _asvs_dispatch(
        self, state: dict[str, Any], payload: dict[str, Any], action: str
    ) -> dict[str, Any]:
        from buggy.sandbox_kernel.asvs_review import (
            ASVSReviewError,
            create_plan,
            record_result,
        )

        try:
            plans = state.get("asvs_plans", {})
            if action == "asvs_init":
                specification = payload
                if "plan_path" in payload:
                    if set(payload) - {"plan_path", "expected_revision"}:
                        raise AssessmentError(
                            "Reviewed ASVS plan cannot be combined with inline fields"
                        )
                    specification = _json_object(
                        self._evidence(payload["plan_path"], capture=True)[1]
                    )
                    if set(specification) - {"asset", "level", "prerequisites"}:
                        raise AssessmentError("Unsupported ASVS plan fields")
                prerequisites = specification.get("prerequisites", {})
                if payload.get("prerequisites_path") is not None:
                    prerequisites = _json_object(
                        self._evidence(payload["prerequisites_path"], capture=True)[1]
                    )
                application = _operation(
                    {"url": specification.get("asset"), "method": "GET"},
                    None,
                    state["allowed_hosts"],
                    state["denied_hosts"],
                )["url"]
                if urlsplit(application).query:
                    raise AssessmentError("ASVS application URLs must not contain query parameters")
                plan = create_plan(application, specification.get("level", 2), prerequisites)
                state.setdefault("asvs_plans", {}).setdefault(plan["plan_id"], plan)
                return {
                    key: plan[key]
                    for key in ("plan_id", "asset", "level", "catalog_version", "catalog_sha256")
                } | {"baseline_coverage_updated": False}
            cache: dict[str, Any] = {}
            if action == "asvs_list":
                summaries = []
                for plan in plans.values():
                    report = self._asvs_plan_report(state, plan, cache)
                    summaries.append(
                        {
                            key: report[key]
                            for key in (
                                "plan_id",
                                "asset",
                                "level",
                                "version",
                                "status_counts",
                                "coverage",
                                "complete",
                            )
                        }
                    )
                return {"engagement_name": state["engagement_name"]} | _page(
                    summaries, payload, "plans"
                )
            plan_id = _text(payload.get("plan_id"), "plan_id", 128)
            if plan_id not in plans:
                raise AssessmentError("Unknown ASVS plan")
            if action == "asvs_record":
                paths = payload.get("evidence_paths", [])
                if not isinstance(paths, list):
                    raise AssessmentError("evidence_paths must be a list")
                references = [
                    self._evidence(path)[0]
                    for path in sorted({str(_relative_path(path)) for path in paths})
                ]
                requirement_id = _text(payload.get("requirement_id"), "requirement_id", 128)
                recorded = record_result(
                    plans[plan_id],
                    requirement_id,
                    payload.get("status"),
                    payload.get("rationale"),
                    payload.get("method"),
                    references,
                    revision=state["revision"] + 1,
                    recorded_at=_now(),
                    available_roles=state["available_roles"],
                    source_available=state["source_available"],
                )
                return {
                    "plan_id": plan_id,
                    "requirement_id": requirement_id,
                    "status": recorded["status"],
                    "method": recorded["method"],
                    "evidence": references,
                    "evaluation_mode": "attested",
                    "independently_verified": False,
                    "baseline_coverage_updated": False,
                }
            report = self._asvs_plan_report(state, plans[plan_id], cache)
            cases = report.pop("cases")
            if action == "asvs_next":
                cases = [
                    case
                    for case in cases
                    if case["prerequisites_available"]
                    and case["status"] in {"untested", "blocked", "inconclusive"}
                ]
            return report | _page(cases, payload, "cases")
        except ASVSReviewError as exc:
            raise AssessmentError(str(exc)) from exc

    def _evidence(
        self, value: Any, capture: bool = False, capture_limit: int = 2 * 1024 * 1024
    ) -> tuple[dict[str, Any], bytes]:
        path = _relative_path(value)
        candidate = os.path.normpath(os.path.join(str(self.workspace), str(path)))
        if not candidate.startswith(str(self.workspace).rstrip(os.sep) + os.sep):
            raise AssessmentError("Evidence path escapes the engagement workspace")
        if os.open not in os.supports_dir_fd or not all(
            hasattr(os, flag) for flag in ("O_NOFOLLOW", "O_DIRECTORY")
        ):
            raise AssessmentError(
                "Secure workspace-relative evidence reads are unavailable on this platform"
            )
        try:
            root = os.open(str(self.workspace), os.O_RDONLY | os.O_NOFOLLOW | os.O_DIRECTORY)
            try:
                with ExitStack() as directories:
                    parent = root
                    for part in path.parts[:-1]:
                        parent = directories.enter_context(_evidence_directory(parent, part))
                    descriptor = os.open(
                        os.path.basename(candidate),
                        os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                        dir_fd=parent,
                    )
                    try:
                        before = os.fstat(descriptor)
                        if not stat.S_ISREG(before.st_mode) or not before.st_size:
                            raise AssessmentError("Evidence must be a nonempty regular file")
                        if capture and before.st_size > capture_limit:
                            raise AssessmentError(
                                f"Captured artifacts must be at most {capture_limit // (1024 * 1024)} MiB"
                            )
                        stream = os.fdopen(descriptor, "rb")
                    except BaseException:
                        os.close(descriptor)
                        raise
                    with stream:
                        digest = hashlib.sha256()
                        chunks = []
                        size = 0
                        while chunk := stream.read(1024 * 1024):
                            size += len(chunk)
                            digest.update(chunk)
                            if capture:
                                if size > capture_limit:
                                    raise AssessmentError(
                                        f"Captured artifacts must be at most {capture_limit // (1024 * 1024)} MiB"
                                    )
                                chunks.append(chunk)
                        after = os.fstat(stream.fileno())
                        if size != before.st_size or any(
                            getattr(before, field) != getattr(after, field)
                            for field in (
                                "st_dev",
                                "st_ino",
                                "st_size",
                                "st_mtime_ns",
                                "st_ctime_ns",
                            )
                        ):
                            raise AssessmentError("Evidence changed while it was being read")
                        return {
                            "path": str(path),
                            "sha256": digest.hexdigest(),
                            "size_bytes": size,
                        }, b"".join(chunks)
            finally:
                os.close(root)
        except OSError as exc:
            raise AssessmentError(
                f"Evidence {str(path)!r} is unreadable, missing, or symlinked"
            ) from exc

    def _evaluate_threat(
        self, state: dict[str, Any], payload: dict[str, Any], action: str
    ) -> dict[str, Any]:
        from buggy.sandbox_kernel.kev import KEVInputError, prioritize_kev
        from buggy.sandbox_kernel.threat_scenarios import ScenarioInputError, evaluate_scenario

        path_key = "evidence_path" if action == "evaluate_scenario" else "observation_path"
        capture_limit = (16 if action == "prioritize_kev" else 2) * 1024 * 1024
        evidence, content = self._evidence(
            payload.get(path_key), capture=True, capture_limit=capture_limit
        )
        artifact = _json_object(content)
        try:
            host = _host(urlsplit(_text(artifact.get("asset"), "asset", 8192)).hostname)
        except (ValueError, UnicodeError) as exc:
            raise AssessmentError("Threat artifact asset is invalid") from exc
        if _in_scope(host, state["denied_hosts"]):
            raise AssessmentError("Threat artifact asset is excluded by denied_hosts")
        if not _in_scope(host, state["allowed_hosts"]):
            raise AssessmentError("Threat artifact asset is outside allowed_hosts")
        references = [evidence]
        try:
            if action == "prioritize_kev":
                catalog_evidence, catalog_content = self._evidence(
                    payload.get("catalog_path"), capture=True, capture_limit=capture_limit
                )
                references.insert(0, catalog_evidence)
                result = prioritize_kev(_json_object(catalog_content), artifact)
                records = result.pop("records")
                result["priority_counts"] = {
                    priority: sum(record["priority"] == priority for record in records)
                    for priority in ("urgent", "investigate", "normal", "not_applicable")
                }
                result.update(_page(records, payload, "records"))
            else:
                result = evaluate_scenario(
                    _text(payload.get("scenario_id"), "scenario_id", 128), artifact
                )
        except (ScenarioInputError, KEVInputError) as exc:
            raise AssessmentError(f"Threat artifact rejected: {exc}") from exc
        return result | {"evidence": references, "baseline_coverage_updated": False}

    def _case(self, state: dict[str, Any], payload: dict[str, Any]) -> dict[str, Any]:
        case_id = _text(payload.get("case_id"), "case_id", 100)
        if case_id not in state["cases"]:
            raise AssessmentError("Unknown assessment case_id")
        return state["cases"][case_id]

    def _set_result(
        self,
        state: dict[str, Any],
        case: dict[str, Any],
        status: str,
        reason: str,
        evidence: list[dict[str, Any]],
        mode: str,
        rationale: str,
        action: str,
    ) -> dict[str, Any]:
        result = {
            "status": status,
            "reason": reason,
            "rationale": rationale,
            "evidence": evidence,
            "evaluation_mode": mode,
        }
        case.update(result)
        case["history"].append(
            result
            | {
                "revision": state["revision"] + 1,
                "action": action,
                "recorded_at": _now(),
            }
        )
        return {"case_id": case["case_id"], "status": status, "evaluation_mode": mode}

    def _record(self, state: dict[str, Any], payload: dict[str, Any]) -> dict[str, Any]:
        case = self._case(state, payload)
        status = payload.get("status")
        if not isinstance(status, str) or status not in _STATUSES[1:]:
            raise AssessmentError("Invalid recorded status")
        rationale = _text(payload.get("rationale"), "rationale", 8192, multiline=True)
        prerequisite = self._prerequisite(state, case)
        if prerequisite and status in {"pass", "fail", "not_applicable"}:
            raise AssessmentError(prerequisite)
        paths = payload.get("evidence_paths", [])
        if not isinstance(paths, list) or (not paths and status in {"pass", "fail"}):
            raise AssessmentError("pass/fail require a nonempty evidence_paths list")
        paths = sorted({str(_relative_path(path)) for path in paths})
        evidence = [self._evidence(path)[0] for path in paths]
        return self._set_result(
            state,
            case,
            status,
            f"Attested: {rationale} (not independently verified).",
            evidence,
            "attested",
            rationale,
            "record",
        )

    def _check_headers(self, state: dict[str, Any], payload: dict[str, Any]) -> dict[str, Any]:
        case = self._case(state, payload)
        if case["control_id"] not in {"http.nosniff", "http.hsts"}:
            raise AssessmentError("check_headers accepts only http.nosniff/http.hsts cases")
        evidence, raw = self._evidence(payload.get("evidence_path"), capture=True)
        artifact = _json_object(raw)
        if artifact.get("source") != "capture":
            raise AssessmentError(
                "Only a supplied source='capture' response artifact is accepted; mocks are forbidden"
            )
        _timestamp(artifact.get("captured_at"), "captured_at")
        operation = state["operations"][case["operation_id"]]
        if (
            _url(artifact.get("url")) != operation["url"]
            or _method(artifact.get("method")) != operation["method"]
        ):
            raise AssessmentError(
                "Artifact URL and method must match the case's canonical operation"
            )
        status, reason = _header_result(case["control_id"], operation["url"], artifact)
        return self._set_result(
            state, case, status, reason, [evidence], "deterministic", reason, "check_headers"
        )

    def _prerequisite(self, state: dict[str, Any], case: dict[str, Any]) -> str:
        if case["control_id"] == "source.authorization" and not state["source_available"]:
            return (
                "Required source material is unavailable; source authorization review is blocked."
            )
        if (
            case["control_id"] == "auth.access-control"
            and case["role"] != "anonymous"
            and case["role"] not in state["available_roles"]
        ):
            return f"Required role '{case['role']}' is unavailable; access-control assessment is blocked."
        return ""

    def _case_view(
        self, state: dict[str, Any], case: dict[str, Any], cache: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        operation = state["operations"][case["operation_id"]]
        prerequisite = self._prerequisite(state, case)
        cache = {} if cache is None else cache
        errors = []
        for evidence in case["evidence"]:
            path = evidence["path"]
            if path not in cache:
                try:
                    cache[path] = self._evidence(path)[0]
                except AssessmentError as exc:
                    cache[path] = str(exc)
            actual = cache[path]
            if isinstance(actual, str):
                errors.append({"path": path, "reason": actual})
            elif (
                actual["sha256"] != evidence["sha256"]
                or actual["size_bytes"] != evidence["size_bytes"]
            ):
                errors.append(
                    {"path": path, "reason": "Evidence hash changed since the recorded assessment."}
                )
        view = case | {
            "url": operation["url"],
            "method": operation["method"],
            "provenance": operation["provenance"],
            "recorded_status": case["status"],
            "prerequisites_available": not prerequisite,
            "trusted": case["status"] != "untested" and not (errors or prerequisite),
            "evidence_errors": errors,
            "evidence_integrity": "untrusted"
            if errors
            else "verified"
            if case["evidence"]
            else "not_cited",
        }
        integrity_reason = (
            "Referenced evidence is untrusted; reassessment is required." if errors else ""
        )
        if errors:
            view.update(status="inconclusive", reason=integrity_reason)
        if prerequisite:
            view.update(status="blocked", reason=(prerequisite + " " + integrity_reason).strip())
        return view

    def _report(
        self, db: sqlite3.Connection, state: dict[str, Any], payload: dict[str, Any], action: str
    ) -> dict[str, Any]:
        cache: dict[str, Any] = {}
        cases = [
            self._case_view(state, state["cases"][key], cache) for key in sorted(state["cases"])
        ]
        if action == "next":
            pending = [
                case
                for case in cases
                if case["prerequisites_available"]
                and case["status"]
                in {
                    "untested",
                    "blocked",
                    "inconclusive",
                }
            ]
            return self._metadata(state) | _page(pending, payload, "cases")
        counts = {status: sum(case["status"] == status for case in cases) for status in _STATUSES}
        sources = [
            {key: value for key, value in source.items() if key != "signature"}
            for source in state["sources"].values()
        ]
        source_gaps = [
            {
                "source_id": source["id"],
                "kind": source["kind"],
                "status": source["status"],
                "reason": {
                    "empty": "The source supplied no operations.",
                    "error": "The source reported an error; no operations were credited from this observation.",
                    "unavailable": "The source is unavailable; no operations were credited from this observation.",
                    "mock": "Mock source data is not assessment coverage and was not imported.",
                }[source["status"]],
                "detail": source["detail"],
                "observed_at": source["observed_at"],
            }
            for source in sources
            if source["status"] != "ok"
        ]
        gaps = [case for case in cases if case["status"] not in {"pass", "not_applicable"}]
        applicable = len(cases) - counts["not_applicable"]
        assessed = counts["pass"] + counts["fail"]
        remaining = counts["untested"] + counts["blocked"] + counts["inconclusive"]
        untrusted = sum(bool(case["evidence_errors"]) for case in cases)
        history = [
            {
                "revision": row[0],
                "action": row[1],
                "changed_at": row[2],
                "details": json.loads(row[3]),
            }
            for row in db.execute(
                "SELECT revision, action, changed_at, details FROM history ORDER BY revision"
            )
        ]
        summary = self._metadata(state) | {
            "controls": list(_CONTROLS),
            "totals": {
                "operations": len(state["operations"]),
                "cases": len(cases),
                "sources": len(sources),
                "source_gaps": len(source_gaps),
                "gaps": len(gaps),
                "untrusted": untrusted,
            },
            "status_counts": counts,
            "complete": bool(state["operations"]) and not (remaining or source_gaps or untrusted),
            "coverage": {
                "applicable": applicable,
                "assessed": assessed,
                "remaining": remaining,
                "not_applicable": counts["not_applicable"],
                "percent": round(100 * assessed / applicable, 2) if applicable else None,
                "evaluation_modes": {
                    mode: sum(
                        case["evaluation_mode"] == mode and case["status"] in {"pass", "fail"}
                        for case in cases
                    )
                    for mode in ("attested", "deterministic")
                },
            },
            "sources": sources,
            "source_gaps": source_gaps,
            "history": history,
        }
        return summary | _page(
            gaps if action == "gaps" else cases, payload, "gaps" if action == "gaps" else "cases"
        )

    def _import(self, state: dict[str, Any], payload: dict[str, Any]) -> dict[str, Any]:
        operations = payload.get("operations")
        if not isinstance(operations, list):
            raise AssessmentError("operations must be a list")
        operations = [
            _operation(op, payload.get("base_url"), state["allowed_hosts"], state["denied_hosts"])
            for op in operations
        ]
        source = payload.get("source")
        if not isinstance(source, dict):
            raise AssessmentError("source must be an object")
        source_id = _text(source.get("id"), "source.id", 128)
        kind, status = source.get("kind"), source.get("status")
        if not isinstance(kind, str) or kind not in _SOURCE_KINDS:
            raise AssessmentError("Invalid source.kind")
        if not isinstance(status, str) or status not in _SOURCE_STATUSES:
            raise AssessmentError("Invalid source.status")
        if status == "empty" and operations:
            raise AssessmentError("An empty source cannot supply operations")
        if status == "ok" and not operations and kind != "osint":
            status = "empty"
        observed = (
            _timestamp(source["observed_at"], "source.observed_at")
            if source.get("observed_at") is not None
            else None
        )
        detail = "" if source.get("detail") is None else source["detail"]
        if detail != "":
            detail = _text(detail, "source.detail", multiline=True)
        previous = state["sources"].get(source_id)
        if previous and previous["kind"] != kind:
            raise AssessmentError("source.kind is immutable for a source id")
        credited = operations if status == "ok" else []
        ids = sorted({op["operation_id"] for op in credited})
        signature = _sha(_dump([kind, status, observed, detail, ids, len(operations)]).encode())
        if previous is None:
            previous = {
                "id": source_id,
                "kind": kind,
                "operation_ids": [],
                "history": [],
            }
            state["sources"][source_id] = previous
        accumulated_ids = sorted(set(previous["operation_ids"]) | set(ids))
        if previous.get("signature") != signature:
            observation = {
                "status": status,
                "observed_at": observed or _now(),
                "detail": detail,
                "operation_ids": ids,
                "reported_operations": len(operations),
                "revision": state["revision"] + 1,
            }
            previous.update(observation | {"signature": signature})
            previous["history"].append(observation)
        previous["operation_ids"] = accumulated_ids
        imported = 0
        for operation in credited:
            operation_id = operation["operation_id"]
            if operation_id not in state["operations"]:
                state["operations"][operation_id] = operation
                self._generate_cases(state, operation)
                imported += 1
            saved = state["operations"][operation_id]
            saved["provenance"] = sorted(set(saved["provenance"]) | {source_id})
            params = {_dump(p): p for p in saved["parameters"] + operation["parameters"]}
            saved["parameters"] = [params[key] for key in sorted(params)]
        return {
            "imported": imported,
            "ignored": len(operations) if status != "ok" else 0,
            "source_id": source_id,
        }

    def _generate_cases(self, state: dict[str, Any], operation: dict[str, Any]) -> None:
        for control in _CONTROLS:
            roles = (
                state["required_roles"]
                if control == "auth.access-control"
                else ["source" if control == "source.authorization" else "anonymous"]
            )
            for role in roles:
                case_id = _identifier("case", operation["method"], operation["url"], role, control)
                state["cases"][case_id] = {
                    "case_id": case_id,
                    "operation_id": operation["operation_id"],
                    "role": role,
                    "control_id": control,
                    "status": "untested",
                    "reason": "Not yet assessed.",
                    "rationale": "",
                    "evidence": [],
                    "evaluation_mode": None,
                    "history": [],
                }
