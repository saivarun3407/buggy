"""Autonomous bug-bounty intake — pull program scope from platform APIs.

API-only by design. The scout agent uses these tools to list the open
programs an operator can access and to fetch a program's *structured*
scope (in-scope assets, out-of-scope assets, severity caps, reporting
policy, and per-program rules) straight from the official APIs — no
scraping, no browser login:

  * **HackerOne Hacker API** — HTTP Basic (``H1_API_USERNAME`` is the API
    token identifier, ``H1_API_TOKEN`` the value).
  * **Bugcrowd API** — ``Authorization: Token <id>:<token>`` header
    (``BUGCROWD_API_USERNAME`` / ``BUGCROWD_API_TOKEN``).

Credential handling is deliberate: tokens are read from the *environment
only*. They are never accepted as tool arguments (which would land in the
agent transcript) and never written to ``roe.json`` or any log line. When
a credential is missing a tool returns a structured ``missing_credentials``
payload naming the env vars to set, so the scout can ask the operator to
provide them at engagement start.

The structured-scope payloads feed straight into ``ingest_bounty_scope``
after the operator confirms them — the HITL gate is the scout's job, not
this module's. Any per-program rule heuristics returned here are
*suggestions* (``suggested_rules``) for the operator to confirm before the
scout hard-enforces them into the RoE.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

import httpx
from langchain_core.tools import tool

from buggy_core.utils.logging import get_logger

log = get_logger("research.bounty_intake")

# ── Public API bases ──────────────────────────────────────────────────────
H1_API_BASE = "https://api.hackerone.com/v1/hackers"
BUGCROWD_API_BASE = "https://api.bugcrowd.com"

# ── Credentials (environment-only; never tool args, never persisted) ──────
_H1_USER_ENV = "H1_API_USERNAME"
_H1_TOKEN_ENV = "H1_API_TOKEN"
_BC_USER_ENV = "BUGCROWD_API_USERNAME"
_BC_TOKEN_ENV = "BUGCROWD_API_TOKEN"

_TIMEOUT = 30.0
_MAX_PAGES = 20  # safety cap on pagination follow
_POLICY_EXCERPT_CHARS = 1500

# HackerOne ``asset_type`` values that describe a network reachable asset
# (everything else — app-store IDs, source repos, hardware — is informational
# and never enters the egress allowlist).
_H1_NETWORK_TYPES = frozenset({"url", "wildcard", "cidr", "ip_address", "domain"})
# Bugcrowd ``category`` values that describe a network reachable target.
_BC_NETWORK_CATEGORIES = frozenset({"website", "api"})

# Curated automated-scanner command patterns. When a program forbids
# automated scanning these regexes are folded into the RoE
# ``forbidden_command_patterns`` so the command parser refuses to launch
# them. ``(?i)`` + word boundaries so ``nuclei`` matches but ``nucleic``
# does not.
SCANNER_COMMAND_PATTERNS: tuple[str, ...] = (
    r"(?i)\bnuclei\b",
    r"(?i)\bsqlmap\b",
    r"(?i)\bnikto\b",
    r"(?i)\bwpscan\b",
    r"(?i)\b(?:dirb|dirbuster)\b",
    r"(?i)\bgobuster\b",
    r"(?i)\bffuf\b",
    r"(?i)\bferoxbuster\b",
    r"(?i)\bwfuzz\b",
    r"(?i)\bmasscan\b",
    r"(?i)\b(?:zap|zaproxy|zap-cli|zap-baseline)\b",
    r"(?i)\b(?:acunetix|nessus|openvas|arachni|w3af|skipfish)\b",
)


@dataclass(frozen=True)
class _Creds:
    identifier: str
    token: str


def _creds(user_env: str, token_env: str) -> _Creds | None:
    user = (os.environ.get(user_env) or "").strip()
    token = (os.environ.get(token_env) or "").strip()
    if user and token:
        return _Creds(user, token)
    return None


def _missing(platform: str, user_env: str, token_env: str) -> dict[str, Any]:
    return {
        "error": "missing_credentials",
        "platform": platform,
        "needed_env": [user_env, token_env],
        "how_to": (
            f"Set {user_env} and {token_env} in the engagement environment "
            f"before intake (the API token identifier + value from your "
            f"{platform} API settings). They are read from the environment "
            f"only — never pass them as tool arguments, and they are never "
            f"written to roe.json or logged."
        ),
    }


def _get_json(
    url: str,
    *,
    auth: tuple[str, str] | None = None,
    headers: dict[str, str] | None = None,
    params: dict[str, Any] | None = None,
) -> tuple[int, Any]:
    """GET ``url`` and parse JSON, returning ``(status_code, parsed)``.

    Network / parse failures surface as ``(0, {...})`` so callers degrade
    gracefully. The auth secret is never written to a log line — only the
    host is logged on failure.
    """
    try:
        with httpx.Client(timeout=_TIMEOUT, follow_redirects=True) as client:
            resp = client.get(url, auth=auth, headers=headers, params=params)
    except httpx.HTTPError as exc:
        log.warning("intake GET %s failed: %s", urlparse(url).netloc, type(exc).__name__)
        return 0, {"_error": f"request failed: {type(exc).__name__}"}
    try:
        return resp.status_code, resp.json()
    except ValueError:
        return resp.status_code, {"_error": "non-JSON response"}


def _http_error(platform: str, status: int, body: Any) -> dict[str, Any]:
    detail = ""
    if isinstance(body, dict):
        detail = str(body.get("_error") or "")
    reason = {
        0: "network error reaching the API",
        401: "unauthorized — check the API token identifier and value",
        403: "forbidden — the token cannot access this resource",
        404: "not found — check the program handle / code",
        429: "rate limited by the platform — slow down and retry",
    }.get(status, f"unexpected HTTP {status}")
    return {
        "error": "api_error",
        "platform": platform,
        "status": status,
        "reason": reason,
        "detail": detail,
    }


def _norm_host(token: str) -> str:
    """Reduce a URL / host token to the bare host, wildcard, or CIDR."""
    token = (token or "").strip().lower()
    token = re.sub(r"^[a-z]+://", "", token)
    if "/" in token and not re.match(r"^\d{1,3}(?:\.\d{1,3}){3}/\d{1,2}$", token):
        token = token.split("/", 1)[0]
    token = token.split("?", 1)[0]
    if ":" in token and not token.startswith("["):
        host, _, port = token.rpartition(":")
        if port.isdigit():
            token = host
    return token.rstrip(".")


def _excerpt(text: str) -> str:
    text = (text or "").strip()
    return (
        text
        if len(text) <= _POLICY_EXCERPT_CHARS
        else text[:_POLICY_EXCERPT_CHARS] + " …[truncated]"
    )


# ── Per-program rule heuristics ───────────────────────────────────────────


def _derive_rules_from_policy(policy: str) -> dict[str, Any]:
    """Best-effort extraction of enforceable rules from freeform policy text.

    Returns a suggestion the operator confirms before the scout enforces it:
    automated-scanning prohibitions become ``forbidden_command_patterns`` and
    a request-rate cap becomes a ``min_inter_request_delay_ms``. Always
    advisory — programs phrase rules a hundred ways and this is a keyword pass.
    """
    text = (policy or "").lower()
    notes: list[str] = []

    no_auto = bool(
        re.search(
            r"no\s+automat|prohibit\w*\s+\w*\s*automat|automat\w+\s+(?:scan|tool|test)"
            r"\w*\s+(?:is|are)?\s*(?:not|pro|forbid|disallow|prohibit)|"
            r"do not (?:use|run) automat|manual\s+testing\s+only|no\s+(?:vulnerability\s+)?scanners?",
            text,
        )
    )
    patterns: list[str] = list(SCANNER_COMMAND_PATTERNS) if no_auto else []
    if no_auto:
        notes.append(
            "policy appears to forbid automated scanning — common scanner "
            "commands will be blocked by the command parser"
        )

    delay_ms = 0
    rate = re.search(r"(\d{1,4})\s*(?:requests?|reqs?|rps)\s*(?:per|/|a)\s*(second|sec|s)\b", text)
    if rate:
        rps = max(1, int(rate.group(1)))
        delay_ms = max(1, round(1000 / rps))
        notes.append(
            f"policy mentions ~{rps} request(s)/second — suggest min delay {delay_ms} ms between requests"
        )

    return {
        "no_automated_tools": no_auto,
        "forbidden_command_patterns": patterns,
        "min_inter_request_delay_ms": delay_ms,
        "notes": notes,
    }


# ── HackerOne ─────────────────────────────────────────────────────────────


def _h1_collect(
    url: str, auth: tuple[str, str], *, soft: bool = False
) -> list[dict[str, Any]] | dict[str, Any]:
    """Follow JSON:API ``links.next`` pagination, returning all ``data`` items.

    ``soft`` suppresses HTTP errors (e.g. the scope-exclusions endpoint may
    404 on programs that pre-date it) and returns an empty list instead.
    """
    items: list[dict[str, Any]] = []
    params: dict[str, Any] | None = {"page[size]": 100}
    pages = 0
    while url and pages < _MAX_PAGES:
        status, body = _get_json(url, auth=auth, params=params)
        params = None  # ``links.next`` already carries the query
        if status != 200 or not isinstance(body, dict):
            if soft:
                return items
            return _http_error("hackerone", status, body)
        data = body.get("data")
        if isinstance(data, list):
            items.extend(d for d in data if isinstance(d, dict))
        url = (body.get("links") or {}).get("next") or ""
        pages += 1
    return items


def _partition_h1_scopes(
    scopes: list[dict[str, Any]],
) -> tuple[list[str], list[str], list[str], dict[str, str]]:
    in_scope: list[str] = []
    out_of_scope: list[str] = []
    non_network: list[str] = []
    severity_caps: dict[str, str] = {}
    for item in scopes:
        attrs = item.get("attributes", {}) or {}
        identifier = str(attrs.get("asset_identifier") or "").strip()
        if not identifier:
            continue
        asset_type = str(attrs.get("asset_type") or "").strip().lower()
        eligible = bool(attrs.get("eligible_for_submission", True))
        if asset_type in _H1_NETWORK_TYPES:
            host = _norm_host(identifier)
            if not host:
                continue
            (in_scope if eligible else out_of_scope).append(host)
            sev = str(attrs.get("max_severity") or "").strip().lower()
            if eligible and sev:
                severity_caps[host] = sev
        elif eligible:
            non_network.append(f"{identifier} ({asset_type or 'other'})")
    return _dedupe(in_scope), _dedupe(out_of_scope), _dedupe(non_network), severity_caps


def _h1_excluded_classes(exclusions: list[dict[str, Any]]) -> list[str]:
    classes: list[str] = []
    for item in exclusions:
        attrs = item.get("attributes", {}) or {}
        name = str(
            attrs.get("name") or attrs.get("title") or attrs.get("description") or ""
        ).strip()
        if name:
            classes.append(name)
    return _dedupe_text(classes)


def _h1_scope(creds: _Creds, handle: str) -> dict[str, Any]:
    auth = (creds.identifier, creds.token)
    status, prog = _get_json(f"{H1_API_BASE}/programs/{handle}", auth=auth)
    if status != 200 or not isinstance(prog, dict):
        return _http_error("hackerone", status, prog)
    pattrs = (prog.get("data") or {}).get("attributes", {}) or {}
    policy = str(pattrs.get("policy") or "")

    scopes = _h1_collect(f"{H1_API_BASE}/programs/{handle}/structured_scopes", auth)
    if isinstance(scopes, dict):
        return scopes  # error payload
    exclusions = _h1_collect(f"{H1_API_BASE}/programs/{handle}/scope_exclusions", auth, soft=True)
    exclusions_list = exclusions if isinstance(exclusions, list) else []

    in_scope, out_of_scope, non_network, severity_caps = _partition_h1_scopes(scopes)
    return {
        "platform": "hackerone",
        "program_handle": handle,
        "program_url": f"https://hackerone.com/{handle}",
        "program_name": str(pattrs.get("name") or handle),
        "offers_bounties": bool(pattrs.get("offers_bounties", False)),
        "in_scope": in_scope,
        "out_of_scope": out_of_scope,
        "non_network_assets": non_network,
        "excluded_classes": _h1_excluded_classes(exclusions_list),
        "severity_caps": severity_caps,
        "policy_excerpt": _excerpt(policy),
        "suggested_rules": _derive_rules_from_policy(policy),
        "next_step": (
            "Show this scope to the operator, confirm in-scope / out-of-scope / "
            "excluded classes / rules, then call ingest_bounty_scope(...) in enforce mode."
        ),
    }


def _h1_list(
    creds: _Creds, *, handle_contains: str, only_bounties: bool, limit: int
) -> dict[str, Any]:
    auth = (creds.identifier, creds.token)
    needle = handle_contains.strip().lower()
    programs: list[dict[str, Any]] = []
    url = f"{H1_API_BASE}/programs"
    params: dict[str, Any] | None = {"page[size]": 100}
    pages = 0
    while url and pages < _MAX_PAGES and len(programs) < limit:
        status, body = _get_json(url, auth=auth, params=params)
        params = None
        if status != 200 or not isinstance(body, dict):
            return _http_error("hackerone", status, body)
        for item in body.get("data") or []:
            attrs = (item or {}).get("attributes", {}) or {}
            handle = str(attrs.get("handle") or "")
            name = str(attrs.get("name") or "")
            offers = bool(attrs.get("offers_bounties", False))
            if needle and needle not in f"{handle} {name}".lower():
                continue
            if only_bounties and not offers:
                continue
            programs.append(
                {
                    "handle": handle,
                    "name": name,
                    "offers_bounties": offers,
                    "submission_state": attrs.get("submission_state"),
                    "state": attrs.get("state"),
                }
            )
            if len(programs) >= limit:
                break
        url = (body.get("links") or {}).get("next") or ""
        pages += 1
    return {"platform": "hackerone", "count": len(programs), "programs": programs}


# ── Bugcrowd ──────────────────────────────────────────────────────────────


def _bc_headers(creds: _Creds) -> dict[str, str]:
    return {
        "Accept": "application/vnd.bugcrowd+json",
        "Authorization": f"Token {creds.identifier}:{creds.token}",
    }


def _bc_list(creds: _Creds, *, name_contains: str, limit: int) -> dict[str, Any]:
    headers = _bc_headers(creds)
    needle = name_contains.strip().lower()
    programs: list[dict[str, Any]] = []
    url = f"{BUGCROWD_API_BASE}/programs"
    params: dict[str, Any] | None = {"page[limit]": 100}
    pages = 0
    while url and pages < _MAX_PAGES and len(programs) < limit:
        status, body = _get_json(url, headers=headers, params=params)
        params = None
        if status != 200 or not isinstance(body, dict):
            return _http_error("bugcrowd", status, body)
        for item in body.get("data") or []:
            attrs = (item or {}).get("attributes", {}) or {}
            code = str(attrs.get("code") or item.get("id") or "")
            name = str(attrs.get("name") or "")
            if needle and needle not in f"{code} {name}".lower():
                continue
            programs.append(
                {"code": code, "id": item.get("id"), "name": name, "status": attrs.get("status")}
            )
            if len(programs) >= limit:
                break
        url = (body.get("links") or {}).get("next") or ""
        pages += 1
    return {"platform": "bugcrowd", "count": len(programs), "programs": programs}


def _partition_bc_targets(included: list[dict[str, Any]]) -> tuple[list[str], list[str], list[str]]:
    """Split a Bugcrowd ``included`` array into in/out-of-scope + non-network.

    Target groups carry the in-scope flag; each target points at its group
    via ``relationships.target_group``. A target with no resolvable group
    defaults to in-scope (the common single-group case).
    """
    group_in_scope: dict[str, bool] = {}
    targets: list[dict[str, Any]] = []
    for item in included:
        if not isinstance(item, dict):
            continue
        rtype = str(item.get("type") or "")
        attrs = item.get("attributes", {}) or {}
        if rtype == "target_group":
            group_in_scope[str(item.get("id"))] = bool(attrs.get("in_scope", True))
        elif rtype == "target":
            targets.append(item)

    in_scope: list[str] = []
    out_of_scope: list[str] = []
    non_network: list[str] = []
    for item in targets:
        attrs = item.get("attributes", {}) or {}
        name = str(attrs.get("name") or attrs.get("uri") or "").strip()
        if not name:
            continue
        category = str(attrs.get("category") or "").strip().lower()
        gid = str(
            (((item.get("relationships") or {}).get("target_group") or {}).get("data") or {}).get(
                "id"
            )
            or ""
        )
        eligible = group_in_scope.get(gid, True)
        if category and category not in _BC_NETWORK_CATEGORIES:
            non_network.append(f"{name} ({category})")
            continue
        host = _norm_host(name)
        if not host:
            non_network.append(f"{name} ({category or 'other'})")
            continue
        (in_scope if eligible else out_of_scope).append(host)
    return _dedupe(in_scope), _dedupe(out_of_scope), _dedupe(non_network)


def _bc_scope(creds: _Creds, program: str) -> dict[str, Any]:
    headers = _bc_headers(creds)
    params = {"include": "current_brief.target_groups.targets"}
    status, body = _get_json(
        f"{BUGCROWD_API_BASE}/programs/{program}", headers=headers, params=params
    )
    if status != 200 or not isinstance(body, dict):
        return _http_error("bugcrowd", status, body)
    data = body.get("data") or {}
    pattrs = data.get("attributes", {}) or {}
    included = [i for i in (body.get("included") or []) if isinstance(i, dict)]
    in_scope, out_of_scope, non_network = _partition_bc_targets(included)
    policy = str(pattrs.get("scope") or pattrs.get("brief") or "")
    code = str(pattrs.get("code") or program)
    return {
        "platform": "bugcrowd",
        "program_handle": code,
        "program_url": f"https://bugcrowd.com/{code}",
        "program_name": str(pattrs.get("name") or code),
        "in_scope": in_scope,
        "out_of_scope": out_of_scope,
        "non_network_assets": non_network,
        "excluded_classes": [],
        "severity_caps": {},
        "policy_excerpt": _excerpt(policy),
        "suggested_rules": _derive_rules_from_policy(policy),
        "next_step": (
            "Show this scope to the operator, confirm in-scope / out-of-scope / "
            "rules, then call ingest_bounty_scope(...) in enforce mode."
        ),
    }


# ── Shared dedupe helpers ─────────────────────────────────────────────────


def _dedupe(tokens: list[str]) -> list[str]:
    seen: dict[str, None] = {}
    for tok in tokens:
        norm = _norm_host(tok)
        if norm and norm not in seen:
            seen[norm] = None
    return list(seen)


def _dedupe_text(items: list[str]) -> list[str]:
    seen: dict[str, None] = {}
    for it in items:
        key = it.strip()
        if key and key.lower() not in {s.lower() for s in seen}:
            seen[key] = None
    return list(seen)


# ── Tools ─────────────────────────────────────────────────────────────────


@tool
def bounty_intake_status() -> str:
    """Report which bug-bounty platforms have API credentials configured.

    Returns a per-platform ``available`` flag and, for any platform missing
    credentials, the exact environment variables to set. No secret values are
    ever returned. Call this first so you can ask the operator to provide any
    missing API token before listing programs.
    """
    h1 = _creds(_H1_USER_ENV, _H1_TOKEN_ENV) is not None
    bc = _creds(_BC_USER_ENV, _BC_TOKEN_ENV) is not None
    return json.dumps(
        {
            "hackerone": {
                "available": h1,
                "needed_env": [] if h1 else [_H1_USER_ENV, _H1_TOKEN_ENV],
            },
            "bugcrowd": {
                "available": bc,
                "needed_env": [] if bc else [_BC_USER_ENV, _BC_TOKEN_ENV],
            },
            "note": (
                "Credentials are read from the environment only — never paste a "
                "token into the chat. They are never written to roe.json or logged."
            ),
        },
        indent=2,
    )


@tool
def h1_list_programs(
    handle_contains: str = "", only_bounties: bool = False, limit: int = 50
) -> str:
    """List the HackerOne programs your API token can access.

    WHEN TO USE: After the operator chooses HackerOne, to enumerate open
    programs so they can pick one. Requires ``H1_API_USERNAME`` /
    ``H1_API_TOKEN`` in the environment.

    Args:
        handle_contains: Case-insensitive filter on program handle / name.
        only_bounties: When true, return only programs that offer bounties.
        limit: Max programs to return (1–200).

    Returns:
        JSON: ``{platform, count, programs:[{handle, name, offers_bounties,
        submission_state, state}]}`` — or a ``missing_credentials`` /
        ``api_error`` payload.
    """
    creds = _creds(_H1_USER_ENV, _H1_TOKEN_ENV)
    if creds is None:
        return json.dumps(_missing("hackerone", _H1_USER_ENV, _H1_TOKEN_ENV), indent=2)
    out = _h1_list(
        creds, handle_contains=handle_contains, only_bounties=only_bounties, limit=_clamp(limit)
    )
    return json.dumps(out, indent=2)


@tool
def h1_get_program_scope(program_handle: str) -> str:
    """Fetch a HackerOne program's structured scope, exclusions, and policy.

    WHEN TO USE: After the operator selects a HackerOne program, to pull the
    machine-readable scope to confirm with them before enforcing it. Returns
    normalized in-scope / out-of-scope network assets, non-network assets
    (app IDs, source repos — informational), excluded report categories,
    per-asset severity caps, a policy excerpt, and *suggested* per-program
    rules (automated-scanning / rate-limit heuristics) for the operator to
    confirm. Pass the confirmed values to ``ingest_bounty_scope``.

    Args:
        program_handle: HackerOne program handle / slug (e.g. ``"acme"``).

    Returns:
        JSON scope payload, or a ``missing_credentials`` / ``api_error`` payload.
    """
    creds = _creds(_H1_USER_ENV, _H1_TOKEN_ENV)
    if creds is None:
        return json.dumps(_missing("hackerone", _H1_USER_ENV, _H1_TOKEN_ENV), indent=2)
    handle = program_handle.strip().strip("/")
    if not handle:
        return json.dumps(
            {"error": "bad_request", "detail": "program_handle is required"}, indent=2
        )
    return json.dumps(_h1_scope(creds, handle), indent=2)


@tool
def bugcrowd_list_programs(name_contains: str = "", limit: int = 50) -> str:
    """List the Bugcrowd programs your API token can access.

    WHEN TO USE: After the operator chooses Bugcrowd, to enumerate programs so
    they can pick one. Requires ``BUGCROWD_API_USERNAME`` /
    ``BUGCROWD_API_TOKEN`` in the environment.

    Args:
        name_contains: Case-insensitive filter on program code / name.
        limit: Max programs to return (1–200).

    Returns:
        JSON: ``{platform, count, programs:[{code, id, name, status}]}`` — or a
        ``missing_credentials`` / ``api_error`` payload.
    """
    creds = _creds(_BC_USER_ENV, _BC_TOKEN_ENV)
    if creds is None:
        return json.dumps(_missing("bugcrowd", _BC_USER_ENV, _BC_TOKEN_ENV), indent=2)
    return json.dumps(_bc_list(creds, name_contains=name_contains, limit=_clamp(limit)), indent=2)


@tool
def bugcrowd_get_program_scope(program: str) -> str:
    """Fetch a Bugcrowd program's structured scope and policy.

    WHEN TO USE: After the operator selects a Bugcrowd program, to pull the
    machine-readable targets to confirm before enforcing. Returns normalized
    in-scope / out-of-scope network targets, non-network targets
    (mobile apps, hardware — informational), a policy excerpt, and *suggested*
    per-program rules for the operator to confirm. Pass the confirmed values to
    ``ingest_bounty_scope``.

    Args:
        program: Bugcrowd program code or UUID.

    Returns:
        JSON scope payload, or a ``missing_credentials`` / ``api_error`` payload.
    """
    creds = _creds(_BC_USER_ENV, _BC_TOKEN_ENV)
    if creds is None:
        return json.dumps(_missing("bugcrowd", _BC_USER_ENV, _BC_TOKEN_ENV), indent=2)
    code = program.strip().strip("/")
    if not code:
        return json.dumps({"error": "bad_request", "detail": "program is required"}, indent=2)
    return json.dumps(_bc_scope(creds, code), indent=2)


@tool
def analyze_program_rules(policy_text: str) -> str:
    """Derive *suggested* enforceable rules from a program's policy text.

    WHEN TO USE: On any pasted or fetched program policy to surface
    per-program constraints — automated-scanning prohibitions become
    ``forbidden_command_patterns`` and a stated request-rate cap becomes a
    ``min_inter_request_delay_ms``. Output is advisory: confirm with the
    operator, then pass the agreed values to ``ingest_bounty_scope`` to
    hard-enforce them.

    Args:
        policy_text: Freeform program policy / rules text.

    Returns:
        JSON: ``{no_automated_tools, forbidden_command_patterns,
        min_inter_request_delay_ms, notes}``.
    """
    return json.dumps(_derive_rules_from_policy(policy_text), indent=2)


def _clamp(limit: int) -> int:
    try:
        return max(1, min(int(limit), 200))
    except (TypeError, ValueError):
        return 50


BOUNTY_INTAKE_TOOLS = [
    bounty_intake_status,
    h1_list_programs,
    h1_get_program_scope,
    bugcrowd_list_programs,
    bugcrowd_get_program_scope,
    analyze_program_rules,
]
