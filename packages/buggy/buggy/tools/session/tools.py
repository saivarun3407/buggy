"""Session broker — workspace-resident auth-session store for agents.

Post-authentication surface is where the high-value bugs live, but agents
kept re-fighting login flows burn the budget before they reach it. The
broker splits session *acquisition* (whoever lands it — a login flow, an
operator-provided cookie, a captured credential replay) from session
*consumption*: any agent that is about to make authenticated requests calls
``session_get`` and splices the returned material into its curl / proxy
calls instead of re-deriving it.

Sessions live as JSON files under ``<workspace>/sessions/<host>.json`` —
the workspace is the canonical cross-agent handoff surface (agent contexts
are fresh per objective, so nothing survives except workspace + KG).

  - ``session_store`` — record/replace session material for a host.
  - ``session_get``   — fetch current material, formatted for injection
    (``Cookie:`` header, ``Authorization:`` header, header dict), with a
    staleness flag when ``expires_at`` has passed.
  - ``session_list``  — inventory all stored sessions with expiry status.
  - ``session_clear`` — drop a session (compromised / target rotated).

Acquisition is deliberately transport-agnostic: a real browser, an
operator paste, or an exploit agent that captured cookies all call the
same ``session_store``. The broker does not *perform* logins — it is the
vending layer that stops every downstream agent from repeating them.
"""

from __future__ import annotations

import json
import os
import re
import time
from pathlib import Path
from typing import Any

from langchain_core.tools import tool


def _workspace() -> Path:
    """Resolve the engagement workspace inside the sandbox."""
    for var in ("BUGGY_WORKSPACE_PATH", "WORKSPACE_PATH"):
        raw = os.environ.get(var)
        if raw and raw.strip():
            return Path(raw.strip())
    return Path("/workspace")


def _sessions_dir() -> Path:
    return _workspace() / "sessions"


_HOST_SAFE_RE = re.compile(r"[^a-zA-Z0-9._-]+")


def _host_slug(host: str) -> str:
    """Reduce a host/URL to a safe filename token.

    ``https://api.example.com:8443/app`` → ``api.example.com_8443`` — the
    port is kept (different ports can carry different session scopes) but
    scheme and path are dropped: a session is per origin, not per URL.
    """
    value = host.strip().lower()
    value = re.sub(r"^[a-z][a-z0-9+.\-]*://", "", value)
    value = value.split("/", 1)[0].split("@")[-1]
    slug = _HOST_SAFE_RE.sub("_", value.replace(":", "_")).strip("_")
    return slug or "unknown"


def _session_path(host: str) -> Path:
    return _sessions_dir() / f"{_host_slug(host)}.json"


def _json(data: Any) -> str:
    return json.dumps(data, indent=2, default=str, ensure_ascii=False)


def _read_session(path: Path) -> dict[str, Any] | None:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return data if isinstance(data, dict) else None


def _parse_headers(headers_json: str) -> dict[str, str]:
    """Parse an optional JSON header object; invalid input yields {}."""
    if not headers_json.strip():
        return {}
    try:
        data = json.loads(headers_json)
    except json.JSONDecodeError:
        return {}
    if not isinstance(data, dict):
        return {}
    return {str(k): str(v) for k, v in data.items()}


def _staleness(record: dict[str, Any], now: float) -> str:
    """``fresh`` | ``expired`` | ``unknown`` for one stored record."""
    raw = record.get("expires_at")
    if not isinstance(raw, (int, float)) or raw <= 0:
        return "unknown"
    return "expired" if raw <= now else "fresh"


@tool
def session_store(
    host: str,
    headers_json: str = "",
    cookies: str = "",
    token: str = "",
    expires_in_seconds: int = 0,
    source: str = "",
    notes: str = "",
) -> str:
    """Store authentication session material for a target host.

    Call this the moment any login flow, credential replay, or operator
    hand-off yields session material — BEFORE spending tool calls on
    authenticated requests. Downstream agents reuse it via ``session_get``
    instead of repeating the login.

    Args:
        host: Target host or URL (``api.example.com``, ``https://app:8443``).
            Sessions are keyed per origin — scheme and path are dropped,
            port is kept.
        headers_json: Optional JSON object of extra auth headers
            (``{"X-CSRF-Token": "..."}``).
        cookies: Cookie header value verbatim
            (``sessionid=abc; csrftoken=xyz``).
        token: Bearer token if the target uses one (stored separately so
            consumers can choose ``Authorization: Bearer`` formatting).
        expires_in_seconds: Seconds until the session is expected to die
            (0 = unknown). Sets ``expires_at`` for staleness reporting.
        source: How this session was acquired (``form-login``,
            ``operator``, ``credential-replay``).
        notes: Free-text (MFA caveats, CSRF rotation behaviour, etc.).

    Returns:
        JSON ``{stored: true, host, path, expires_at}`` or ``{error: ...}``.
    """
    if not host.strip():
        return _json({"error": "host is required"})
    if not (cookies.strip() or token.strip() or headers_json.strip()):
        return _json({"error": "nothing to store — provide cookies, token, or headers_json"})

    now = time.time()
    record: dict[str, Any] = {
        "host": host.strip(),
        "headers": _parse_headers(headers_json),
        "cookies": cookies.strip(),
        "token": token.strip(),
        "source": source.strip(),
        "notes": notes.strip(),
        "acquired_at": now,
        "expires_at": (now + expires_in_seconds) if expires_in_seconds > 0 else 0,
    }
    path = _session_path(host)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(record, indent=2), encoding="utf-8")
    except OSError as exc:
        return _json({"error": f"session write failed: {exc}"})
    return _json(
        {
            "stored": True,
            "host": record["host"],
            "path": str(path),
            "expires_at": record["expires_at"],
        }
    )


@tool
def session_get(host: str) -> str:
    """Retrieve stored session material for a host, formatted for injection.

    Call BEFORE making authenticated requests. Returns the raw parts plus
    ready-to-splice forms: ``cookie_header``, ``authorization_header`` and a
    merged ``headers`` dict you can pass straight to curl / proxy_send_request.
    A ``staleness`` field reports ``fresh`` / ``expired`` / ``unknown`` —
    an ``expired`` result means re-run the login flow and re-store, not
    that the material is unusable (some sessions outlive their TTL hint).

    Args:
        host: Target host or URL, same keying as ``session_store``.

    Returns:
        JSON ``{found: true, host, cookie_header, authorization_header,
        headers, staleness, source, acquired_at}`` or ``{found: false}``.
    """
    record = _read_session(_session_path(host))
    if record is None:
        return _json(
            {
                "found": False,
                "host": host.strip(),
                "hint": "no stored session — run the login flow, then session_store",
            }
        )

    headers: dict[str, str] = {}
    raw_headers = record.get("headers")
    if isinstance(raw_headers, dict):
        headers.update({str(k): str(v) for k, v in raw_headers.items()})
    cookie_header = str(record.get("cookies") or "")
    if cookie_header:
        headers["Cookie"] = cookie_header
    token = str(record.get("token") or "")
    authorization_header = f"Bearer {token}" if token else ""
    if authorization_header:
        headers["Authorization"] = authorization_header

    return _json(
        {
            "found": True,
            "host": record.get("host", host.strip()),
            "cookie_header": cookie_header,
            "authorization_header": authorization_header,
            "headers": headers,
            "staleness": _staleness(record, time.time()),
            "source": record.get("source", ""),
            "acquired_at": record.get("acquired_at", 0),
            "notes": record.get("notes", ""),
        }
    )


@tool
def session_list() -> str:
    """List every stored session with host, source, age, and staleness.

    Returns:
        JSON ``{sessions: [{host, source, staleness, age_seconds, notes}]}``.
    """
    root = _sessions_dir()
    sessions: list[dict[str, Any]] = []
    now = time.time()
    try:
        paths = sorted(root.glob("*.json")) if root.is_dir() else []
    except OSError:
        paths = []
    for path in paths:
        record = _read_session(path)
        if record is None:
            continue
        acquired = float(record.get("acquired_at") or 0)
        sessions.append(
            {
                "host": record.get("host", path.stem),
                "source": record.get("source", ""),
                "staleness": _staleness(record, now),
                "age_seconds": int(now - acquired) if acquired else None,
                "notes": record.get("notes", ""),
            }
        )
    return _json({"sessions": sessions})


@tool
def session_clear(host: str) -> str:
    """Delete the stored session for a host (compromised, rotated, or wrong).

    Returns:
        JSON ``{cleared: true|false, host}``.
    """
    path = _session_path(host)
    try:
        existed = path.exists()
        if existed:
            path.unlink()
    except OSError as exc:
        return _json({"error": f"session clear failed: {exc}"})
    return _json({"cleared": existed, "host": host.strip()})


SESSION_TOOLS = [session_store, session_get, session_list, session_clear]


__all__ = [
    "SESSION_TOOLS",
    "session_clear",
    "session_get",
    "session_list",
    "session_store",
]
