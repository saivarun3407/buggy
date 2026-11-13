"""Session broker tools — store/get/list/clear round-trip semantics."""

from __future__ import annotations

import json
import time
from pathlib import Path

import pytest

from buggy.tools.session.tools import (
    _host_slug,
    session_clear,
    session_get,
    session_list,
    session_store,
)


@pytest.fixture()
def workspace(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Point the broker's workspace resolution at a temp dir."""
    monkeypatch.setenv("BUGGY_WORKSPACE_PATH", str(tmp_path))
    monkeypatch.delenv("WORKSPACE_PATH", raising=False)
    return tmp_path


def _payload(raw: str) -> dict:
    return json.loads(raw)


# ── host slugging ──────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("host", "slug"),
    [
        ("api.example.com", "api.example.com"),
        ("https://api.example.com/app/path", "api.example.com"),
        ("https://api.example.com:8443/app", "api.example.com_8443"),
        ("user@example.com", "example.com"),
        ("EXAMPLE.COM", "example.com"),
    ],
)
def test_host_slug_normalizes_origin(host: str, slug: str) -> None:
    """A session is per origin: scheme/path/userinfo drop, port keeps."""
    assert _host_slug(host) == slug


# ── store ──────────────────────────────────────────────────────────────


def test_store_rejects_empty_material(workspace: Path) -> None:
    payload = _payload(session_store.invoke({"host": "api.example.com"}))
    assert "error" in payload


def test_store_rejects_empty_host(workspace: Path) -> None:
    payload = _payload(session_store.invoke({"host": "  ", "token": "t"}))
    assert "error" in payload


def test_store_then_get_roundtrip(workspace: Path) -> None:
    stored = _payload(
        session_store.invoke(
            {
                "host": "api.example.com",
                "cookies": "sessionid=abc; csrf=xyz",
                "token": "tok-123",
                "headers_json": '{"X-App": "1"}',
                "expires_in_seconds": 3600,
                "source": "form-login",
            }
        )
    )
    assert stored["stored"] is True
    assert stored["expires_at"] > time.time()

    got = _payload(session_get.invoke({"host": "https://api.example.com/admin"}))
    assert got["found"] is True
    assert got["cookie_header"] == "sessionid=abc; csrf=xyz"
    assert got["authorization_header"] == "Bearer tok-123"
    assert got["headers"]["Cookie"] == "sessionid=abc; csrf=xyz"
    assert got["headers"]["Authorization"] == "Bearer tok-123"
    assert got["headers"]["X-App"] == "1"
    assert got["staleness"] == "fresh"
    assert got["source"] == "form-login"


def test_get_missing_session(workspace: Path) -> None:
    got = _payload(session_get.invoke({"host": "nope.example.com"}))
    assert got["found"] is False
    assert "hint" in got


def test_expired_session_flagged_not_dropped(workspace: Path) -> None:
    session_store.invoke({"host": "api.example.com", "token": "t", "expires_in_seconds": -1})
    got = _payload(session_get.invoke({"host": "api.example.com"}))
    # expires_in_seconds <= 0 means "unknown" TTL — never auto-expires.
    assert got["found"] is True
    assert got["staleness"] == "unknown"


def test_list_inventories_sessions(workspace: Path) -> None:
    session_store.invoke({"host": "a.example.com", "token": "1"})
    session_store.invoke({"host": "b.example.com", "cookies": "c=2"})
    listed = _payload(session_list.invoke({}))
    hosts = {s["host"] for s in listed["sessions"]}
    assert hosts == {"a.example.com", "b.example.com"}


def test_clear_removes_session(workspace: Path) -> None:
    session_store.invoke({"host": "a.example.com", "token": "1"})
    cleared = _payload(session_clear.invoke({"host": "a.example.com"}))
    assert cleared["cleared"] is True
    again = _payload(session_clear.invoke({"host": "a.example.com"}))
    assert again["cleared"] is False
    assert _payload(session_get.invoke({"host": "a.example.com"}))["found"] is False


def test_invalid_headers_json_falls_back_to_empty(workspace: Path) -> None:
    """A malformed headers_json must not lose the rest of the session."""
    session_store.invoke({"host": "a.example.com", "headers_json": "not-json", "token": "t"})
    got = _payload(session_get.invoke({"host": "a.example.com"}))
    assert got["found"] is True
    assert got["headers"]["Authorization"] == "Bearer t"
