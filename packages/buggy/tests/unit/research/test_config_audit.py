"""Unit tests for the web security config audit tools.

No live HTTP/TLS calls — httpx and ssl are monkeypatched.
Tests verify header grading, HSTS validation, CSP checking, cookie
flag auditing, and CORS policy analysis.
"""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import httpx

from buggy.tools.research import config_audit as ca

# ── Helpers ──────────────────────────────────────────────────────────────


def _mock_response(
    headers: dict[str, str],
    status_code: int = 200,
    multi_headers: list[tuple[str, str]] | None = None,
) -> MagicMock:
    """Build a mock httpx.Response with the given headers."""
    resp = MagicMock(spec=httpx.Response)
    resp.status_code = status_code
    resp.headers = httpx.Headers(headers)
    if multi_headers:
        resp.headers = httpx.Headers(multi_headers)
    return resp


def _mock_client(resp: MagicMock) -> MagicMock:
    client = MagicMock()
    client.__enter__ = lambda self: client
    client.__exit__ = MagicMock(return_value=False)
    client.get.return_value = resp
    client.options.return_value = resp
    return client


# ── Header checks ────────────────────────────────────────────────────────


class TestCheckHsts:
    def test_good_hsts(self) -> None:
        issues = ca._check_hsts("max-age=31536000; includeSubDomains; preload")
        assert issues == []

    def test_short_max_age(self) -> None:
        issues = ca._check_hsts("max-age=3600")
        assert any("below recommended" in i for i in issues)

    def test_missing_include_subdomains(self) -> None:
        issues = ca._check_hsts("max-age=31536000")
        assert any("includeSubDomains" in i for i in issues)


class TestCheckCsp:
    def test_unsafe_inline(self) -> None:
        issues = ca._check_csp("default-src 'self' 'unsafe-inline'")
        assert any("unsafe-inline" in i for i in issues)

    def test_unsafe_eval(self) -> None:
        issues = ca._check_csp("default-src 'self' 'unsafe-eval'")
        assert any("unsafe-eval" in i for i in issues)

    def test_good_csp(self) -> None:
        issues = ca._check_csp("default-src 'self'; script-src 'self'")
        assert issues == []


class TestCheckCookies:
    def test_insecure_cookie(self) -> None:
        findings = ca._check_cookies(["session=abc123; Path=/"])
        assert len(findings) == 1
        issues = findings[0]["issues"]
        assert any("Secure" in i for i in issues)
        assert any("HttpOnly" in i for i in issues)
        assert any("SameSite" in i for i in issues)

    def test_secure_cookie(self) -> None:
        findings = ca._check_cookies(["session=abc; Secure; HttpOnly; SameSite=Strict; Path=/"])
        assert len(findings) == 0

    def test_samesite_none(self) -> None:
        findings = ca._check_cookies(["tok=x; Secure; HttpOnly; SameSite=None"])
        assert len(findings) == 1
        assert any("SameSite=None" in i for i in findings[0]["issues"])


# ── Header grading ───────────────────────────────────────────────────────


class TestGradeHeaders:
    def test_all_present(self) -> None:
        present = {
            "HSTS": "v",
            "CSP": "v",
            "X-CTO": "v",
            "XFO": "v",
            "Referrer": "v",
            "Permissions": "v",
        }
        grade = ca._grade_headers(present, [], [])
        assert grade == "A"

    def test_none_present(self) -> None:
        grade = ca._grade_headers({}, ["a", "b", "c", "d", "e", "f"], [])
        assert grade == "F"

    def test_leaks_reduce_grade(self) -> None:
        present = {
            "HSTS": "v",
            "CSP": "v",
            "X-CTO": "v",
            "XFO": "v",
            "Referrer": "v",
            "Permissions": "v",
        }
        grade = ca._grade_headers(present, [], ["leak1", "leak2", "leak3"])
        assert grade != "A"  # penalty applied


# ── Tool: audit_security_headers ─────────────────────────────────────────


class TestAuditSecurityHeaders:
    def test_all_present(self) -> None:
        resp = _mock_response(
            {
                "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
                "Content-Security-Policy": "default-src 'self'",
                "X-Content-Type-Options": "nosniff",
                "X-Frame-Options": "DENY",
                "Referrer-Policy": "strict-origin-when-cross-origin",
                "Permissions-Policy": "geolocation=()",
            }
        )
        client = _mock_client(resp)
        with patch("buggy.tools.research.config_audit.httpx.Client", return_value=client):
            result = json.loads(ca.audit_security_headers.invoke({"url": "https://example.com"}))
        assert result["grade"] == "A"
        assert len(result["missing_headers"]) == 0

    def test_missing_headers(self) -> None:
        resp = _mock_response({"X-Powered-By": "Express"})
        client = _mock_client(resp)
        with patch("buggy.tools.research.config_audit.httpx.Client", return_value=client):
            result = json.loads(ca.audit_security_headers.invoke({"url": "https://example.com"}))
        assert result["grade"] == "F"
        assert len(result["missing_headers"]) == 6
        assert len(result["information_leaks"]) >= 1


# ── Tool: audit_cors_policy ──────────────────────────────────────────────


class TestAuditCorsPolicy:
    def test_wildcard_with_creds(self) -> None:
        resp = _mock_response(
            {
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Credentials": "true",
            }
        )
        client = _mock_client(resp)
        with patch("buggy.tools.research.config_audit.httpx.Client", return_value=client):
            result = json.loads(ca.audit_cors_policy.invoke({"url": "https://example.com"}))
        assert any("CRITICAL" in i for i in result["issues"])

    def test_reflected_origin(self) -> None:
        resp = _mock_response(
            {
                "Access-Control-Allow-Origin": "https://evil.example.com",
                "Access-Control-Allow-Credentials": "true",
            }
        )
        client = _mock_client(resp)
        with patch("buggy.tools.research.config_audit.httpx.Client", return_value=client):
            result = json.loads(ca.audit_cors_policy.invoke({"url": "https://example.com"}))
        assert any("reflection" in i.lower() for i in result["issues"])

    def test_safe_cors(self) -> None:
        resp = _mock_response(
            {
                "Access-Control-Allow-Origin": "https://safe.example.com",
            }
        )
        client = _mock_client(resp)
        with patch("buggy.tools.research.config_audit.httpx.Client", return_value=client):
            result = json.loads(ca.audit_cors_policy.invoke({"url": "https://example.com"}))
        assert len(result["issues"]) == 0
