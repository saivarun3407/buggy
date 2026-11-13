"""Web security configuration auditing — headers, TLS, cookies.

Pure-Python checks against live HTTP responses. No external binary
required. Covers the OWASP Secure Headers Project recommendations and
common ASVS verification requirements for transport security.
"""

from __future__ import annotations

import json
import re
import socket
import ssl
from typing import Any
from urllib.parse import urlparse

import httpx
from langchain_core.tools import tool

from buggy_core.utils.logging import get_logger

log = get_logger("research.config_audit")

_TIMEOUT = 15.0


# ── Security header checks ───────────────────────────────────────────────

_REQUIRED_HEADERS: list[tuple[str, str, str]] = [
    ("Strict-Transport-Security", "HSTS", "Missing HSTS — browsers will accept plain HTTP"),
    ("Content-Security-Policy", "CSP", "Missing CSP — no XSS mitigation at browser level"),
    (
        "X-Content-Type-Options",
        "X-CTO",
        "Missing X-Content-Type-Options — MIME-sniffing attacks possible",
    ),
    ("X-Frame-Options", "XFO", "Missing X-Frame-Options — clickjacking possible"),
    ("Referrer-Policy", "Referrer", "Missing Referrer-Policy — referrer leaks to third parties"),
    (
        "Permissions-Policy",
        "Permissions",
        "Missing Permissions-Policy — browser features unrestricted",
    ),
]

_DEPRECATED_HEADERS: list[tuple[str, str]] = [
    ("X-Powered-By", "Leaks server technology — remove X-Powered-By"),
    ("Server", "Server banner reveals version — suppress or genericize"),
    ("X-AspNet-Version", "Leaks ASP.NET version — remove"),
    ("X-AspNetMvc-Version", "Leaks MVC version — remove"),
]


def _grade_headers(present: dict[str, str], missing: list[str], leaks: list[str]) -> str:
    """A-F grade based on header coverage and information leakage."""
    total = len(present) + len(missing)
    score = len(present) / max(total, 1)
    penalty = len(leaks) * 0.1
    final = max(0.0, score - penalty)
    if final >= 0.9:
        return "A"
    if final >= 0.7:
        return "B"
    if final >= 0.5:
        return "C"
    if final >= 0.3:
        return "D"
    return "F"


def _check_hsts(value: str) -> list[str]:
    """Validate HSTS header value."""
    issues: list[str] = []
    age_match = re.search(r"max-age=(\d+)", value, re.IGNORECASE)
    if age_match:
        age = int(age_match.group(1))
        if age < 31536000:
            issues.append(f"HSTS max-age={age} is below recommended 1 year (31536000)")
    else:
        issues.append("HSTS missing max-age directive")
    if "includesubdomains" not in value.lower():
        issues.append("HSTS missing includeSubDomains")
    return issues


def _check_csp(value: str) -> list[str]:
    """Basic CSP policy audit."""
    issues: list[str] = []
    val_lower = value.lower()
    if "'unsafe-inline'" in val_lower:
        issues.append("CSP allows 'unsafe-inline' — weakens XSS protection")
    if "'unsafe-eval'" in val_lower:
        issues.append("CSP allows 'unsafe-eval' — allows eval() calls")
    if "default-src" not in val_lower and "script-src" not in val_lower:
        issues.append("CSP has no default-src or script-src — incomplete policy")
    # Flag bare wildcard sources (e.g. "* " or "'*'") but not subdomain
    # wildcards like "*.googleapis.com".
    csp_tokens = re.split(r"[\s;]+", value)
    if any(tok.strip("'\"") == "*" for tok in csp_tokens):
        issues.append("CSP uses wildcard (*) source — overly permissive")
    return issues


def _check_cookies(set_cookie_headers: list[str]) -> list[dict[str, Any]]:
    """Audit Set-Cookie headers for security flags."""
    findings: list[dict[str, Any]] = []
    for header in set_cookie_headers:
        parts = header.split(";")
        name_value = parts[0].strip()
        name = name_value.split("=", 1)[0].strip() if "=" in name_value else name_value
        flags_str = header.lower()
        issues: list[str] = []
        if "secure" not in flags_str:
            issues.append("Missing Secure flag — cookie sent over HTTP")
        if "httponly" not in flags_str:
            issues.append("Missing HttpOnly flag — cookie accessible to JavaScript")
        if "samesite" not in flags_str:
            issues.append("Missing SameSite attribute — CSRF risk")
        elif "samesite=none" in flags_str:
            issues.append("SameSite=None — cookie sent on cross-site requests")
        if issues:
            findings.append({"cookie": name, "issues": issues})
    return findings


def _json(data: Any) -> str:
    return json.dumps(data, indent=2, default=str)


# ── TLS checks ───────────────────────────────────────────────────────────

_WEAK_CIPHERS = re.compile(r"(?i)(RC4|DES|3DES|MD5|NULL|EXPORT|anon)")
_WEAK_PROTOCOLS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.0", "TLSv1.1"}


def _check_tls(host: str, port: int) -> dict[str, Any]:
    """Check TLS configuration for a host."""
    result: dict[str, Any] = {"host": host, "port": port, "issues": []}
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=_TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                result["protocol"] = ssock.version()
                cipher = ssock.cipher()
                if cipher:
                    result["cipher_name"] = cipher[0]
                    result["cipher_protocol"] = cipher[1]
                    result["cipher_bits"] = cipher[2]
                    if _WEAK_CIPHERS.search(cipher[0]):
                        result["issues"].append(f"Weak cipher in use: {cipher[0]}")
                    if cipher[2] and cipher[2] < 128:
                        result["issues"].append(f"Cipher key length {cipher[2]} bits is below 128")
                cert = ssock.getpeercert()
                if cert:
                    subj: Any = cert.get("subject", ())
                    result["subject"] = dict(x[0] for x in subj) if subj else {}
                    iss: Any = cert.get("issuer", ())
                    result["issuer"] = dict(x[0] for x in iss) if iss else {}
                    result["not_after"] = cert.get("notAfter", "")
                    san = cert.get("subjectAltName", [])
                    result["san_count"] = len(san)
                proto = result.get("protocol", "")
                if proto in _WEAK_PROTOCOLS:
                    result["issues"].append(f"Weak TLS protocol: {proto}")
    except ssl.SSLError as exc:
        result["issues"].append(f"SSL error: {exc}")
    except (OSError, TimeoutError) as exc:
        result["issues"].append(f"Connection failed: {type(exc).__name__}")
    result["grade"] = "A" if not result["issues"] else ("C" if len(result["issues"]) <= 1 else "F")
    return result


# ── @tool wrappers ───────────────────────────────────────────────────────


@tool
def audit_security_headers(url: str) -> str:
    """Check HTTP security headers for a URL.

    Fetches the URL and inspects response headers against OWASP Secure
    Headers Project recommendations. Checks for: HSTS, CSP, X-CTO,
    X-Frame-Options, Referrer-Policy, Permissions-Policy. Also flags
    information-leaking headers (Server, X-Powered-By). Returns an A-F
    grade and actionable findings.
    """
    try:
        with httpx.Client(
            timeout=_TIMEOUT,
            follow_redirects=True,
        ) as client:
            resp = client.get(url)
    except httpx.HTTPError as exc:
        return _json({"error": "request_failed", "url": url, "detail": str(exc)})

    headers_lower = {k.lower(): v for k, v in resp.headers.items()}
    present: dict[str, str] = {}
    missing: list[str] = []
    details: list[dict[str, Any]] = []

    for header, short, msg in _REQUIRED_HEADERS:
        val = headers_lower.get(header.lower(), "")
        if val:
            present[short] = val
            if header.lower() == "strict-transport-security":
                issues = _check_hsts(val)
                if issues:
                    details.append({"header": header, "value": val, "issues": issues})
            elif header.lower() == "content-security-policy":
                issues = _check_csp(val)
                if issues:
                    details.append({"header": header, "value": val[:200], "issues": issues})
        else:
            missing.append(msg)

    leaks: list[str] = []
    for header, msg in _DEPRECATED_HEADERS:
        val = headers_lower.get(header.lower(), "")
        if val:
            leaks.append(f"{msg} (value: {val[:100]})")

    cookie_headers = [v for k, v in resp.headers.multi_items() if k.lower() == "set-cookie"]
    cookie_findings = _check_cookies(cookie_headers)

    grade = _grade_headers(present, missing, leaks)
    return _json(
        {
            "url": url,
            "status_code": resp.status_code,
            "grade": grade,
            "present_headers": present,
            "missing_headers": missing,
            "header_issues": details,
            "information_leaks": leaks,
            "cookie_issues": cookie_findings,
        }
    )


@tool
def audit_tls_config(host: str, port: int = 443) -> str:
    """Check TLS/SSL configuration for a host.

    Connects to the host and inspects the negotiated protocol, cipher
    suite, key length, and certificate details. Flags weak protocols
    (SSLv2/3, TLS 1.0/1.1), weak ciphers (RC4, DES, NULL), and short
    key lengths. Returns an A/C/F grade.
    """
    parsed = urlparse(host)
    if parsed.hostname:
        host = parsed.hostname
        if parsed.port:
            port = parsed.port
    return _json(_check_tls(host, port))


@tool
def audit_cors_policy(url: str, test_origin: str = "https://evil.example.com") -> str:
    """Test CORS policy by sending a preflight with a foreign origin.

    Sends an OPTIONS request with ``Origin: <test_origin>`` and inspects
    ``Access-Control-Allow-Origin``, ``Allow-Credentials``, and
    ``Allow-Methods``. Flags overly permissive CORS (wildcard + credentials,
    reflecting arbitrary origins).
    """
    try:
        with httpx.Client(
            timeout=_TIMEOUT,
            follow_redirects=True,
        ) as client:
            resp = client.options(
                url,
                headers={"Origin": test_origin, "Access-Control-Request-Method": "GET"},
            )
    except httpx.HTTPError as exc:
        return _json({"error": "request_failed", "url": url, "detail": str(exc)})

    acao = resp.headers.get("access-control-allow-origin", "")
    acac = resp.headers.get("access-control-allow-credentials", "").lower()
    acam = resp.headers.get("access-control-allow-methods", "")
    issues: list[str] = []

    if acao == "*":
        issues.append("CORS allows any origin (wildcard *)")
        if acac == "true":
            issues.append(
                "CRITICAL: wildcard origin + credentials=true — any site can read authenticated responses"
            )
    elif acao.lower() == test_origin.lower():
        issues.append(f"CORS reflects the test origin ({test_origin}) — may reflect any origin")
        if acac == "true":
            issues.append("Origin reflection + credentials=true — potential credential theft")

    return _json(
        {
            "url": url,
            "test_origin": test_origin,
            "access_control_allow_origin": acao,
            "access_control_allow_credentials": acac,
            "access_control_allow_methods": acam,
            "issues": issues,
            "status_code": resp.status_code,
        }
    )


CONFIG_AUDIT_TOOLS = [audit_security_headers, audit_tls_config, audit_cors_policy]
