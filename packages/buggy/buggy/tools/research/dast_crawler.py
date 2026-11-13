"""Active DAST crawler — endpoint discovery + injection testing.

Crawls a target web application by following links and forms, then
tests discovered endpoints for common injection vulnerabilities using
non-destructive payloads.

Operates in two modes:
- **crawl**: discover endpoints, forms, and parameters
- **test**: inject payloads and analyse responses for vulnerability indicators

Uses httpx for HTTP requests. No browser/headless required for basic
crawling; Playwright can be layered on top for JS-rendered pages.
"""

from __future__ import annotations

import json
import re
from typing import Any
from urllib.parse import urljoin, urlparse

import httpx
from langchain_core.tools import tool

from buggy_core.utils.logging import get_logger

log = get_logger("research.dast_crawler")

_TIMEOUT = 10.0
_MAX_PAGES = 100
_MAX_DEPTH = 3

# ── Link / form extraction ───────────────────────────────────────────────

_LINK_RE = re.compile(r'href=["\']([^"\']+)["\']', re.IGNORECASE)
_FORM_RE = re.compile(r"(<form[^>]*>)(.*?)</form>", re.IGNORECASE | re.DOTALL)
_INPUT_RE = re.compile(
    r'<input[^>]*name=["\']([^"\']+)["\'][^>]*(?:type=["\']([^"\']+)["\'])?',
    re.IGNORECASE,
)
_ACTION_RE = re.compile(r'action=["\']([^"\']+)["\']', re.IGNORECASE)
_METHOD_RE = re.compile(r'method=["\']([^"\']+)["\']', re.IGNORECASE)


def _extract_links(html: str, base_url: str) -> list[str]:
    """Extract and normalise links from HTML."""
    links: list[str] = []
    for match in _LINK_RE.findall(html):
        url = urljoin(base_url, match)
        parsed = urlparse(url)
        base_parsed = urlparse(base_url)
        # Stay on same host
        if parsed.hostname == base_parsed.hostname:
            # Remove fragments
            clean = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            if parsed.query:
                clean += f"?{parsed.query}"
            links.append(clean)
    return links


def _extract_forms(html: str, page_url: str) -> list[dict[str, Any]]:
    """Extract forms and their inputs from HTML."""
    forms: list[dict[str, Any]] = []
    for form_tag, form_body in _FORM_RE.findall(html):
        action_match = _ACTION_RE.search(form_tag)
        method_match = _METHOD_RE.search(form_tag)
        action = urljoin(page_url, action_match.group(1)) if action_match else page_url
        method = method_match.group(1).upper() if method_match else "GET"
        inputs = []
        for input_match in _INPUT_RE.finditer(form_body):
            inputs.append(
                {
                    "name": input_match.group(1),
                    "type": input_match.group(2) or "text",
                }
            )
        if inputs:
            forms.append(
                {
                    "action": action,
                    "method": method,
                    "inputs": inputs,
                }
            )
    return forms


# ── Crawling logic ───────────────────────────────────────────────────────


def _crawl(
    base_url: str, max_pages: int = _MAX_PAGES, max_depth: int = _MAX_DEPTH
) -> dict[str, Any]:
    """Crawl a web application and discover endpoints + forms."""
    visited: set[str] = set()
    queue: list[tuple[str, int]] = [(base_url, 0)]
    endpoints: list[dict[str, Any]] = []
    forms: list[dict[str, Any]] = []
    errors: list[str] = []

    try:
        with httpx.Client(
            timeout=_TIMEOUT,
            follow_redirects=True,
        ) as client:
            while queue and len(visited) < max_pages:
                url, depth = queue.pop(0)
                if url in visited or depth > max_depth:
                    continue
                visited.add(url)

                try:
                    resp = client.get(url)
                    endpoints.append(
                        {
                            "url": url,
                            "status": resp.status_code,
                            "content_type": resp.headers.get("content-type", ""),
                            "depth": depth,
                        }
                    )

                    if "text/html" in resp.headers.get("content-type", ""):
                        page_links = _extract_links(resp.text, url)
                        page_forms = _extract_forms(resp.text, url)
                        forms.extend(page_forms)
                        for link in page_links:
                            if link not in visited:
                                queue.append((link, depth + 1))
                except httpx.HTTPError as exc:
                    errors.append(f"{url}: {exc}")
    except httpx.HTTPError as exc:
        errors.append(f"Client error: {exc}")

    # Build testable endpoints from forms: each form has an action URL,
    # HTTP method, and named inputs that can be fuzzed.
    testable: list[dict[str, Any]] = []
    for form in forms:
        testable.append(
            {
                "url": form["action"],
                "method": form["method"],
                "params": [inp["name"] for inp in form.get("inputs", [])],
            }
        )

    # Extract query-string parameter names from crawled URLs so they
    # are also available for injection testing.
    for ep in endpoints:
        parsed = urlparse(ep["url"])
        if parsed.query:
            param_names = [p.split("=", 1)[0] for p in parsed.query.split("&") if "=" in p]
            if param_names:
                testable.append(
                    {
                        "url": f"{parsed.scheme}://{parsed.netloc}{parsed.path}",
                        "method": "GET",
                        "params": param_names,
                    }
                )

    return {
        "base_url": base_url,
        "pages_crawled": len(visited),
        "endpoints": endpoints,
        "forms": forms[:50],
        "testable_endpoints": testable[:50],
        "errors": errors[:10],
    }


# ── Injection testing ────────────────────────────────────────────────────

_INJECTION_PAYLOADS: dict[str, list[dict[str, str]]] = {
    "sqli": [
        {"payload": "'", "indicator": "sql", "type": "error-based"},
        {"payload": "' OR '1'='1", "indicator": "always-true", "type": "boolean-based"},
        {"payload": "1; WAITFOR DELAY '0:0:5'", "indicator": "time", "type": "time-based"},
    ],
    "xss": [
        {"payload": "<script>alert(1)</script>", "indicator": "reflection", "type": "reflected"},
        {
            "payload": '"><img src=x onerror=alert(1)>',
            "indicator": "reflection",
            "type": "reflected",
        },
        {"payload": "{{7*7}}", "indicator": "49", "type": "template"},
    ],
    "path_traversal": [
        {"payload": "../../etc/passwd", "indicator": "root:", "type": "linux"},
        {"payload": "..\\..\\windows\\win.ini", "indicator": "[fonts]", "type": "windows"},
    ],
    "command_injection": [
        {"payload": "; id", "indicator": "uid=", "type": "unix"},
        {"payload": "| cat /etc/passwd", "indicator": "root:", "type": "unix"},
    ],
}

_SQL_ERROR_PATTERNS = re.compile(
    r"(?i)(sql\s*syntax|mysql|sqlite|postgres|oracle|ORA-\d+|"
    r"unclosed\s*quotation|quoted\s*string|SQLSTATE|PDOException|"
    r"pg_query|sqlite3\.OperationalError|unterminated)"
)


def _test_parameter(
    client: httpx.Client,
    url: str,
    method: str,
    param_name: str,
    payloads: list[dict[str, str]],
    vuln_type: str,
) -> list[dict[str, Any]]:
    """Test a single parameter with injection payloads."""
    findings: list[dict[str, Any]] = []
    for pl in payloads:
        try:
            if method == "GET":
                resp = client.get(url, params={param_name: pl["payload"]})
            else:
                resp = client.post(url, data={param_name: pl["payload"]})

            # Check for indicators
            found = False
            detail = ""
            if pl["indicator"] == "reflection" and pl["payload"] in resp.text:
                found = True
                detail = "Payload reflected in response"
            elif pl["indicator"] == "sql" and _SQL_ERROR_PATTERNS.search(resp.text):
                found = True
                detail = "SQL error message in response"
            elif pl["indicator"] not in ("reflection", "sql", "always-true", "time"):
                if pl["indicator"] in resp.text:
                    found = True
                    detail = f"Indicator '{pl['indicator']}' found in response"

            if found:
                findings.append(
                    {
                        "vulnerability_type": vuln_type,
                        "url": url,
                        "method": method,
                        "parameter": param_name,
                        "payload": pl["payload"],
                        "payload_type": pl["type"],
                        "detail": detail,
                        "status_code": resp.status_code,
                        "response_length": len(resp.text),
                    }
                )
        except httpx.HTTPError:
            continue
    return findings


def _json(data: Any) -> str:
    return json.dumps(data, indent=2, default=str)


# ── @tool wrappers ───────────────────────────────────────────────────────


@tool
def dast_crawl(
    base_url: str,
    max_pages: int = 50,
    max_depth: int = 3,
) -> str:
    """Crawl a web application and discover endpoints + forms.

    Follows links within the same host, extracts HTML forms with their
    inputs, and builds an endpoint inventory. Returns discovered pages,
    forms, and a ``testable_endpoints`` array (with ``url``, ``method``,
    ``params``) ready to pass directly to ``dast_test_endpoints``.
    """
    if not base_url.startswith(("http://", "https://")):
        return _json(
            {"error": "bad_request", "detail": "base_url must start with http:// or https://"}
        )

    result = _crawl(base_url, max_pages=max_pages, max_depth=max_depth)
    return _json(result)


@tool
def dast_test_endpoints(
    endpoints_json: str,
    vuln_types: str = "sqli,xss",
) -> str:
    """Test discovered endpoints for injection vulnerabilities.

    Takes a JSON array of testable endpoints where each entry has
    ``url``, ``method``, and ``params`` (list of parameter names).
    Use the ``testable_endpoints`` field from ``dast_crawl`` output
    directly.

    Supported vuln_types: sqli, xss, path_traversal, command_injection
    """
    try:
        endpoints = json.loads(endpoints_json)
        if not isinstance(endpoints, list):
            return _json({"error": "invalid_input", "detail": "Expected a JSON array"})
    except json.JSONDecodeError as exc:
        return _json({"error": "json_parse_error", "detail": str(exc)})

    selected_types = [t.strip() for t in vuln_types.split(",")]
    all_findings: list[dict[str, Any]] = []
    tests_run = 0

    try:
        with httpx.Client(
            timeout=_TIMEOUT,
            follow_redirects=True,
        ) as client:
            for ep in endpoints[:50]:
                url = ep.get("url", "")
                method = ep.get("method", "GET").upper()
                params = ep.get("params", [])

                for param in params:
                    for vtype in selected_types:
                        payloads = _INJECTION_PAYLOADS.get(vtype, [])
                        if payloads:
                            tests_run += len(payloads)
                            findings = _test_parameter(client, url, method, param, payloads, vtype)
                            all_findings.extend(findings)
    except httpx.HTTPError as exc:
        return _json({"error": "request_failed", "detail": str(exc)})

    return _json(
        {
            "endpoints_tested": min(len(endpoints), 50),
            "tests_run": tests_run,
            "total_findings": len(all_findings),
            "findings": all_findings[:100],
        }
    )


@tool
def dast_test_single(
    url: str,
    parameter: str,
    method: str = "GET",
    vuln_types: str = "sqli,xss,path_traversal,command_injection",
) -> str:
    """Test a single endpoint/parameter for injection vulnerabilities.

    Quick-test a specific parameter on a specific URL with all supported
    injection types. Useful for targeted testing of a known-interesting
    parameter.
    """
    if not url.startswith(("http://", "https://")):
        return _json({"error": "bad_request", "detail": "url must start with http:// or https://"})

    selected_types = [t.strip() for t in vuln_types.split(",")]
    all_findings: list[dict[str, Any]] = []
    tests_run = 0

    try:
        with httpx.Client(
            timeout=_TIMEOUT,
            follow_redirects=True,
        ) as client:
            for vtype in selected_types:
                payloads = _INJECTION_PAYLOADS.get(vtype, [])
                tests_run += len(payloads)
                findings = _test_parameter(client, url, method.upper(), parameter, payloads, vtype)
                all_findings.extend(findings)
    except httpx.HTTPError as exc:
        return _json({"error": "request_failed", "detail": str(exc)})

    return _json(
        {
            "url": url,
            "parameter": parameter,
            "method": method.upper(),
            "tests_run": tests_run,
            "total_findings": len(all_findings),
            "findings": all_findings,
        }
    )


DAST_TOOLS = [dast_crawl, dast_test_endpoints, dast_test_single]
