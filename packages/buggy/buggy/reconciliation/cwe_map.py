"""Deterministic CWE → reconciliation-class routing.

Every schema-valid SARIF result reaches a class: a CWE this table names routes
to its specific class and priority; an unrecognized-but-well-formed CWE routes
to ``miscellaneous`` at the lowest priority rather than being dropped. That is
what lets the exploitation queue stay complete — an unmapped bug still gets its
own task, just without a specific category name.

Clean-room routing design (original
``reconciliation/sast/cwe-mapper.ts`` (AGPL). The table below is an original
Python mapping keyed on public CWE identifiers (which are facts, not the
donor's expression); it is not a line-by-line port and intentionally carries a
practical subset tuned for web-app engagements.
"""

from __future__ import annotations

from typing import NamedTuple

from buggy.reconciliation.contracts import Priority, VulnClass


class CweRoute(NamedTuple):
    """Where a CWE routes: its class, a human name, and a priority band."""

    vuln_class: VulnClass
    name: str
    priority: Priority


# CWE id (``CWE-NNN``) → route. Grouped by class for readability.
CWE_TO_ROUTE: dict[str, CweRoute] = {
    # ── injection ──────────────────────────────────────────────────────
    "CWE-89": CweRoute("injection", "SQL Injection", "P1"),
    "CWE-78": CweRoute("injection", "OS Command Injection", "P1"),
    "CWE-94": CweRoute("injection", "Code Injection", "P1"),
    "CWE-95": CweRoute("injection", "Eval Injection", "P1"),
    "CWE-502": CweRoute("injection", "Deserialization", "P1"),
    "CWE-611": CweRoute("injection", "XXE", "P1"),
    "CWE-22": CweRoute("injection", "Path Traversal", "P1"),
    "CWE-434": CweRoute("injection", "Unrestricted File Upload", "P1"),
    "CWE-943": CweRoute("injection", "NoSQL Injection", "P1"),
    "CWE-1336": CweRoute("injection", "Template Injection", "P1"),
    "CWE-1321": CweRoute("injection", "Prototype Pollution", "P1"),
    "CWE-90": CweRoute("injection", "LDAP Injection", "P2"),
    "CWE-91": CweRoute("injection", "XML Injection", "P2"),
    "CWE-643": CweRoute("injection", "XPath Injection", "P2"),
    "CWE-93": CweRoute("injection", "CRLF Injection", "P2"),
    "CWE-117": CweRoute("injection", "Log Injection", "P2"),
    "CWE-1427": CweRoute("injection", "Prompt Injection", "P2"),
    # ── xss ────────────────────────────────────────────────────────────
    "CWE-79": CweRoute("xss", "Cross-Site Scripting", "P1"),
    "CWE-80": CweRoute("xss", "Basic XSS", "P1"),
    "CWE-83": CweRoute("xss", "Improper Neutralization of Script in Attributes", "P2"),
    # ── auth ───────────────────────────────────────────────────────────
    "CWE-287": CweRoute("auth", "Broken Authentication", "P1"),
    "CWE-306": CweRoute("auth", "Missing Authentication", "P1"),
    "CWE-798": CweRoute("auth", "Hard-coded Credentials", "P1"),
    "CWE-522": CweRoute("auth", "Insufficiently Protected Credentials", "P1"),
    "CWE-319": CweRoute("auth", "Cleartext Transmission", "P2"),
    "CWE-330": CweRoute("auth", "Insufficient Randomness", "P2"),
    "CWE-338": CweRoute("auth", "Weak PRNG", "P2"),
    "CWE-295": CweRoute("auth", "Improper Certificate Validation", "P2"),
    "CWE-347": CweRoute("auth", "Improper Signature Verification", "P2"),
    "CWE-327": CweRoute("auth", "Broken Cryptographic Algorithm", "P3"),
    "CWE-328": CweRoute("auth", "Weak Hash", "P3"),
    "CWE-614": CweRoute("auth", "Cookie without Secure Flag", "P3"),
    "CWE-1004": CweRoute("auth", "Cookie without HttpOnly", "P3"),
    # ── authz ──────────────────────────────────────────────────────────
    "CWE-639": CweRoute("authz", "IDOR", "P1"),
    "CWE-285": CweRoute("authz", "Broken Authorization", "P1"),
    "CWE-862": CweRoute("authz", "Missing Authorization", "P1"),
    "CWE-863": CweRoute("authz", "Incorrect Authorization", "P1"),
    "CWE-269": CweRoute("authz", "Privilege Escalation", "P1"),
    "CWE-284": CweRoute("authz", "Improper Access Control", "P1"),
    "CWE-915": CweRoute("authz", "Mass Assignment", "P1"),
    "CWE-359": CweRoute("authz", "PII Exposure", "P1"),
    "CWE-732": CweRoute("authz", "Incorrect Permission Assignment", "P2"),
    # ── ssrf ───────────────────────────────────────────────────────────
    "CWE-918": CweRoute("ssrf", "Server-Side Request Forgery", "P1"),
    # ── miscellaneous (named, but generalist class) ────────────────────
    "CWE-352": CweRoute("miscellaneous", "CSRF", "P1"),
    "CWE-601": CweRoute("miscellaneous", "Open Redirect", "P2"),
    "CWE-1236": CweRoute("miscellaneous", "CSV Formula Injection", "P2"),
    "CWE-1021": CweRoute("miscellaneous", "Clickjacking", "P3"),
    "CWE-1333": CweRoute("miscellaneous", "ReDoS", "P3"),
    "CWE-489": CweRoute("miscellaneous", "Active Debug Code", "P3"),
    "CWE-532": CweRoute("miscellaneous", "Sensitive Logging", "P3"),
    "CWE-922": CweRoute("miscellaneous", "Insecure Storage", "P3"),
}

_CWE_FORMAT_HINT = "expected a bare CWE identifier like 'CWE-89'"


def normalize_cwe(raw: str) -> str | None:
    """Return a canonical ``CWE-NNN`` id, or ``None`` if ``raw`` is not one.

    Accepts case-insensitive ``cwe-89`` and a bare numeric ``89``. Anything
    that is not a positive CWE number returns ``None`` so the caller can decide
    whether to drop the finding or route it to ``miscellaneous``.
    """
    text = raw.strip().upper()
    if not text:
        return None
    if text.startswith("CWE-"):
        digits = text[4:]
    else:
        digits = text
    if not digits.isdigit():
        return None
    number = int(digits)
    if number <= 0:
        return None
    return f"CWE-{number}"


def class_for_cwe(raw: str) -> CweRoute | None:
    """Route a CWE to its class. ``None`` only when ``raw`` is not a CWE id.

    A well-formed but unrecognized CWE (e.g. ``CWE-9999``) never returns
    ``None`` — it routes to ``miscellaneous`` at ``P3`` so the finding keeps a
    place in the queue. ``None`` is reserved for input that is not a CWE at all,
    which the intake layer treats as a drop.
    """
    canonical = normalize_cwe(raw)
    if canonical is None:
        return None
    route = CWE_TO_ROUTE.get(canonical)
    if route is not None:
        return route
    return CweRoute("miscellaneous", canonical, "P3")


__all__ = [
    "CWE_TO_ROUTE",
    "CweRoute",
    "class_for_cwe",
    "normalize_cwe",
]
