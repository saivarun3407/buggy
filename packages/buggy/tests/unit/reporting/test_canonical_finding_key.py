"""Write-side finding dedup — ``_canonical_finding_key``.

Two agents reporting the same bug with different wording must collide on
the same KG key so ``record_observations`` MERGEs instead of duplicating.
"""

from __future__ import annotations

from buggy.tools.reporting.kg_adapter import _canonical_finding_key


def test_same_bug_different_wording_collapses() -> None:
    a = _canonical_finding_key(
        {
            "title": "SQL Injection on /login",
            "target": "https://api.example.com:443/login?next=/home",
            "kind": "sqli",
        }
    )
    b = _canonical_finding_key(
        {
            "title": "SQLi in the login endpoint",
            "target": "api.example.com/login",
            "kind": "sqli",
        }
    )
    assert a == b


def test_different_endpoint_produces_different_key() -> None:
    a = _canonical_finding_key({"title": "sqli", "target": "api.example.com/login", "kind": "sqli"})
    b = _canonical_finding_key(
        {"title": "sqli", "target": "api.example.com/search", "kind": "sqli"}
    )
    assert a != b


def test_different_class_same_endpoint_differs() -> None:
    a = _canonical_finding_key({"title": "sqli", "target": "api.example.com/x", "kind": "sqli"})
    b = _canonical_finding_key({"title": "xss", "target": "api.example.com/x", "kind": "xss"})
    assert a != b


def test_explicit_key_always_wins() -> None:
    key = _canonical_finding_key(
        {"key": "custom::id", "title": "x", "target": "a.com", "kind": "x"}
    )
    assert key == "custom::id"


def test_no_location_falls_back_to_title_key() -> None:
    key = _canonical_finding_key({"title": "Misconfigured TLS"})
    assert key == "finding::Misconfigured TLS"


def test_class_falls_back_to_title_slug() -> None:
    key = _canonical_finding_key(
        {"title": "Broken Access Control", "target": "api.example.com/users"}
    )
    assert key == "finding::api.example.com/users::broken-access-control"


def test_cwe_used_as_class() -> None:
    a = _canonical_finding_key({"title": "sqli", "target": "h.example.com/a", "cwe": "CWE-89"})
    b = _canonical_finding_key(
        {"title": "sql injection", "target": "h.example.com/a", "cwe": "CWE-89"}
    )
    assert a == b
