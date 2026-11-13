import pytest

from buggy_core.types.roe import MachineEnforcement, _glob_match, evaluate_target


def test_bug_bounty_wildcard_allows_only_direct_subdomains() -> None:
    rules = MachineEnforcement.from_dict(
        {"in_scope": [{"target": "*.anduril.dev", "type": "domain-glob"}]}
    )

    assert evaluate_target("sentry.anduril.dev", rules).allow
    assert not evaluate_target("internal.sentry.anduril.dev", rules).allow


def test_bug_bounty_wildcard_does_not_expand_to_apex_or_lookalike() -> None:
    rules = MachineEnforcement.from_dict(
        {"in_scope": [{"target": "*.anduril.dev", "type": "domain-glob"}]}
    )

    assert not evaluate_target("anduril.dev", rules).allow
    assert not evaluate_target("internal.sentry.anduril.dev.evil.test", rules).allow
    assert not evaluate_target("evil-anduril.dev", rules).allow


def test_explicit_exclusion_overrides_direct_subdomain_wildcard() -> None:
    rules = MachineEnforcement.from_dict(
        {
            "in_scope": [
                {"target": "*.anduril.dev", "type": "domain-glob"},
            ],
            "out_of_scope": [
                {"target": "sentry.anduril.dev", "type": "host"},
            ],
        }
    )

    decision = evaluate_target("sentry.anduril.dev", rules)

    assert not decision.allow
    assert decision.reason_code == "OUT_OF_SCOPE"


@pytest.mark.parametrize(
    ("pattern", "host", "allowed"),
    [
        ("*.example.com", "api.example.com", True),
        ("*.example.com", "API.EXAMPLE.COM", True),
        ("*.example.com", "example.com", False),
        ("*.example.com", "a.b.example.com", False),
        ("*.example.com", ".example.com", False),
        ("*.example.com", "api.example.com.evil.test", False),
        ("?.example.com", "a.example.com", True),
        ("?.example.com", "ab.example.com", False),
        ("?.example.com", "..example.com", False),
    ],
)
def test_domain_globs_respect_label_boundaries(pattern: str, host: str, allowed: bool) -> None:
    assert _glob_match(pattern, host) is allowed


def test_deeper_host_requires_explicit_scope() -> None:
    rules = MachineEnforcement.from_dict({"in_scope": ["*.example.com", "a.b.example.com"]})
    assert evaluate_target("a.b.example.com", rules).allow
    assert not evaluate_target("c.b.example.com", rules).allow


def test_exclusion_wildcard_has_the_same_depth_limit() -> None:
    rules = MachineEnforcement.from_dict(
        {
            "in_scope": ["a.example.com", "a.b.example.com"],
            "out_of_scope": ["*.example.com"],
        }
    )
    assert evaluate_target("a.example.com", rules).reason_code == "OUT_OF_SCOPE"
    assert evaluate_target("a.b.example.com", rules).allow
