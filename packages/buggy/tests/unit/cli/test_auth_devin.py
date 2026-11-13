"""Tests for the agent-subscription (Devin) surface of the auth report.

Covers the CLI rendering of the new group, the no-model-backend hint
that points at delegation, and the factory helper that builds the
Devin entry with the same two-gate contract as OAuth methods.
"""

from __future__ import annotations

import json

import pytest

from buggy.cli import auth
from buggy.llm import factory
from buggy.llm.factory import AgentSubscriptionStatus
from buggy_core.subscriptions import DevinCLIStatus


def _probe_ok() -> DevinCLIStatus:
    return DevinCLIStatus(
        bin_path="/opt/devin", installed=True, authenticated=True, detail="Logged in (via Devin)."
    )


def _devin_sub(configured: bool, detail: str = "Logged in (via Devin).") -> AgentSubscriptionStatus:
    return AgentSubscriptionStatus(
        name="devin",
        label="Devin CLI — agent delegation",
        env_var="BUGGY_AUTH_DEVIN",
        configured=configured,
        detail=detail,
    )


def _make_inventory(**kwargs):
    return factory.AuthInventory(
        statuses=(),
        resolved_chain=kwargs.pop("resolved_chain", ()),
        priority_explicit=False,
        agent_subscriptions=kwargs.pop("agent_subscriptions", (_devin_sub(False),)),
    )


def test_render_includes_agent_group():
    text = auth._render_text(_make_inventory(agent_subscriptions=(_devin_sub(True),)))
    assert "Agent subscriptions (delegation)" in text
    assert "✓ avail." in text
    assert "Logged in (via Devin)." in text


def test_render_agent_group_unconfigured():
    text = auth._render_text(_make_inventory(agent_subscriptions=(_devin_sub(False),)))
    assert "Agent subscriptions (delegation)" in text
    assert "✓ avail." not in text


def test_render_no_chain_hints_at_delegation():
    inv = _make_inventory(resolved_chain=(), agent_subscriptions=(_devin_sub(True),))
    text = auth._render_text(inv)
    assert "No usable credential detected" in text
    assert "Agent delegation IS available" in text
    assert "devin_delegate" in text


def test_render_chain_present_no_delegation_hint():
    inv = _make_inventory(
        resolved_chain=(factory.AuthMethod.OPENAI_API,),
        agent_subscriptions=(_devin_sub(True),),
    )
    text = auth._render_text(inv)
    assert "Resolved fallback chain" in text
    assert "Agent delegation IS available" not in text


def test_render_no_agent_group_when_empty():
    text = auth._render_text(_make_inventory(agent_subscriptions=()))
    assert "Agent subscriptions (delegation)" not in text


def test_json_includes_agent_subscriptions():
    inv = _make_inventory(agent_subscriptions=(_devin_sub(True),))
    payload = json.loads(auth._render_json(inv))
    (entry,) = payload["agent_subscriptions"]
    assert entry["name"] == "devin"
    assert entry["configured"] is True
    assert entry["env_var"] == "BUGGY_AUTH_DEVIN"


def test_factory_devin_status_flag_unset_skips_probe(monkeypatch):
    monkeypatch.delenv("BUGGY_AUTH_DEVIN", raising=False)

    def _boom():
        raise AssertionError("probe must not run when the intent flag is unset")

    monkeypatch.setattr(factory, "probe_devin_cli", _boom)
    status = factory._devin_subscription_status()
    assert status.configured is False
    assert "BUGGY_AUTH_DEVIN" in status.detail


def test_factory_devin_status_authenticated(monkeypatch):
    monkeypatch.setenv("BUGGY_AUTH_DEVIN", "true")
    monkeypatch.setattr(factory, "probe_devin_cli", _probe_ok)
    status = factory._devin_subscription_status()
    assert status.configured is True
    assert status.detail == "Logged in (via Devin)."


def test_factory_devin_status_flag_set_but_logged_out(monkeypatch):
    monkeypatch.setenv("BUGGY_AUTH_DEVIN", "true")

    from buggy_core.subscriptions import DevinCLIStatus

    monkeypatch.setattr(
        factory,
        "probe_devin_cli",
        lambda: DevinCLIStatus(
            bin_path="/opt/devin",
            installed=True,
            authenticated=False,
            detail="devin auth status exited 1",
        ),
    )
    status = factory._devin_subscription_status()
    assert status.configured is False
    assert "exited 1" in status.detail


@pytest.mark.parametrize("env_value", ["true", "1", "yes"])
def test_doctor_still_model_based_with_only_devin(monkeypatch, env_value, capsys):
    # Devin delegation alone must NOT flip doctor to success — the agents
    # themselves still need a model method to think.
    for name in (
        *factory._API_METHOD_ENV.values(),
        *factory._OAUTH_METHOD_ENV.values(),
        *factory._LOCAL_METHOD_ENV.values(),
        "BUGGY_AUTH_PRIORITY",
        "BUGGY_AUTH_DEVIN",
        "DEVIN_BIN",
    ):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("BUGGY_AUTH_DEVIN", env_value)
    # Stub the probe at the factory layer — the CLI resolves through it.
    monkeypatch.setattr(factory, "probe_devin_cli", _probe_ok)
    assert auth.main(["doctor", "--no-env-file"]) == auth.EXIT_CONFIG
