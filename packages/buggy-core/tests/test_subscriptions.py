"""Tests for the Devin CLI agent-subscription probe (core.subscriptions).

The probe is the single detection point shared by the auth inventory and
the delegation-tool gate, so its failure modes fold into a status object
instead of raising — every test here pins one of those folds.
"""

from __future__ import annotations

import subprocess

import pytest

import buggy_core.subscriptions as subs
from buggy_core.subscriptions import (
    BUGGY_AUTH_DEVIN_ENV,
    DevinCLIStatus,
    devin_available,
    devin_intent_enabled,
    probe_devin_cli,
    resolve_devin_bin,
)


def _completed(
    returncode: int = 0, stdout: str = "", stderr: str = ""
) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(args=[], returncode=returncode, stdout=stdout, stderr=stderr)


@pytest.mark.parametrize("value", ("true", "1", "yes", "on", "TRUE"))
def test_intent_flag_truthy_values(monkeypatch, value):
    monkeypatch.setenv(BUGGY_AUTH_DEVIN_ENV, value)
    assert devin_intent_enabled() is True


@pytest.mark.parametrize("value", ("", "false", "0", "no", "off", "garbage"))
def test_intent_flag_falsy_values(monkeypatch, value):
    monkeypatch.setenv(BUGGY_AUTH_DEVIN_ENV, value)
    assert devin_intent_enabled() is False


def test_intent_flag_unset(monkeypatch):
    monkeypatch.delenv(BUGGY_AUTH_DEVIN_ENV, raising=False)
    assert devin_intent_enabled() is False


def test_resolve_bin_env_override_wins(monkeypatch):
    monkeypatch.setenv("DEVIN_BIN", "/opt/devin")
    assert resolve_devin_bin() == "/opt/devin"


def test_resolve_bin_falls_back_to_which(monkeypatch):
    monkeypatch.delenv("DEVIN_BIN", raising=False)
    monkeypatch.setattr(subs.shutil, "which", lambda name: f"/usr/local/bin/{name}")
    assert resolve_devin_bin() == "/usr/local/bin/devin"


def test_probe_binary_not_on_path(monkeypatch):
    monkeypatch.delenv("DEVIN_BIN", raising=False)
    monkeypatch.setattr(subs.shutil, "which", lambda name: None)
    status = probe_devin_cli()
    assert status.installed is False
    assert status.authenticated is False
    assert "not on PATH" in status.detail


def test_probe_authenticated(monkeypatch):
    monkeypatch.setenv("DEVIN_BIN", "/opt/devin")
    monkeypatch.setattr(
        subs.subprocess,
        "run",
        lambda *a, **kw: _completed(0, stdout="Logged in (via Devin).\n  extra lines"),
    )
    status = probe_devin_cli()
    assert status.installed is True
    assert status.authenticated is True
    assert status.detail == "Logged in (via Devin)."


def test_probe_nonzero_exit(monkeypatch):
    monkeypatch.setenv("DEVIN_BIN", "/opt/devin")
    monkeypatch.setattr(
        subs.subprocess,
        "run",
        lambda *a, **kw: _completed(1, stdout="", stderr="not logged in"),
    )
    status = probe_devin_cli()
    assert status.installed is True
    assert status.authenticated is False
    assert "exited 1" in status.detail
    assert "not logged in" in status.detail


def test_probe_missing_binary(monkeypatch):
    monkeypatch.setenv("DEVIN_BIN", "/opt/devin")

    def _raise(*args, **kwargs):
        raise FileNotFoundError("no such file")

    monkeypatch.setattr(subs.subprocess, "run", _raise)
    status = probe_devin_cli()
    assert status.installed is False
    assert status.authenticated is False
    assert "not found" in status.detail


def test_probe_timeout(monkeypatch):
    monkeypatch.setenv("DEVIN_BIN", "/opt/devin")

    def _raise(*args, **kwargs):
        raise subprocess.TimeoutExpired(cmd="devin auth status", timeout=15)

    monkeypatch.setattr(subs.subprocess, "run", _raise)
    status = probe_devin_cli()
    assert status.installed is True
    assert status.authenticated is False
    assert "timed out" in status.detail


def test_devin_available_requires_intent_fast_path(monkeypatch):
    # Flag unset → False without ever spawning the probe subprocess.
    monkeypatch.delenv(BUGGY_AUTH_DEVIN_ENV, raising=False)

    def _boom():
        raise AssertionError("probe must not run when the intent flag is unset")

    monkeypatch.setattr(subs, "probe_devin_cli", _boom)
    assert devin_available() is False


def test_devin_available_when_authenticated(monkeypatch):
    monkeypatch.setenv(BUGGY_AUTH_DEVIN_ENV, "true")
    monkeypatch.setattr(
        subs,
        "probe_devin_cli",
        lambda: DevinCLIStatus(
            bin_path="/opt/devin", installed=True, authenticated=True, detail="Logged in"
        ),
    )
    assert devin_available() is True


def test_devin_available_false_when_probe_unauthenticated(monkeypatch):
    monkeypatch.setenv(BUGGY_AUTH_DEVIN_ENV, "true")
    monkeypatch.setattr(
        subs,
        "probe_devin_cli",
        lambda: DevinCLIStatus(
            bin_path="/opt/devin", installed=True, authenticated=False, detail="exited 1"
        ),
    )
    assert devin_available() is False
