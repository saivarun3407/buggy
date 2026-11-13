"""Tests for the devin_delegate tool and its client envelope contract.

The client never raises — every failure mode folds into a JSON-able
envelope so the LangChain tool caller renders failure as data. These
tests pin the envelope contract and the exact ``devin -p`` argv shape.
"""

from __future__ import annotations

import json
import subprocess

import pytest

import buggy.tools.devin.client as devin_client
from buggy.tools.devin import DEVIN_TOOLS, devin_delegate
from buggy.tools.devin.client import _MAX_CAPTURED_OUTPUT_CHARS, run_devin_print
from buggy_core.subscriptions import DevinCLIStatus


def _completed(
    returncode: int = 0, stdout: str = "", stderr: str = ""
) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(args=[], returncode=returncode, stdout=stdout, stderr=stderr)


def test_not_installed_envelope(monkeypatch):
    monkeypatch.delenv("DEVIN_BIN", raising=False)
    monkeypatch.setattr(devin_client, "resolve_devin_bin", lambda: None)
    envelope = run_devin_print("do a thing")
    assert envelope["ok"] is False
    assert envelope["error"] == "devin_not_installed"
    assert "DEVIN_BIN" in envelope["hint"]


def test_success_envelope_and_argv(monkeypatch):
    captured_argv: list[str] = []

    def _fake_run(argv, **kwargs):
        captured_argv.extend(argv)
        return _completed(0, stdout="PONG\n")

    monkeypatch.setattr(devin_client, "resolve_devin_bin", lambda: "/opt/devin")
    monkeypatch.setattr(devin_client.subprocess, "run", _fake_run)
    envelope = run_devin_print("analyze the artifacts dir")
    assert captured_argv[0] == "/opt/devin"
    assert captured_argv[1:6] == [
        "-p",
        "--respect-workspace-trust",
        "false",
        "--permission-mode",
        "accept-edits",
    ]
    assert captured_argv[-2:] == ["--", "analyze the artifacts dir"]
    assert envelope["ok"] is True
    assert envelope["exit_code"] == 0
    assert envelope["stdout"] == "PONG"
    assert envelope["model"] is None


def test_permission_mode_env_override(monkeypatch):
    captured_argv: list[str] = []

    def _fake_run(argv, **kwargs):
        captured_argv.extend(argv)
        return _completed(0, stdout="ok")

    monkeypatch.setattr(devin_client, "resolve_devin_bin", lambda: "/opt/devin")
    monkeypatch.setattr(devin_client.subprocess, "run", _fake_run)
    monkeypatch.setenv("DEVIN_DELEGATE_PERMISSION_MODE", "smart")
    run_devin_print("task")
    assert captured_argv[4:6] == ["--permission-mode", "smart"]


def test_model_pin_from_env(monkeypatch):
    captured_argv: list[str] = []

    def _fake_run(argv, **kwargs):
        captured_argv.extend(argv)
        return _completed(0, stdout="ok")

    monkeypatch.setattr(devin_client, "resolve_devin_bin", lambda: "/opt/devin")
    monkeypatch.setattr(devin_client.subprocess, "run", _fake_run)
    monkeypatch.setenv("DEVIN_MODEL", "glm-5-3-max")
    envelope = run_devin_print("task")
    assert captured_argv[-4:-2] == ["--model", "glm-5-3-max"]
    assert envelope["model"] == "glm-5-3-max"


def test_nonzero_exit_envelope(monkeypatch):
    monkeypatch.setattr(devin_client, "resolve_devin_bin", lambda: "/opt/devin")
    monkeypatch.setattr(
        devin_client.subprocess,
        "run",
        lambda argv, **kwargs: _completed(2, stdout="", stderr="boom"),
    )
    # The hint consults the probe — stub it so no real subprocess runs.
    monkeypatch.setattr(
        devin_client,
        "probe_devin_cli",
        lambda: DevinCLIStatus(
            bin_path="/opt/devin", installed=True, authenticated=True, detail="Logged in"
        ),
    )
    envelope = run_devin_print("task")
    assert envelope["ok"] is False
    assert envelope["error"] == "devin_nonzero_exit"
    assert envelope["exit_code"] == 2
    assert "devin auth status" in envelope["hint"]


def test_timeout_envelope(monkeypatch):
    monkeypatch.setattr(devin_client, "resolve_devin_bin", lambda: "/opt/devin")

    def _raise(argv, **kwargs):
        raise subprocess.TimeoutExpired(cmd=argv, timeout=900)

    monkeypatch.setattr(devin_client.subprocess, "run", _raise)
    envelope = run_devin_print("task")
    assert envelope["ok"] is False
    assert envelope["error"] == "devin_timeout"
    assert envelope["timeout_seconds"] == pytest.approx(900.0)
    assert "smaller subtask" in envelope["hint"]


def test_stdout_truncated(monkeypatch):
    monkeypatch.setattr(devin_client, "resolve_devin_bin", lambda: "/opt/devin")
    monkeypatch.setattr(
        devin_client.subprocess,
        "run",
        lambda argv, **kwargs: _completed(0, stdout="x" * (_MAX_CAPTURED_OUTPUT_CHARS + 50)),
    )
    envelope = run_devin_print("task")
    assert envelope["ok"] is True
    assert len(envelope["stdout"]) <= _MAX_CAPTURED_OUTPUT_CHARS + 20
    assert envelope["stdout"].endswith("…[truncated]")


def test_tool_returns_json_envelope(monkeypatch):
    monkeypatch.setattr(
        "buggy.tools.devin.tools.run_devin_print",
        lambda task, model=None: {"ok": True, "stdout": "did it", "exit_code": 0},
    )
    result = devin_delegate.invoke({"task": "summarize findings/"})
    payload = json.loads(result)
    assert payload == {"ok": True, "stdout": "did it", "exit_code": 0}


def test_tool_passes_model_param(monkeypatch):
    seen: dict[str, object] = {}

    def _fake_run(task, model=None):
        seen["task"] = task
        seen["model"] = model
        return {"ok": True, "stdout": "planned", "exit_code": 0}

    monkeypatch.setattr("buggy.tools.devin.tools.run_devin_print", _fake_run)
    devin_delegate.invoke({"task": "plan the attack chain", "model": "claude-opus-5-5-high"})
    assert seen["task"] == "plan the attack chain"
    assert seen["model"] == "claude-opus-5-5-high"


def test_tools_list_contains_only_delegate():
    assert [t.name for t in DEVIN_TOOLS] == ["devin_delegate"]
