"""Devin CLI client — subprocess wrapper for delegated agent sessions.

Devin is an *agent-level* subscription: every call spawns a full Devin
agent session (its own tools, planning, and permission modes) under the
operator's Devin subscription, executing a self-contained subtask and
printing the final response. There is deliberately no completion-shaped
API here — the integration point is the agent, not the model.

Invocation shape (verified against devin 3000.12.43):

    devin -p --respect-workspace-trust false [--model M] -- <task>

``-p`` is the documented non-interactive print-and-exit mode; the
workspace-trust opt-out is documented "for scripts and CI" so headless
delegation never blocks on an interactive trust prompt.
"""

from __future__ import annotations

import os
import subprocess
import time
from typing import Any

from buggy_core.subscriptions import (
    DEFAULT_DEVIN_TIMEOUT_SECONDS,
    DEVIN_MODEL_ENV,
    DEVIN_TIMEOUT_ENV,
    probe_devin_cli,
    resolve_devin_bin,
)

# Permission mode for delegated sessions. ``-p`` mode has no interactive
# approval prompt, so the CLI default (``auto`` — read-only tools only)
# would stall any delegation that needs to write a deliverable.
# ``accept-edits`` auto-approves workspace edits; raise to ``smart`` /
# ``dangerous`` only with eyes open (the session runs inside this
# container with its own exec tools). Distinct name from the CLI's own
# DEVIN_PERMISSION_MODE env so the delegation contract stays explicit.
DEVIN_DELEGATE_PERMISSION_MODE_ENV = "DEVIN_DELEGATE_PERMISSION_MODE"
_DEFAULT_DELEGATE_PERMISSION_MODE = "accept-edits"

# Cap on the stdout/stderr we hand back to the calling agent. A delegated
# session can produce a lot of output; past this the model's context is
# better spent on a summary than a firehose.
_MAX_CAPTURED_OUTPUT_CHARS = 100_000


def resolve_devin_timeout() -> float:
    """Per-delegation timeout: ``DEVIN_TIMEOUT_SECONDS`` env > default."""
    raw = os.getenv(DEVIN_TIMEOUT_ENV, "").strip()
    if raw:
        try:
            value = float(raw)
        except ValueError:
            value = 0.0
        if value > 0:
            return value
    return DEFAULT_DEVIN_TIMEOUT_SECONDS


def resolve_devin_model() -> str | None:
    """Optional model pin for delegated sessions (``DEVIN_MODEL``)."""
    model = os.getenv(DEVIN_MODEL_ENV, "").strip()
    return model or None


def resolve_devin_permission_mode() -> str:
    """Permission mode for delegated sessions (``DEVIN_DELEGATE_PERMISSION_MODE``)."""
    mode = os.getenv(DEVIN_DELEGATE_PERMISSION_MODE_ENV, "").strip().lower()
    return mode or _DEFAULT_DELEGATE_PERMISSION_MODE


def _truncate(text: str) -> str:
    if len(text) <= _MAX_CAPTURED_OUTPUT_CHARS:
        return text
    return text[:_MAX_CAPTURED_OUTPUT_CHARS] + "\n…[truncated]"


def run_devin_print(
    task: str,
    *,
    model: str | None = None,
    timeout: float | None = None,
    cwd: str | None = None,
) -> dict[str, Any]:
    """Run one delegated subtask via ``devin -p`` and return a JSON-able envelope.

    The envelope always carries ``ok`` plus either the session output
    (``stdout``, ``stderr``, ``exit_code``, ``duration_seconds``) or an
    ``error`` code with an actionable ``hint``. Never raises — LangChain
    tool callers get the failure rendered as data.
    """
    bin_path = resolve_devin_bin()
    if bin_path is None:
        return {
            "ok": False,
            "error": "devin_not_installed",
            "hint": "devin binary not on PATH — install the Devin CLI or set DEVIN_BIN",
        }
    argv = [
        bin_path,
        "-p",
        "--respect-workspace-trust",
        "false",
        "--permission-mode",
        resolve_devin_permission_mode(),
    ]
    effective_model = model or resolve_devin_model()
    if effective_model:
        argv += ["--model", effective_model]
    argv += ["--", task]
    effective_timeout = timeout if timeout is not None else resolve_devin_timeout()

    started = time.monotonic()
    try:
        completed = subprocess.run(  # noqa: S603 — fixed argv, operator-configured binary
            argv,
            capture_output=True,
            text=True,
            timeout=effective_timeout,
            cwd=cwd,
            check=False,
        )
    except FileNotFoundError:
        return {
            "ok": False,
            "error": "devin_not_installed",
            "hint": f"devin binary not found at {bin_path} — fix DEVIN_BIN or install the CLI",
        }
    except subprocess.TimeoutExpired:
        return {
            "ok": False,
            "error": "devin_timeout",
            "timeout_seconds": effective_timeout,
            "hint": "delegated session exceeded DEVIN_TIMEOUT_SECONDS — delegate a smaller subtask",
        }
    except OSError as exc:
        return {"ok": False, "error": "devin_launch_failed", "hint": str(exc)}
    duration = time.monotonic() - started
    stdout = (completed.stdout or "").strip()
    stderr = (completed.stderr or "").strip()
    if completed.returncode != 0:
        return {
            "ok": False,
            "error": "devin_nonzero_exit",
            "exit_code": completed.returncode,
            "stdout": _truncate(stdout),
            "stderr": _truncate(stderr),
            "duration_seconds": round(duration, 1),
            "hint": (
                "devin exited non-zero — if this is an auth failure run `devin auth status` "
                f"(probe says: {probe_devin_cli().detail})"
            ),
        }
    return {
        "ok": True,
        "exit_code": 0,
        "stdout": _truncate(stdout),
        "stderr": _truncate(stderr),
        "duration_seconds": round(duration, 1),
        "model": effective_model,
    }
