"""Agent-level subscription probes (Devin CLI and friends).

``AuthMethod`` covers *model* backends — credentials that yield raw
completions through the LiteLLM proxy and therefore join the model
fallback chain. An agent-level subscription is a different animal: it
provides **agent labor** (a full agent session with its own tools and
planning) rather than completions, so it can never join the chain. The
Devin CLI is the canonical example — a logged-in ``devin`` binary can
execute delegated subtasks under the operator's Devin subscription, but
there is no completion endpoint behind it.

These probes let ``auth_inventory`` answer "what subscriptions do I
actually have" in one place: model methods AND agent-level methods. The
delegation tools (``buggy.tools.devin``) gate themselves on the
same probe so an unauthenticated CLI never offers a tool that would
only fail.

Detection contract (mirrors the OAuth model methods):

  - intent flag ``BUGGY_AUTH_DEVIN=true`` — the user opted in
  - credential check — ``devin auth status`` exits 0

Both must hold for ``devin_available()``. When the flag is unset the
probe never spawns a subprocess, so CI and default installs pay zero
cost.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass

from buggy_core.utils.env import env_flag
from buggy_core.utils.logging import get_logger

log = get_logger("core.subscriptions")

# Intent flag, same convention as BUGGY_AUTH_CLAUDE_CODE and friends:
# a boolean the onboard wizard / .env sets after the operator opts in.
BUGGY_AUTH_DEVIN_ENV = "BUGGY_AUTH_DEVIN"

# Binary locator. Default: whatever ``devin`` resolves to on PATH. Set
# this when the CLI is installed at a non-PATH location (e.g. an editor's
# bundled copy) — the probe and the delegation tool both use it.
DEVIN_BIN_ENV = "DEVIN_BIN"

# Model the delegation tool pins for each session (optional). Accepts the
# same fuzzy names as ``devin --model`` (e.g. ``glm-5-3-max``, ``swe-2``).
# Unset → the account-configured default model.
DEVIN_MODEL_ENV = "DEVIN_MODEL"

# Per-delegation wall-clock budget. A full agent session routinely takes
# tens of seconds to minutes, so this is deliberately far above a normal
# LLM request timeout.
DEVIN_TIMEOUT_ENV = "DEVIN_TIMEOUT_SECONDS"
DEFAULT_DEVIN_TIMEOUT_SECONDS = 900.0

# Budget for the ``devin auth status`` probe itself. It is a local
# credential check (reads the credentials file, optionally refreshes team
# settings), so seconds — but never let a hung CLI block agent startup.
_DEVIN_AUTH_STATUS_TIMEOUT_SECONDS = 15.0


@dataclass(frozen=True, slots=True)
class DevinCLIStatus:
    """Result of probing the local Devin CLI install."""

    bin_path: str | None
    installed: bool
    authenticated: bool
    detail: str


def devin_intent_enabled() -> bool:
    """Return True when ``BUGGY_AUTH_DEVIN`` is set truthy."""
    return env_flag(BUGGY_AUTH_DEVIN_ENV)


def _first_nonempty_line(text: str | None) -> str:
    """First stripped non-empty line of ``text``, or "".

    ``splitlines()[0]`` on whitespace-only output raises IndexError —
    the probe contract is never-raise, so this guards it.
    """
    for line in (text or "").splitlines():
        stripped = line.strip()
        if stripped:
            return stripped
    return ""


def resolve_devin_bin() -> str | None:
    """Locate the ``devin`` binary.

    ``DEVIN_BIN`` wins verbatim when set (operator explicitly points at
    an install; a wrong path surfaces as ``devin_not_installed`` at call
    time rather than a silent PATH miss). Otherwise ``shutil.which``.
    """
    override = os.getenv(DEVIN_BIN_ENV, "").strip()
    if override:
        return override
    return shutil.which("devin")


def probe_devin_cli() -> DevinCLIStatus:
    """Probe install + auth state of the Devin CLI.

    ``devin auth status`` exits 0 and prints ``Logged in ...`` when the
    stored credential is valid; any non-zero exit (including the CLI's
    own "not logged in" path) means unauthenticated. Never raises — a
    missing binary, a timeout, or a broken install all fold into the
    returned status so callers (auth inventory, tool gating) can render
    an actionable hint instead of crashing.
    """
    bin_path = resolve_devin_bin()
    if bin_path is None:
        return DevinCLIStatus(
            bin_path=None,
            installed=False,
            authenticated=False,
            detail="devin binary not on PATH — install the Devin CLI or set DEVIN_BIN",
        )
    try:
        completed = subprocess.run(  # noqa: S603 — fixed argv, operator-configured binary
            [bin_path, "auth", "status"],
            capture_output=True,
            text=True,
            timeout=_DEVIN_AUTH_STATUS_TIMEOUT_SECONDS,
            check=False,
        )
    except FileNotFoundError:
        return DevinCLIStatus(
            bin_path=bin_path,
            installed=False,
            authenticated=False,
            detail=f"devin binary not found at {bin_path} — fix DEVIN_BIN or install the CLI",
        )
    except subprocess.TimeoutExpired:
        return DevinCLIStatus(
            bin_path=bin_path,
            installed=True,
            authenticated=False,
            detail=f"devin auth status timed out after {_DEVIN_AUTH_STATUS_TIMEOUT_SECONDS:g}s",
        )
    except OSError as exc:
        return DevinCLIStatus(
            bin_path=bin_path,
            installed=True,
            authenticated=False,
            detail=f"devin auth status failed to run: {exc}",
        )
    authenticated = completed.returncode == 0
    first_line = _first_nonempty_line(completed.stdout)
    if authenticated:
        detail = first_line or "devin auth status exited 0"
    else:
        hint = first_line or _first_nonempty_line(completed.stderr)
        detail = f"devin auth status exited {completed.returncode}" + (f": {hint}" if hint else "")
    return DevinCLIStatus(
        bin_path=bin_path,
        installed=True,
        authenticated=authenticated,
        detail=detail,
    )


def devin_available() -> bool:
    """Return True when Devin delegation is usable right now.

    Intent flag AND authenticated CLI — the same two-gate contract the
    OAuth model methods use (boolean + credential present). Fast path:
    an unset flag returns False without spawning any subprocess.
    """
    if not devin_intent_enabled():
        return False
    return probe_devin_cli().authenticated
