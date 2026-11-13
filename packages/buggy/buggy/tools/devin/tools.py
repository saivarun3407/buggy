"""LangChain ``@tool`` wrappers for Devin CLI delegation.

Scoped to the orchestrator (``buggy`` agent) — same least-privilege
rationale as the ADR-0006 ``ops_*`` tools: a delegated session is an
agent with its own tools, so only the coordinator that already owns
cross-agent work may spawn one. A prompt-injected sub-agent must not be
able to fan out agent sessions on the operator's subscription.

Delegation contract (stated in the tool docstring so the model sees it):

  - each call is a FULL Devin agent session — tens of seconds to minutes,
    billed to the operator's Devin subscription
  - delegate coarse, self-contained subtasks; never use it as a
    per-step completion endpoint
"""

from __future__ import annotations

import json
from typing import Any

from langchain_core.tools import tool

from buggy.tools.devin.client import run_devin_print


def _envelope(payload: dict[str, Any]) -> str:
    """Stable JSON envelope so the agent can parse without surprises."""
    return json.dumps(payload, sort_keys=True, default=str)


@tool
def devin_delegate(task: str, model: str | None = None) -> str:
    """Delegate a coarse, self-contained subtask to a Devin agent session.

    Use for well-scoped chunks of work that benefit from a full agent —
    analyzing a directory of artifacts, drafting a report section,
    triaging findings, reviewing a patch, or planning an attack chain.
    Each call spawns a complete Devin CLI session under the operator's
    Devin subscription: expect tens of seconds to minutes per call, so
    batch related work into one task string instead of calling per-file
    or per-step.

    ``model`` (optional) picks the session's model + thinking level.
    Model ids embed the effort level. Selection guide:
      - ``glm-5-3-high`` — complex analysis / exploitation work (default)
      - ``claude-opus-5-5-high`` / ``claude-fable-5-2-high`` — planning,
        attack-chain design, structured synthesis
      - ``gpt-6-sol-high`` / ``gpt-6-astra-high`` — fallback when another
        model declines the task
    Omit to use DEVIN_MODEL from the environment.

    The session runs `devin -p` in this process's working directory, so
    reference files by path relative to it. Timeout comes from
    DEVIN_TIMEOUT_SECONDS (default 900s).

    TRUST BOUNDARY: a delegated Devin session is a peer agent — it runs
    OUTSIDE this harness's RoE guardrail, egress allowlist, proof gate,
    and audit ledger. Only delegate tasks whose targets and actions are
    already inside the engagement scope; the delegate does not re-check
    them.

    Returns a JSON envelope:
        ``{"ok": true, "stdout": "...", "exit_code": 0, ...}``
    or an error envelope (``devin_not_installed`` / ``devin_timeout`` /
    ``devin_nonzero_exit``) with an actionable hint.
    """
    return _envelope(run_devin_print(task, model=model))


DEVIN_TOOLS = [devin_delegate]
