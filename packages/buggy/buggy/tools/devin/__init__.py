"""Agent-facing delegation tools for the Devin CLI subscription.

The orchestrator calls :func:`devin_delegate` to hand a self-contained
subtask to a full Devin agent session running under the operator's
Devin subscription. Specialist sub-agents intentionally do not carry
these tools (least privilege — a compromised sub-agent must not be able
to fan out agent sessions on the operator's dime).

Registered only when the CLI is actually usable:
``BUGGY_AUTH_DEVIN=true`` plus a logged-in ``devin`` binary
(see :func:`buggy_core.subscriptions.devin_available`).
"""

from __future__ import annotations

from buggy.tools.devin.client import (
    resolve_devin_model,
    resolve_devin_timeout,
    run_devin_print,
)
from buggy.tools.devin.tools import DEVIN_TOOLS, devin_delegate
from buggy_core.subscriptions import devin_available

__all__ = [
    "DEVIN_TOOLS",
    "devin_available",
    "devin_delegate",
    "resolve_devin_model",
    "resolve_devin_timeout",
    "run_devin_print",
]
