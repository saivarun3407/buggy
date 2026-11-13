"""Plugin-author Protocols for the Buggy contract layer.

Each Protocol declares the duck-type interface plugin authors must
implement to contribute a tool, middleware, callback, etc. Decorated
with ``@runtime_checkable`` so ``isinstance(obj, MiddlewareProtocol)``
works at runtime; static type checkers verify shape at plugin compile
time.

Submodules:

  * ``backend``    — deepagents-style filesystem backend
  * ``middleware`` — langchain agent middleware
  * ``tool``       — langchain ``@tool``-style callable
  * ``callback``   — langchain ``BaseCallbackHandler``
  * ``llm``        — bound language model
  * ``sandbox``    — sandbox transport (HTTPSandbox or equivalent)
  * ``agent``      — compiled agent / sub-agent

All Protocols ship in this contract layer so plugin authors can
declare conformance without depending on the framework runtime.
"""

from __future__ import annotations

from buggy_core.protocols.agent import AgentProtocol
from buggy_core.protocols.backend import BackendProtocol
from buggy_core.protocols.callback import CallbackProtocol
from buggy_core.protocols.llm import LLMProtocol
from buggy_core.protocols.middleware import MiddlewareProtocol
from buggy_core.protocols.sandbox import SandboxProtocol
from buggy_core.protocols.tool import ToolProtocol

__all__ = [
    "AgentProtocol",
    "BackendProtocol",
    "CallbackProtocol",
    "LLMProtocol",
    "MiddlewareProtocol",
    "SandboxProtocol",
    "ToolProtocol",
]
