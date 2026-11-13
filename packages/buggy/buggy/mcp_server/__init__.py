"""Buggy engagement MCP server.

Exposes Buggy engagement control — list graphs, start/monitor/cancel an
engagement, and pull findings — over the Model Context Protocol so external
agent runtimes such as OpenClaw and Hermes can drive Buggy as a tool.

The server SDK (``mcp``) is an optional dependency: install with
``pip install 'buggy[mcp]'``. Importing this package is safe without it;
only :func:`main` and :func:`buggy.mcp_server.server.build_server`
require the SDK.
"""

from __future__ import annotations

from buggy.mcp_server.__main__ import main
from buggy.mcp_server.config import ServerConfig, load_config

__all__ = ["ServerConfig", "load_config", "main"]
