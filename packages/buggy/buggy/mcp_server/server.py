"""FastMCP server exposing Buggy engagement control to external agents.

This is the seam that makes external agent runtimes (OpenClaw, Hermes, or any
MCP client) able to *drive* Buggy like its CLI — from a phone, via those
agents' chat channels. The full surface:

- ``buggy_list_graphs`` / ``buggy_list_engagements`` — discover & resume
- ``buggy_start_engagement`` — launch an authorized engagement
- ``buggy_send_message`` — steer / answer / ``/model`` switch mid-run
- ``buggy_transcript`` — watch the orchestrator narrative incrementally
- ``buggy_watch`` — tail the live sub-agent stream for a few seconds
- ``buggy_engagement_state`` — inspect OPPLAN / scope / phase
- ``buggy_engagement_status`` / ``buggy_engagement_findings`` — status & SARIF
- ``buggy_cancel_engagement`` — stop a run

The server is a thin control plane. The red-team work runs inside the
Buggy LangGraph server (RoE enforcement, sandbox, knowledge-graph
persistence); this module only translates MCP tool calls into LangGraph runs
and reads persisted state/findings back.
"""

from __future__ import annotations

from typing import Any

from mcp.server.fastmcp import FastMCP

from buggy.mcp_server.auth import build_auth
from buggy.mcp_server.config import ServerConfig, load_config
from buggy.mcp_server.engagements import EngagementClient
from buggy.mcp_server.tools_interactive import register_interactive_tools
from buggy.mcp_server.tools_lifecycle import register_lifecycle_tools


def build_server(
    config: ServerConfig | None = None,
    *,
    client: Any | None = None,
    host: str = "127.0.0.1",
    port: int = 8765,
) -> FastMCP:
    """Construct the Buggy engagement MCP server with all tools registered.

    ``client`` injects a pre-built LangGraph SDK client (tests/embedding);
    production callers leave it ``None`` so it is created from ``config``.
    """
    cfg = config or load_config()
    engagements = EngagementClient(cfg, client=client)
    verifier, auth = build_auth(cfg, host=host, port=port)
    mcp = FastMCP("buggy", host=host, port=port, token_verifier=verifier, auth=auth)
    register_lifecycle_tools(mcp, engagements, cfg)
    register_interactive_tools(mcp, engagements)
    return mcp
