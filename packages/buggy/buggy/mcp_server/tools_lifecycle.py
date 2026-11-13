"""MCP tool registration — engagement lifecycle (start / status / findings / cancel)."""

from __future__ import annotations

import os
from datetime import UTC, datetime
from typing import Any

from mcp.server.fastmcp import FastMCP

from buggy.mcp_server.config import ServerConfig
from buggy.mcp_server.engagements import EngagementClient
from buggy.mcp_server.findings import (
    engagement_workspace,
    load_findings_graph,
    summarize_findings,
)
from buggy.mcp_server.models import (
    FindingsResult,
    GraphInfo,
    ScanMode,
    StartResult,
    StatusResult,
)
from buggy_core.utils.engagement_scope import is_valid_engagement_label


def default_engagement_name() -> str:
    return "mcp-" + datetime.now(UTC).strftime("%Y%m%d-%H%M%S")


class _ThreadAccessError(ValueError):
    """A thread is not bound to the selected engagement workspace."""


async def _selected_thread_state(engagements: EngagementClient, thread_id: str) -> dict[str, Any]:
    selected = os.environ.get("BUGGY_ENGAGEMENT", "")
    workspace = os.environ.get("BUGGY_WORKSPACE_PATH", "/workspace")
    if selected:
        thread = await engagements._ensure_client().threads.get(thread_id)
        metadata = thread.get("metadata") if isinstance(thread, dict) else None
        if not isinstance(metadata, dict) or (
            metadata.get("engagement_name") != selected
            or metadata.get("workspace_identity") != str(engagement_workspace(selected))
            or metadata.get("workspace_path") != workspace
        ):
            raise _ThreadAccessError("thread does not belong to the selected engagement workspace")
    state = await engagements.get_state(thread_id)
    if not isinstance(state, dict):
        raise _ThreadAccessError("invalid engagement thread state")
    if selected:
        values = state.get("values")
        if not isinstance(values, dict) or (
            values.get("engagement_name") not in (None, selected)
            or values.get("workspace_path") not in (None, workspace)
        ):
            raise _ThreadAccessError("thread does not belong to the selected engagement workspace")
    return state


def register_lifecycle_tools(
    mcp: FastMCP, engagements: EngagementClient, config: ServerConfig
) -> None:
    """Register start / status / findings / cancel tools on the server."""

    @mcp.tool()
    async def buggy_list_graphs() -> list[GraphInfo]:
        """List the engagement graphs the connected Buggy server exposes.

        Pick a graph: ``buggy`` (full kill-chain engagement), ``recon``
        (reconnaissance only), ``soundwave`` (planning), etc. Requires a running
        Buggy LangGraph server.
        """
        return await engagements.list_graphs()

    @mcp.tool()
    async def buggy_start_engagement(
        targets: list[str],
        instruction: str = "",
        scan_mode: ScanMode = "standard",
        engagement_name: str | None = None,
        assistant: str | None = None,
    ) -> StartResult:
        """Start an AUTHORIZED Buggy engagement against one or more targets.

        ``targets`` are URLs, hostnames/CIDRs, repo URLs, or filesystem paths.
        Put scope and rules of engagement in ``instruction`` (what is in and out
        of scope) — the orchestrator gates every tool call against it. Only test
        assets you are authorized to test.

        Returns immediately with a ``thread_id`` (the engagement handle). Drive
        everything else with that handle: ``buggy_transcript`` to watch,
        ``buggy_send_message`` to steer, ``buggy_engagement_findings``
        to pull results.
        """
        selected = os.environ.get("BUGGY_ENGAGEMENT", "")
        name = engagement_name or selected or default_engagement_name()
        if selected and name != selected:
            raise _ThreadAccessError("cannot start outside the selected engagement workspace")
        if not is_valid_engagement_label(name):
            raise ValueError(
                f"invalid engagement_name {name!r}; must match "
                "[A-Za-z0-9][A-Za-z0-9._-]{0,127} (no path separators or '..')"
            )
        return await engagements.start(
            targets=targets,
            instruction=instruction,
            scan_mode=scan_mode,
            engagement_name=name,
            assistant=assistant or config.default_assistant,
        )

    @mcp.tool()
    async def buggy_engagement_status(thread_id: str, engagement_name: str = "") -> StatusResult:
        """Report an engagement's latest run status + whether findings exist yet.

        ``status`` is the LangGraph run status (``pending``/``running``/
        ``success``/``error``/``timeout``/``interrupted``/``none``). Pass
        ``engagement_name`` to also learn whether findings have been persisted.
        """
        if os.environ.get("BUGGY_ENGAGEMENT"):
            await _selected_thread_state(engagements, thread_id)
        latest = await engagements.latest_run(thread_id)
        run_id = str(latest["run_id"]) if latest else None
        status = str(latest.get("status", "unknown")) if latest else "none"
        findings_available = (
            bool(engagement_name)
            and is_valid_engagement_label(engagement_name)
            and (engagement_workspace(engagement_name) / "graph.json").exists()
        )
        return StatusResult(
            thread_id=thread_id,
            run_id=run_id,
            status=status,
            findings_available=findings_available,
        )

    @mcp.tool()
    async def buggy_engagement_findings(
        engagement_name: str, include_sarif: bool = False
    ) -> FindingsResult:
        """Fetch the findings summary for an engagement (optionally full SARIF).

        Returns counts by SARIF level plus, when ``include_sarif`` is true, the
        complete SARIF v2.1.0 document. ``available`` is false until the
        orchestrator persists findings.
        """
        graph = load_findings_graph(engagement_name)
        return summarize_findings(
            graph, engagement_name=engagement_name, include_sarif=include_sarif
        )

    @mcp.tool()
    async def buggy_cancel_engagement(thread_id: str) -> str:
        """Cancel the active run on an engagement thread."""
        if os.environ.get("BUGGY_ENGAGEMENT"):
            await _selected_thread_state(engagements, thread_id)
        run_id = await engagements.cancel(thread_id)
        return f"cancelled {run_id}" if run_id else "no active run to cancel"
