"""Selected-workspace isolation through the actual MCP protocol."""

from __future__ import annotations

from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import pytest
from langgraph_sdk.schema import StreamPart

mcp_fastmcp = pytest.importorskip("mcp.server.fastmcp", reason="mcp not installed")
mcp_memory = pytest.importorskip("mcp.shared.memory", reason="mcp not installed")
FastMCP = mcp_fastmcp.FastMCP
create_connected_server_and_client_session = mcp_memory.create_connected_server_and_client_session

from buggy.mcp_server.config import ServerConfig  # noqa: E402
from buggy.mcp_server.engagements import EngagementClient  # noqa: E402
from buggy.mcp_server.server import build_server  # noqa: E402
from buggy.mcp_server.tools_lifecycle import _selected_thread_state  # noqa: E402


class _Threads:
    def __init__(self, workspace: Path) -> None:
        self.workspace = workspace
        self.created: list[str] = []
        self.failure: ValueError | None = None
        self.states: dict[str, Any] = {}
        self.metadata: dict[str, Any] = {}
        for thread_id in ("foreign-thread", "misplaced-thread", "selected-thread"):
            name = "foreign" if thread_id == "foreign-thread" else "selected"
            self.states[thread_id] = {
                "values": {
                    "engagement_name": name,
                    "workspace_path": "/workspace"
                    if thread_id == "selected-thread"
                    else "/foreign",
                    "messages": [],
                }
            }
            self.metadata[thread_id] = {
                "engagement_name": name,
                "workspace_identity": str(workspace) if name == "selected" else "/foreign",
                "workspace_path": "/workspace",
            }

    async def create(self, *, metadata: dict[str, Any] | None = None) -> dict[str, Any]:
        thread_id = f"created-{len(self.created)}"
        self.created.insert(0, thread_id)
        self.states[thread_id] = {"values": {}}
        self.metadata[thread_id] = metadata or {}
        return {"thread_id": thread_id}

    async def get(self, thread_id: str) -> dict[str, Any]:
        return {"thread_id": thread_id, "metadata": self.metadata[thread_id]}

    async def get_state(self, thread_id: str) -> Any:
        if self.failure:
            raise self.failure
        return self.states[thread_id]

    async def search(self, *, limit: int, sort_by: str, sort_order: str) -> list[dict[str, Any]]:
        order = self.created + ["foreign-thread", "misplaced-thread", "selected-thread"]
        return [{"thread_id": tid, **self.states[tid]} for tid in order[:limit]]


class _Runs:
    def __init__(self, threads: _Threads) -> None:
        self.threads = threads
        self.cancelled: list[str] = []
        self.started: list[str] = []
        self.hydrate = True
        self.config: dict[str, Any] = {}

    async def list(self, thread_id: str, *, limit: int) -> list[dict[str, Any]]:
        return [{"run_id": "run", "status": "running", "assistant_id": "soundwave"}]

    async def cancel(self, thread_id: str, run_id: str) -> None:
        self.cancelled.append(thread_id)

    async def create(
        self,
        thread_id: str,
        *,
        assistant_id: str,
        input: dict[str, Any],
        multitask_strategy: str = "enqueue",
        config: dict[str, Any] | None = None,
    ) -> dict[str, str]:
        self.started.append(thread_id)
        self.config = config or {}
        if self.hydrate:
            self.threads.states[thread_id]["values"].update(input)
            self.threads.states[thread_id]["values"].update(self.config.get("configurable", {}))
        return {"run_id": "run", "status": "pending"}

    async def join_stream(
        self, thread_id: str, run_id: str, *, stream_mode: list[str]
    ) -> AsyncIterator[StreamPart]:
        yield StreamPart("updates", {})


class _Client:
    def __init__(self, workspace: Path) -> None:
        self.threads = _Threads(workspace)
        self.runs = _Runs(self.threads)


@pytest.fixture
def selected_client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> _Client:
    monkeypatch.delenv("BUGGY_WORKSPACE_PATH", raising=False)
    monkeypatch.setenv("BUGGY_ENGAGEMENT", "selected")
    monkeypatch.setenv("BUGGY_ENGAGEMENT_WORKSPACE", str(tmp_path))
    return _Client(tmp_path)


def _server(client: _Client) -> FastMCP:
    return build_server(ServerConfig("http://test:2024", "soundwave", 10), client=client)


@pytest.mark.parametrize(
    ("tool", "arguments"),
    [
        ("buggy_transcript", {}),
        ("buggy_engagement_state", {}),
        ("buggy_engagement_status", {}),
        ("buggy_cancel_engagement", {}),
        ("buggy_watch", {}),
        ("buggy_send_message", {"message": "scope fixture"}),
    ],
)
@pytest.mark.parametrize("thread_id", ["foreign-thread", "misplaced-thread"])
async def test_selected_workspace_rejects_foreign_thread(
    tool: str, arguments: dict[str, str], thread_id: str, selected_client: _Client
) -> None:
    async with create_connected_server_and_client_session(_server(selected_client)) as session:
        response = await session.call_tool(tool, {"thread_id": thread_id, **arguments})
        assert response.isError and "does not belong" in str(response.content)


@pytest.mark.parametrize("thread_id", ["foreign-thread", "misplaced-thread"])
async def test_foreign_thread_is_not_cancelled(thread_id: str, selected_client: _Client) -> None:
    async with create_connected_server_and_client_session(_server(selected_client)) as session:
        await session.call_tool("buggy_cancel_engagement", {"thread_id": thread_id})
        assert selected_client.runs.cancelled == []


@pytest.mark.parametrize("thread_id", ["foreign-thread", "misplaced-thread"])
async def test_foreign_thread_does_not_start_a_run(
    thread_id: str, selected_client: _Client
) -> None:
    async with create_connected_server_and_client_session(_server(selected_client)) as session:
        await session.call_tool(
            "buggy_send_message", {"thread_id": thread_id, "message": "scope fixture"}
        )
        assert selected_client.runs.started == []


async def test_selected_workspace_list_excludes_foreign_threads(selected_client: _Client) -> None:
    async with create_connected_server_and_client_session(_server(selected_client)) as session:
        response = await session.call_tool("buggy_list_engagements", {"limit": 1})
        rows = (response.structuredContent or {}).get("result", [])
        assert [row["thread_id"] for row in rows] == ["selected-thread"]


@pytest.mark.parametrize("engagement_name", [None, "selected"])
@pytest.mark.parametrize("hydrate", [False, True])
@pytest.mark.parametrize(
    ("tool", "arguments"),
    [
        ("buggy_transcript", {}),
        ("buggy_engagement_state", {}),
        ("buggy_engagement_status", {}),
        ("buggy_cancel_engagement", {}),
        ("buggy_watch", {}),
        ("buggy_send_message", {"message": "scope fixture"}),
    ],
)
async def test_started_selected_thread_is_controllable(
    engagement_name: str | None,
    hydrate: bool,
    tool: str,
    arguments: dict[str, str],
    selected_client: _Client,
) -> None:
    selected_client.runs.hydrate = hydrate
    async with create_connected_server_and_client_session(_server(selected_client)) as session:
        start = await session.call_tool(
            "buggy_start_engagement",
            {
                "targets": ["http://127.0.0.1:9"],
                "engagement_name": engagement_name,
            },
        )
        handle = start.structuredContent or {}
        response = await session.call_tool(tool, {"thread_id": handle["thread_id"], **arguments})
        assert not response.isError, response.content


async def test_start_defaults_to_selected_engagement(selected_client: _Client) -> None:
    async with create_connected_server_and_client_session(_server(selected_client)) as session:
        start = await session.call_tool("buggy_start_engagement", {"targets": []})
        assert (start.structuredContent or {}).get("engagement_name") == "selected"


async def test_foreign_start_is_rejected(selected_client: _Client) -> None:
    async with create_connected_server_and_client_session(_server(selected_client)) as session:
        response = await session.call_tool(
            "buggy_start_engagement",
            {
                "targets": [],
                "engagement_name": "foreign",
            },
        )
        assert response.isError


async def test_foreign_start_creates_no_thread(selected_client: _Client) -> None:
    async with create_connected_server_and_client_session(_server(selected_client)) as session:
        await session.call_tool(
            "buggy_start_engagement",
            {
                "targets": [],
                "engagement_name": "foreign",
            },
        )
        assert selected_client.threads.created == []


async def test_selected_start_sets_runtime_workspace(selected_client: _Client) -> None:
    async with create_connected_server_and_client_session(_server(selected_client)) as session:
        await session.call_tool("buggy_start_engagement", {"targets": []})
        assert (
            selected_client.runs.config.get("configurable", {}).get("workspace_path")
            == "/workspace"
        )


async def test_pending_selected_thread_is_listed(selected_client: _Client) -> None:
    selected_client.runs.hydrate = False
    async with create_connected_server_and_client_session(_server(selected_client)) as session:
        start = await session.call_tool("buggy_start_engagement", {"targets": []})
        handle = start.structuredContent or {}
        response = await session.call_tool("buggy_list_engagements", {"limit": 1})
        rows = (response.structuredContent or {}).get("result", [])
        assert [row["thread_id"] for row in rows] == [handle["thread_id"]]


@pytest.mark.parametrize(
    "metadata",
    [
        None,
        [],
        {},
        {
            "engagement_name": "selected",
            "workspace_identity": "/another-root",
            "workspace_path": "/workspace",
        },
    ],
)
async def test_host_path_cannot_substitute_for_workspace_identity(
    metadata: Any,
    selected_client: _Client,
) -> None:
    selected_client.threads.metadata["selected-thread"] = metadata
    selected_client.threads.states["selected-thread"]["values"]["workspace_path"] = str(
        selected_client.threads.workspace
    )
    async with create_connected_server_and_client_session(_server(selected_client)) as session:
        response = await session.call_tool(
            "buggy_engagement_state", {"thread_id": "selected-thread"}
        )
        assert response.isError


@pytest.mark.parametrize(
    "state", [None, {"values": []}, {"values": {"engagement_name": "foreign"}}]
)
async def test_thread_scope_failures_use_a_domain_exception(
    state: Any, selected_client: _Client
) -> None:
    selected_client.threads.states["selected-thread"] = state
    engagements = EngagementClient(
        ServerConfig("http://test:2024", "soundwave", 10), client=selected_client
    )
    with pytest.raises(ValueError) as failure:
        await _selected_thread_state(engagements, "selected-thread")
    assert failure.type is not ValueError


async def test_listing_propagates_backend_value_error(selected_client: _Client) -> None:
    selected_client.threads.failure = ValueError("backend decode failed")
    async with create_connected_server_and_client_session(_server(selected_client)) as session:
        response = await session.call_tool("buggy_list_engagements", {})
        assert response.isError


@pytest.mark.parametrize("runtime_path", ["/workspace", "/tenants/selected"])
async def test_listing_uses_bound_runtime_workspace(
    runtime_path: str,
    selected_client: _Client,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("BUGGY_WORKSPACE_PATH", runtime_path)
    selected_client.threads.metadata["selected-thread"]["workspace_path"] = runtime_path
    selected_client.threads.states["selected-thread"]["values"]["workspace_path"] = runtime_path
    async with create_connected_server_and_client_session(_server(selected_client)) as session:
        response = await session.call_tool("buggy_list_engagements", {})
        rows = (response.structuredContent or {}).get("result", [])
        assert [row["thread_id"] for row in rows] == ["selected-thread"]
