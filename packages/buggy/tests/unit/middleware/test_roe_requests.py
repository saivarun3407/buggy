"""RoE checks on LangChain's native request shape, without network or shell IO."""

from __future__ import annotations

import asyncio
import json
from collections.abc import Sequence
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
from langchain.agents import create_agent
from langchain.agents.middleware import AgentState
from langchain.agents.middleware.types import ToolCallRequest
from langchain_core.language_models.fake_chat_models import FakeMessagesListChatModel
from langchain_core.messages import AIMessage, HumanMessage, ToolMessage
from langchain_core.tools import BaseTool, tool

from buggy.middleware.roe import RoEAuditSink, RoEGuardrailMiddleware


@pytest.fixture
def workspace(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setenv("BUGGY_EGRESS_DISABLE", "1")
    (tmp_path / "plan").mkdir()
    (tmp_path / "plan" / "roe.json").write_text(
        json.dumps(
            {
                "machine_enforcement": {
                    "mode": "enforce",
                    "in_scope": ["allowed.example"],
                    "out_of_scope": ["denied.example"],
                    "forbidden_destinations": ["forbidden.example"],
                    "forbidden_command_patterns": ["blocked-marker"],
                }
            }
        ),
        encoding="utf-8",
    )
    return tmp_path


@pytest.fixture
def local_tools() -> tuple[dict[str, BaseTool], list[str]]:
    calls: list[str] = []

    @tool
    def bash(command: str) -> str:
        """Record a command without executing it."""
        calls.append(command)
        return command

    @tool
    def http_request(url: str) -> str:
        """Record a URL without connecting to it."""
        calls.append(url)
        return url

    return {"bash": bash, "http_request": http_request}, calls


@pytest.mark.parametrize("use_async", [False, True], ids=["sync", "async"])
@pytest.mark.parametrize(
    ("name", "args", "reason"),
    [
        ("bash", {"command": "printf harmless"}, None),
        ("bash", {"command": "printf blocked-marker"}, "FORBIDDEN_COMMAND"),
        ("bash", {"command": "curl https://denied.example/"}, "OUT_OF_SCOPE"),
        ("http_request", {"url": "https://allowed.example/"}, None),
        ("http_request", {"url": "https://denied.example/"}, "OUT_OF_SCOPE"),
        ("http_request", {"url": "https://unrelated.example/"}, "NOT_IN_SCOPE"),
        ("http_request", {"url": "https://forbidden.example/"}, "FORBIDDEN_DESTINATION"),
    ],
)
def test_native_request_scope_and_command_checks(
    workspace: Path,
    local_tools: tuple[dict[str, BaseTool], list[str]],
    use_async: bool,
    name: str,
    args: dict[str, str],
    reason: str | None,
) -> None:
    tools, _calls = local_tools
    request = ToolCallRequest(
        tool_call={"name": name, "args": args, "id": "native-id", "type": "tool_call"},
        tool=tools[name],
        state={"workspace_path": str(workspace)},
        runtime=MagicMock(),
    )
    mw = RoEGuardrailMiddleware(sink=RoEAuditSink(path=workspace / "audit.jsonl"))
    handler = AsyncMock() if use_async else MagicMock()
    response = (
        asyncio.run(mw.awrap_tool_call(request, handler))
        if use_async
        else mw.wrap_tool_call(request, handler)
    )
    if reason is None:
        handler.assert_called_once()
    else:
        handler.assert_not_called()
        assert isinstance(response, ToolMessage)
        assert reason in response.content
        assert response.tool_call_id == "native-id"
    record = json.loads((workspace / "audit.jsonl").read_text(encoding="utf-8"))
    assert record["decision"] == ("allow" if reason is None else "refuse")
    assert record["command_excerpt"] == args.get("command", "")


@pytest.mark.parametrize("use_async", [False, True], ids=["sync", "async"])
@pytest.mark.parametrize("abort", [False, True], ids=["invalid-policy", "abort"])
def test_native_refusal_preserves_call_id(
    workspace: Path,
    local_tools: tuple[dict[str, BaseTool], list[str]],
    use_async: bool,
    abort: bool,
) -> None:
    if abort:
        (workspace / ".abort").touch()
    else:
        (workspace / "plan" / "roe.json").write_text("{invalid", encoding="utf-8")
    tools, _calls = local_tools
    request = ToolCallRequest(
        tool_call={
            "name": "bash",
            "args": {"command": "printf harmless"},
            "id": "native-id",
            "type": "tool_call",
        },
        tool=tools["bash"],
        state={"workspace_path": str(workspace)},
        runtime=MagicMock(),
    )
    mw = RoEGuardrailMiddleware()
    handler = AsyncMock() if use_async else MagicMock()
    response = (
        asyncio.run(mw.awrap_tool_call(request, handler))
        if use_async
        else mw.wrap_tool_call(request, handler)
    )
    handler.assert_not_called()
    assert isinstance(response, ToolMessage)
    assert ("EMERGENCY_ABORT" if abort else "INVALID_ROE") in response.content
    assert response.tool_call_id == "native-id"


class _WorkspaceState(AgentState):
    workspace_path: str


class _FixtureModel(FakeMessagesListChatModel):
    def bind_tools(self, tools: Sequence[Any], **kwargs: Any) -> _FixtureModel:
        return self


@pytest.mark.parametrize("use_async", [False, True], ids=["sync", "async"])
def test_agent_graph_refuses_then_allows_native_calls(
    workspace: Path, local_tools: tuple[dict[str, BaseTool], list[str]], use_async: bool
) -> None:
    tools, calls = local_tools
    requests = [
        ("http_request", {"url": "https://denied.example/"}),
        ("http_request", {"url": "https://allowed.example/"}),
        ("bash", {"command": "printf blocked-marker"}),
        ("bash", {"command": "printf harmless"}),
    ]
    model = _FixtureModel(
        responses=[
            AIMessage(
                content="",
                tool_calls=[{"name": name, "args": args, "id": str(index), "type": "tool_call"}],
            )
            for index, (name, args) in enumerate(requests)
        ]
        + [AIMessage(content="done")]
    )
    graph = create_agent(
        model=model,
        tools=list(tools.values()),
        middleware=[RoEGuardrailMiddleware(sink=RoEAuditSink(path=workspace / "audit.jsonl"))],
        state_schema=_WorkspaceState,
    )
    initial = {
        "messages": [HumanMessage(content="Run the offline fixture")],
        "workspace_path": str(workspace),
    }
    completed = asyncio.run(graph.ainvoke(initial)) if use_async else graph.invoke(initial)
    messages = [message for message in completed["messages"] if isinstance(message, ToolMessage)]
    assert calls == ["https://allowed.example/", "printf harmless"]
    assert [message.tool_call_id for message in messages] == ["0", "1", "2", "3"]
    assert "OUT_OF_SCOPE" in messages[0].content
    assert "FORBIDDEN_COMMAND" in messages[2].content
    records = [json.loads(line) for line in (workspace / "audit.jsonl").read_text().splitlines()]
    assert [record["decision"] for record in records] == ["refuse", "allow", "refuse", "allow"]


@pytest.mark.parametrize("use_async", [False, True], ids=["sync", "async"])
@pytest.mark.parametrize("native", [False, True], ids=["legacy", "native"])
@pytest.mark.parametrize(
    ("template", "redacted"),
    [
        (
            'curl -H "Authorization: Bearer {secret}" https://allowed.example/',
            'curl -H "Authorization: ***" https://allowed.example/',
        ),
        ("curl https://user:{secret}@allowed.example/", "curl https://user:***@allowed.example/"),
        ('tool --password="{secret}"', "tool --password=***"),
        ("tool --token {secret}", "tool --token ***"),
    ],
)
def test_abort_audit_redacts_before_truncation(
    workspace: Path,
    local_tools: tuple[dict[str, BaseTool], list[str]],
    use_async: bool,
    native: bool,
    template: str,
    redacted: str,
) -> None:
    (workspace / ".abort").touch()
    tools, _calls = local_tools
    canary = "abort-canary-" + "x" * 600
    command = template.format(secret=canary)
    if native:
        request = ToolCallRequest(
            tool_call={
                "name": "bash",
                "args": {"command": command},
                "id": "abort-id",
                "type": "tool_call",
            },
            tool=tools["bash"],
            state={"workspace_path": str(workspace)},
            runtime=MagicMock(),
        )
    else:
        request = SimpleNamespace(
            tool=tools["bash"],
            tool_call_args={"command": command},
            tool_call_id="abort-id",
            state={"workspace_path": str(workspace)},
        )
    sink_path = workspace / "audit.jsonl"
    mw = RoEGuardrailMiddleware(sink=RoEAuditSink(path=sink_path))
    handler = AsyncMock() if use_async else MagicMock()
    response = (
        asyncio.run(mw.awrap_tool_call(request, handler))
        if use_async
        else mw.wrap_tool_call(request, handler)
    )
    handler.assert_not_called()
    assert isinstance(response, ToolMessage)
    assert response.tool_call_id == "abort-id"
    raw = sink_path.read_text(encoding="utf-8")
    assert "abort-canary-" not in raw
    record = json.loads(raw)
    assert record["command_excerpt"] == redacted
    assert record["event"] == "abort"


@pytest.mark.parametrize("use_async", [False, True], ids=["sync", "async"])
def test_agent_graph_abort_redacts_command(
    workspace: Path, local_tools: tuple[dict[str, BaseTool], list[str]], use_async: bool
) -> None:
    (workspace / ".abort").touch()
    tools, calls = local_tools
    model = _FixtureModel(
        responses=[
            AIMessage(
                content="",
                tool_calls=[
                    {
                        "name": "bash",
                        "args": {"command": "tool --token abort-graph-canary"},
                        "id": "abort-id",
                        "type": "tool_call",
                    }
                ],
            ),
            AIMessage(content="done"),
        ]
    )
    sink_path = workspace / "audit.jsonl"
    graph = create_agent(
        model=model,
        tools=list(tools.values()),
        middleware=[RoEGuardrailMiddleware(sink=RoEAuditSink(path=sink_path))],
        state_schema=_WorkspaceState,
    )
    initial = {
        "messages": [HumanMessage(content="Run the offline abort fixture")],
        "workspace_path": str(workspace),
    }
    completed = asyncio.run(graph.ainvoke(initial)) if use_async else graph.invoke(initial)
    assert calls == []
    messages = [message for message in completed["messages"] if isinstance(message, ToolMessage)]
    assert len(messages) == 1
    assert messages[0].tool_call_id == "abort-id"
    assert "EMERGENCY_ABORT" in messages[0].content
    raw = sink_path.read_text(encoding="utf-8")
    assert "abort-graph-canary" not in raw
    assert json.loads(raw)["command_excerpt"] == "tool --token ***"
