"""Unit tests for the web_search / web_fetch management-side tool wrappers."""

from __future__ import annotations

import json
import shlex
from collections.abc import Iterator
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, HTTPServer
from importlib import import_module
from threading import Thread

import pytest
from langchain_core.tools import StructuredTool

from buggy.backends.http_sandbox import HTTPSandbox
from buggy.middleware.roe import GATED_TOOL_NAMES, NETWORK_TARGET_EXTRACTORS
from buggy.middleware.untrusted_output import UNTRUSTED_TOOL_NAMES
from buggy.tools.web import search


@dataclass
class _ExecResp:
    output: str
    exit_code: int = 0
    truncated: bool = False


class _FakeSandbox:
    def __init__(self, output: str) -> None:
        self.output = output
        self.commands: list[str] = []

    def execute(self, command: str, *, timeout: int | None = None) -> _ExecResp:
        self.commands.append(command)
        return _ExecResp(output=self.output)


def _patch_sandbox(monkeypatch: pytest.MonkeyPatch, output: str) -> _FakeSandbox:
    fake = _FakeSandbox(output)
    monkeypatch.setattr(search, "get_sandbox", lambda _config=None: fake)
    monkeypatch.setattr(search, "_workspace_path_from_config", lambda _c: "/workspace/eng1")
    return fake


# --- JSON extraction (robust to parent-import log noise) ---------------------


def test_extract_json_clean() -> None:
    assert search._extract_json('{"ok": true}') == {"ok": True}


def test_extract_json_last_line_amid_noise() -> None:
    noisy = 'INFO factory: blah\nWARNING something\n{"ok": false, "verdict": "challenge"}'
    assert search._extract_json(noisy) == {"ok": False, "verdict": "challenge"}


def test_extract_json_none_when_absent() -> None:
    assert search._extract_json("just logs, no json") is None


# --- web_fetch ---------------------------------------------------------------


async def test_web_fetch_ok(monkeypatch: pytest.MonkeyPatch) -> None:
    payload = json.dumps(
        {
            "ok": True,
            "verdict": "strong_ok",
            "final_url": "https://x.test/a",
            "content": "<h1>hi</h1>",
            "content_length": 11,
            "content_truncated": False,
        }
    )
    fake = _patch_sandbox(monkeypatch, "noise\n" + payload)
    out = await search.web_fetch.ainvoke({"url": "https://x.test/a", "selector": "h1"})
    assert "web_fetch OK" in out
    assert "strong_ok" in out
    assert "<h1>hi</h1>" in out
    # Command dispatched the engine into the sandbox with the right verb/args.
    # Assert the URL as an exact shlex token (== — not a URL substring test).
    cmd = fake.commands[0]
    argv = shlex.split(cmd)
    assert "buggy.sandbox_web fetch" in cmd
    assert any(a == "https://x.test/a" for a in argv)
    assert "--workspace" in cmd and "/workspace/eng1" in cmd
    assert "--selector" in cmd


async def test_web_fetch_failure_verdict(monkeypatch: pytest.MonkeyPatch) -> None:
    payload = json.dumps({"ok": False, "verdict": "challenge", "summary": "all blocked"})
    _patch_sandbox(monkeypatch, payload)
    out = await search.web_fetch.ainvoke({"url": "https://x.test/a"})
    assert "web_fetch FAILED" in out
    assert "challenge" in out


async def test_web_fetch_scope_refusal_is_not_reported_as_login(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = json.dumps(
        {"ok": False, "verdict": "blocked", "stop_reason": "roe_refused", "summary": "ROE_REFUSED"}
    )
    _patch_sandbox(monkeypatch, payload)
    out = await search.web_fetch.ainvoke({"url": "https://outside.test/"})

    assert "Check the signed engagement scope" in out
    assert "TERMINAL (login/paywall/404)" not in out


async def test_web_fetch_no_sandbox(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(search, "get_sandbox", lambda _config=None: None)
    monkeypatch.setattr(search, "_workspace_path_from_config", lambda _c: "/workspace/eng1")
    out = await search.web_fetch.ainvoke({"url": "https://x.test/a"})
    assert "no sandbox" in out


# --- web_search --------------------------------------------------------------


async def test_web_search_hits(monkeypatch: pytest.MonkeyPatch) -> None:
    payload = json.dumps(
        {
            "provider": "duckduckgo",
            "query": "q",
            "count": 2,
            "hits": [
                {"title": "A", "url": "https://a.test", "snippet": "sa"},
                {"title": "B", "url": "https://b.test", "snippet": ""},
            ],
        }
    )
    fake = _patch_sandbox(monkeypatch, payload)
    out = await search.web_search.ainvoke({"query": "q"})
    assert "2 results" in out
    # Exact-equality match per line (== is complete sanitization — avoids
    # CodeQL's incomplete-url-substring-sanitization query, which fires on
    # any `<url-literal> in <expr>` membership test even in test asserts).
    lines = [ln.strip() for ln in out.splitlines()]
    assert any(ln == "https://a.test" for ln in lines)
    assert any(ln == "https://b.test" for ln in lines)
    assert "buggy.sandbox_web search" in fake.commands[0]


async def test_web_search_provider_error(monkeypatch: pytest.MonkeyPatch) -> None:
    payload = json.dumps(
        {"provider": "google", "query": "q", "hits": [], "error": "not in allowlist"}
    )
    _patch_sandbox(monkeypatch, payload)
    out = await search.web_search.ainvoke({"query": "q", "provider": "google"})
    assert "web_search FAILED" in out
    assert "allowlist" in out


# --- middleware wiring -------------------------------------------------------


def test_tools_are_roe_gated() -> None:
    assert "web_fetch" in GATED_TOOL_NAMES
    assert "web_search" in GATED_TOOL_NAMES


def test_web_fetch_target_gated_web_search_exempt() -> None:
    # web_fetch extracts the url host (target-gated)...
    assert NETWORK_TARGET_EXTRACTORS["web_fetch"]({"url": "https://t.test/x"}) == ["t.test"]
    # ...web_search is OSINT: no host extracted (target-exempt, still audited).
    assert NETWORK_TARGET_EXTRACTORS["web_search"]({"query": "q"}) == []


def test_tools_are_untrusted() -> None:
    assert "web_fetch" in UNTRUSTED_TOOL_NAMES
    assert "web_search" in UNTRUSTED_TOOL_NAMES


@pytest.mark.parametrize("web_tool", [search.web_fetch, search.web_search])
def test_tool_schema_excludes_injected_config(web_tool: StructuredTool) -> None:
    assert "config" not in web_tool.args


@pytest.fixture
def sandbox_http(
    monkeypatch: pytest.MonkeyPatch,
) -> Iterator[tuple[str, list[tuple[str, str | None, list[str]]]]]:
    calls: list[tuple[str, str | None, list[str]]] = []

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            payload = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            calls.append(
                (self.path, self.headers.get("Authorization"), shlex.split(payload["command"]))
            )
            body = json.dumps({"output": "{}", "exit_code": 0}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format: str, *args: object) -> None:
            return

    server = HTTPServer(("127.0.0.1", 0), Handler)
    worker = Thread(target=server.serve_forever, daemon=True)
    worker.start()
    url = f"http://127.0.0.1:{server.server_port}"
    sandbox = HTTPSandbox(url)
    bash_module = import_module("buggy.tools.bash.bash")
    monkeypatch.setattr(bash_module, "_sandbox_default", sandbox)
    token = bash_module._sandbox_var.set(sandbox)
    try:
        yield url, calls
    finally:
        bash_module._sandbox_var.reset(token)
        sandbox.close()
        server.shutdown()
        server.server_close()
        worker.join(timeout=5)


@pytest.fixture(
    params=[
        (web_tool, arguments, engine_args, forged_config)
        for web_tool, arguments, engine_args in [
            (
                search.web_fetch,
                {"url": "https://outside.test/"},
                ["fetch", "https://outside.test/"],
            ),
            (
                search.web_search,
                {"query": "scope fixture"},
                ["search", "scope fixture", "--provider", "duckduckgo"],
            ),
        ]
        for forged_config in (False, True)
    ],
    ids=["fetch-trusted", "fetch-forged", "search-trusted", "search-forged"],
)
async def native_requests(
    request: pytest.FixtureRequest,
    sandbox_http: tuple[str, list[tuple[str, str | None, list[str]]]],
) -> tuple[list[tuple[str, str | None, list[str]]], list[str]]:
    url, calls = sandbox_http
    web_tool, arguments, engine_args, forged_config = request.param
    invocation_args: dict[str, object] = dict(arguments)
    if forged_config:
        invocation_args["config"] = {"configurable": {"workspace_path": "/workspace/foreign"}}
    await web_tool.ainvoke(
        invocation_args,
        config={
            "configurable": {
                "sandbox_url": f"{url}/selected",
                "sandbox_token": "fixture-token",
                "workspace_path": "/workspace/selected-engagement",
            }
        },
    )
    expected_command = [
        "python3",
        "-m",
        "buggy.sandbox_web",
        *engine_args,
        "--workspace",
        "/workspace/selected-engagement",
    ]
    return calls, expected_command


def test_native_invocation_uses_selected_endpoint(
    native_requests: tuple[list[tuple[str, str | None, list[str]]], list[str]],
) -> None:
    assert [call[0] for call in native_requests[0]] == ["/selected/execute"]


def test_native_invocation_uses_selected_token(
    native_requests: tuple[list[tuple[str, str | None, list[str]]], list[str]],
) -> None:
    assert [call[1] for call in native_requests[0]] == ["Bearer fixture-token"]


def test_native_invocation_uses_selected_workspace(
    native_requests: tuple[list[tuple[str, str | None, list[str]]], list[str]],
) -> None:
    calls, expected_command = native_requests
    assert [call[2] for call in calls] == [expected_command]
