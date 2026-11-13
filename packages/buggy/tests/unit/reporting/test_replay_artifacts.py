"""Replay artifacts — verified findings mint Caido replay entries."""

from __future__ import annotations

import asyncio
import json
from typing import Any
from unittest.mock import patch

import pytest

from buggy.tools.proxy.tools import CaidoClient, CaidoError
from buggy.tools.reporting.tools import _mint_replays


class _ReplayClient(CaidoClient):
    """Minimal client double — only ``repeat_request`` is exercised."""

    def __init__(self, ok: set[str], failing: set[str] | None = None) -> None:
        self.ok = ok
        self.failing = failing or set()
        self.repeated: list[str] = []

    def repeat_request(self, request_id: str, mutations_json: str = "") -> dict[str, Any]:
        self.repeated.append(request_id)
        if request_id in self.failing:
            raise CaidoError("Caido CLI exited 1: boom", kind="exited", exit_code=1)
        return {"replay_id": f"r{request_id}", "session": "Replay-1"}


def test_mint_replays_records_payloads() -> None:
    client = _ReplayClient(ok={"101", "102"})
    replay = _mint_replays(client, ["101", "102"], "SQLi on /login")
    assert replay is not None
    assert replay["name"] == "finding::sqli-on-login"
    assert replay["repeat_commands"] == [
        "caido requests repeat 101",
        "caido requests repeat 102",
    ]
    assert client.repeated == ["101", "102"]
    assert replay["entries"][0]["replay"]["replay_id"] == "r101"


def test_mint_replays_failure_is_per_entry_not_fatal() -> None:
    client = _ReplayClient(ok={"101"}, failing={"102"})
    replay = _mint_replays(client, ["101", "102"], "t")
    assert replay is not None
    assert replay["entries"][0]["replay"]["replay_id"] == "r101"
    assert replay["entries"][1]["error"].startswith("Caido CLI exited 1")
    assert replay["entries"][1]["kind"] == "exited"


def test_mint_replays_no_ids_returns_none() -> None:
    assert _mint_replays(_ReplayClient(ok=set()), [], "t") is None
    assert _mint_replays(None, None, "t") is None


def test_mint_replays_env_off_keeps_commands_only(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("BUGGY_FINDING_REPLAY", "0")
    client = _ReplayClient(ok={"101"})
    replay = _mint_replays(client, ["101"], "t")
    assert replay is not None
    assert replay["entries"] == []
    assert replay["repeat_commands"] == ["caido requests repeat 101"]
    assert client.repeated == []


def test_mint_replays_no_client_keeps_commands_only(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("BUGGY_FINDING_REPLAY", raising=False)
    replay = _mint_replays(None, ["101"], "t")
    assert replay is not None
    assert replay["entries"] == []


def test_record_finding_attaches_replay_block() -> None:
    """End-to-end: a gated finding carries the replay block through to the KG."""
    from buggy.tools.reporting.tools import report_record_finding

    class _GateClient(_ReplayClient):
        def view_request(self, request_id: str) -> dict[str, Any]:
            return {"id": request_id, "url": "https://t/x"}

    captured: dict[str, Any] = {}

    def _capture(engagement: str, finding: dict[str, Any], **kw: Any):
        captured.update(finding)
        return ("node1", True)

    with (
        patch(
            "buggy.tools.reporting.tools._new_caido_client",
            return_value=_GateClient(ok={"101"}),
        ),
        patch(
            "buggy.tools.reporting.tools.publish_finding_node",
            side_effect=_capture,
        ),
        patch(
            "buggy.tools.reporting.tools.get_active_engagement",
            return_value="eng",
        ),
        patch.dict("os.environ", {"BUGGY_PROOF_GATE_STRICT": "1"}, clear=False),
    ):
        raw = asyncio.run(
            report_record_finding.ainvoke(
                {
                    "title": "SQLi",
                    "poc_script_code": "x",
                    "poc_description": "y",
                    "evidence": "z",
                    "http_exchange_ids": ["101"],
                }
            )
        )
    payload = json.loads(raw)
    assert payload["success"] is True
    assert payload["replay"]["name"] == "finding::sqli"
    assert captured["replay"]["entries"][0]["replay"]["replay_id"] == "r101"
