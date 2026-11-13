"""Buggy: telemetry removed — the exporter's network sender is inert.

Locks in that ``_http_post`` opens no socket, that the module imports no
``urllib``, and that a ``BatchExporter`` left on its DEFAULT transport sends
nothing even when flushed.
"""

from __future__ import annotations

from typing import Any

from buggy.telemetry import exporter as exporter_mod
from buggy.telemetry.exporter import BatchExporter, _http_post


def _envelope(events: list[dict[str, Any]]) -> dict[str, Any]:
    return {"schema_version": "1.0", "events": events}


def test_http_post_is_inert_noop() -> None:
    # Returns None, opens nothing, raises nothing — the one sender is dead.
    assert _http_post("https://gw.example", b"{}") is None


def test_exporter_module_imports_no_network_stack() -> None:
    # No urllib / socket / requests pulled into the telemetry exporter.
    assert not hasattr(exporter_mod, "urllib")
    assert not hasattr(exporter_mod, "socket")
    assert not hasattr(exporter_mod, "requests")


def test_default_transport_is_the_inert_sender() -> None:
    # A BatchExporter with no injected transport routes to the inert _http_post,
    # so a full record+flush cycle sends nothing and never raises.
    exp = BatchExporter(
        endpoint="https://gw.example",
        envelope=_envelope,
        batch_size=1,
        flush_interval_s=0,  # disable the background timer
    )
    assert exp._transport is _http_post
    exp.record({"type": "tool.call", "ts": 1})  # inline flush via default (inert) transport
    exp.close()  # final flush — still inert


def test_buffering_still_works_with_injected_transport() -> None:
    # The type stays drop-in: with an explicit transport the queue behaves, so
    # nothing downstream breaks. (The default path, above, remains inert.)
    sent: list[bytes] = []
    exp = BatchExporter(
        endpoint="https://gw.example",
        envelope=_envelope,
        batch_size=3,
        flush_interval_s=0,
        transport=lambda _url, body: sent.append(body),
    )
    exp.record({"type": "tool.call", "ts": 1})
    exp.record({"type": "tool.call", "ts": 2})
    assert sent == []  # not full yet
    exp.record({"type": "tool.call", "ts": 3})  # triggers flush
    assert len(sent) == 1


def test_injected_transport_failure_is_swallowed() -> None:
    def boom(_url: str, _body: bytes) -> None:
        raise OSError("network down")

    exp = BatchExporter(
        endpoint="https://gw.example",
        envelope=_envelope,
        batch_size=1,
        flush_interval_s=0,
        transport=boom,
    )
    exp.record({"type": "tool.call", "ts": 1})  # must not raise
    exp.close()
