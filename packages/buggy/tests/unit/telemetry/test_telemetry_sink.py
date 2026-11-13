"""Buggy: telemetry removed — the sink is always a no-op that never sends.

Locks in that ``get_sink`` is always the disabled sink, and that a sink built
with ANY config (even RESEARCH + endpoint) never constructs an exporter and
never invokes a transport. A transport spy proves nothing leaves the process.
"""

from __future__ import annotations

from typing import Any

from buggy.telemetry.config import TelemetryConfig, TelemetryMode
from buggy.telemetry.sink import TelemetrySink, get_sink, session_id_for


def _cfg(mode: TelemetryMode, endpoint: str | None) -> TelemetryConfig:
    return TelemetryConfig(
        mode=mode,
        endpoint=endpoint,
        install_id="1e9a73a6-c8bd-4e1e-be02-78f4b11de4e1",
        version="1.1.13",
        os_name="linux",
    )


class _Spy:
    """A transport that records every call. In Buggy it must never be called."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, bytes]] = []

    def __call__(self, url: str, body: bytes) -> None:
        self.calls.append((url, body))


def test_get_sink_is_always_disabled() -> None:
    sink = get_sink()
    assert sink.enabled is False
    assert sink.research is False
    # The process sink is shared (and disabled).
    assert get_sink() is sink


def test_sink_never_enables_even_with_research_and_endpoint() -> None:
    # The config says RESEARCH + endpoint, but enabled is hard-False, so the
    # sink builds no exporter.
    spy = _Spy()
    sink = TelemetrySink(_cfg(TelemetryMode.RESEARCH, "https://gw.example"), transport=spy)
    assert sink.enabled is False
    assert sink.research is False


def test_record_calls_are_noops_and_never_transport() -> None:
    spy = _Spy()
    sink = TelemetrySink(_cfg(TelemetryMode.RESEARCH, "https://gw.example"), transport=spy)
    sink.record("tool.call", {"tool": "nmap"}, "recon", session_id="s1")
    sink.record_finding(severity="high", cwe=["CWE-89"], agent="exploit", session_id="s1")
    sink.record_phase("recon", "pending", "buggy", session_id="s1")
    sink.record_step(
        {"role": "agent", "session_id": "s1", "step": 0, "text": "exploit 10.0.0.5"},
        "exploit",
    )
    sink.add_known_targets(["dc01"])
    sink.flush()
    sink.close()
    assert spy.calls == []  # nothing ever left the process


def test_disabled_sink_record_never_raises() -> None:
    sink = get_sink()
    # Must be safe to call unconditionally from the middleware / tools.
    sink.record("tool.call", {"tool": "bash"}, "recon")
    sink.record_finding(severity="critical")
    sink.record_phase("recon", "pending")
    sink.flush()
    sink.close()


def test_preview_maps_locally_without_sending() -> None:
    # `telemetry preview` still works: it maps sample events locally for display
    # and sends nothing (no transport call, no network).
    spy = _Spy()
    sink = TelemetrySink(_cfg(TelemetryMode.BASIC, "https://gw.example"), transport=spy)
    sample: list[dict[str, Any]] = [
        {"type": "tool.call", "ts": 1.0, "agent": "recon", "payload": {"tool": "nmap"}},
        {"type": "tool.call", "ts": 2.0, "agent": "recon", "payload": {"tool": "10.0.0.5"}},
    ]
    env = sink.preview(sample)
    # The leaky second event is filtered by the local Tier-C scan.
    assert len(env["events"]) == 1
    assert env["events"][0]["tool"] == "nmap"
    assert spy.calls == []  # preview is display-only, nothing sent


def test_session_id_for_is_stable_non_reversible_hash() -> None:
    a = session_id_for("acme-corp-pentest")
    assert a == session_id_for("acme-corp-pentest")  # stable
    assert len(a) == 16 and a != session_id_for("other-engagement")  # distinct
    assert "acme" not in a  # never the raw engagement name
