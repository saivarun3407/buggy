"""Buggy: telemetry removed — ground-truth capture paths are all no-ops.

Upstream, these paths (findings, phase, trajectory) forwarded structured
signal to the gateway. In Buggy they must never send. A transport spy proves
it, and the consent/persistence knobs cannot re-enable sending.
"""

from __future__ import annotations

from buggy.telemetry.config import (
    TelemetryConfig,
    TelemetryMode,
    persisted_mode,
    resolve_config,
    set_persisted_mode,
)
from buggy.telemetry.sink import TelemetrySink


def _cfg(mode: TelemetryMode, endpoint: str | None = "https://gw.example") -> TelemetryConfig:
    return TelemetryConfig(
        mode=mode,
        endpoint=endpoint,
        install_id="1e9a73a6-c8bd-4e1e-be02-78f4b11de4e1",
        version="1.1.13",
        os_name="linux",
    )


class _Spy:
    def __init__(self) -> None:
        self.calls: list[tuple[str, bytes]] = []

    def __call__(self, url: str, body: bytes) -> None:
        self.calls.append((url, body))


# ── findings / phase / trajectory never ship ─────────────────────────────────


def test_record_finding_is_a_noop() -> None:
    spy = _Spy()
    sink = TelemetrySink(_cfg(TelemetryMode.BASIC), transport=spy)
    sink.record_finding(
        severity="high",
        cwe=["CWE-89"],
        mitre=["T1190"],
        phase="initial-access",
        confidence="verified",
        detected=False,
        agent="exploit",
    )
    sink.close()
    assert spy.calls == []


def test_record_phase_is_a_noop() -> None:
    spy = _Spy()
    sink = TelemetrySink(_cfg(TelemetryMode.BASIC), transport=spy)
    sink.record_phase("recon", "pending", "buggy")
    sink.close()
    assert spy.calls == []


def test_research_trajectory_capture_is_a_noop() -> None:
    spy = _Spy()
    sink = TelemetrySink(_cfg(TelemetryMode.RESEARCH), transport=spy)
    # Even at RESEARCH consent the reasoning corpus never leaves the box.
    assert sink.research is False
    sink.record_step(
        {"role": "agent", "session_id": "s1", "step": 0, "text": "try SQLi on 10.0.0.5"},
        "exploit",
        model="anthropic/claude-opus-4-8",
    )
    sink.close()
    assert spy.calls == []


# ── consent / persistence cannot re-enable sending ───────────────────────────


def test_persisted_research_mode_cannot_enable(tmp_path) -> None:
    env = {"BUGGY_HOME": str(tmp_path)}
    set_persisted_mode(TelemetryMode.RESEARCH, env)
    # The persisted choice is still readable locally...
    assert persisted_mode(env) is TelemetryMode.RESEARCH
    # ...but resolution ignores it: the effective config stays disabled.
    cfg = resolve_config({**env, "BUGGY_TELEMETRY_ENDPOINT": "https://gw"})
    assert cfg.mode is TelemetryMode.OFF
    assert cfg.endpoint is None
    assert cfg.enabled is False


def test_env_mode_plus_endpoint_cannot_enable(tmp_path) -> None:
    cfg = resolve_config(
        {
            "BUGGY_HOME": str(tmp_path),
            "BUGGY_TELEMETRY": "basic",
            "BUGGY_TELEMETRY_ENDPOINT": "https://gw",
        }
    )
    assert cfg.enabled is False


# ── the local sanitizer mapping is still pure (used by preview) ──────────────


def test_sanitizer_slug_and_mapping_are_pure() -> None:
    from buggy.telemetry.sanitizer import event_to_tier_a, slug

    assert slug(None) is None
    assert slug("") is None
    ev = event_to_tier_a({"type": "llm.call", "ts": 1.0, "payload": {"messages": 3}})
    assert ev is not None
    assert "model" not in ev  # absent field dropped, not shipped as "none"
