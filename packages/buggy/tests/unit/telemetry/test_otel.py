"""Buggy: telemetry removed — OpenTelemetry/OTLP export is permanently off.

The helpers keep their names (callers import them) but emit zero spans and
never import an ``opentelemetry`` exporter, even with ``OTEL_ENABLED=1``.
"""

from __future__ import annotations

import pytest

from buggy.telemetry import otel as otel_module
from buggy.telemetry.otel import (
    init_otel,
    record_llm_cost,
    record_llm_token_usage,
    reset_current_objective_id,
    set_current_objective_id,
    start_agent_span,
    start_engagement_span,
    start_llm_span,
    start_tool_span,
)


def test_enabled_is_always_false(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OTEL_ENABLED", "1")
    assert otel_module._enabled() is False


def test_init_otel_always_false_even_when_env_set(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OTEL_ENABLED", "1")
    monkeypatch.setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "https://otel.example")
    assert init_otel() is False


def test_init_otel_does_not_import_opentelemetry(monkeypatch: pytest.MonkeyPatch) -> None:
    # Calling init_otel (the only place upstream imported the exporter) must not
    # pull in the opentelemetry SDK/exporter. Make any such import explode: if
    # our code tried, the AssertionError would surface as a test failure.
    real_import = __import__

    def _boom(name: str, *a: object, **k: object) -> object:
        if name.startswith("opentelemetry"):
            raise AssertionError(f"Buggy telemetry must not import {name}")
        return real_import(name, *a, **k)

    monkeypatch.setattr("builtins.__import__", _boom)
    monkeypatch.setenv("OTEL_ENABLED", "1")
    assert init_otel() is False


def test_span_helpers_emit_nothing_and_are_safe(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OTEL_ENABLED", "1")
    # Full nesting must run without a tracer and yield None spans throughout.
    with start_engagement_span("eng-x") as eng:
        assert eng is None
        with start_agent_span("buggy") as agent:
            assert agent is None
            token = set_current_objective_id("OBJ-1")
            assert token is None  # disabled → no context bound
            try:
                with start_tool_span("update_objective") as tool:
                    assert tool is None
                with start_llm_span("anthropic/claude-haiku-4-5") as llm:
                    assert llm is None
                    record_llm_cost(0.42)
                    record_llm_token_usage(prompt_tokens=10, completion_tokens=5)
            finally:
                reset_current_objective_id(token)


def test_set_current_objective_id_returns_none(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OTEL_ENABLED", "1")
    assert set_current_objective_id("OBJ-1") is None
    reset_current_objective_id(None)  # must be safe with a None token
