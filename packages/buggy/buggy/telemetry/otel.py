"""OpenTelemetry trace helpers (opt-in, no-op when disabled).

Every public helper degrades gracefully through two failure modes:

1. ``OTEL_ENABLED`` env var is not truthy -> all helpers are no-ops.
2. ``opentelemetry`` packages are not installed (the ``telemetry`` extra is
   optional) -> all helpers are no-ops and emit one debug log line.

The library therefore stays safe to import from any process without the
optional extra, and trace cardinality is bounded to stable identifiers
(engagement id, agent name, tool name, model name, objective id, token
counts, cost). Prompt text, tool outputs, credentials, and target URLs
are never recorded as span attributes.
"""

from __future__ import annotations

import logging
from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from typing import Any

log = logging.getLogger("buggy.telemetry.otel")

_INITIALIZED: bool = False
_TRACER: Any = None

_current_engagement_id: ContextVar[str | None] = ContextVar("buggy_engagement_id", default=None)
_current_agent: ContextVar[str | None] = ContextVar("buggy_agent", default=None)
_current_objective_id: ContextVar[str | None] = ContextVar("buggy_objective_id", default=None)
_active_llm_span: ContextVar[Any | None] = ContextVar("buggy_active_llm_span", default=None)
_active_engagement_span: ContextVar[Any | None] = ContextVar(
    "buggy_active_engagement_span", default=None
)


def _enabled() -> bool:
    """Buggy: telemetry removed — OpenTelemetry export is always off.

    ``OTEL_ENABLED`` and friends are ignored, so every span helper below is a
    no-op and no tracer provider / OTLP exporter is ever created.
    """
    return False


def init_otel() -> bool:
    """Buggy: telemetry removed — OTLP export permanently disabled.

    Always returns ``False`` and never imports any ``opentelemetry`` exporter,
    so no span ever leaves the process and the optional network extra is never
    loaded. Kept for import/call compatibility.
    """
    return False


def _reset_for_tests() -> None:
    """Test-only: forget initialization so a fresh provider can be installed."""
    global _INITIALIZED, _TRACER
    _INITIALIZED = False
    _TRACER = None


def _get_tracer() -> Any | None:
    if not _enabled():
        return None
    init_otel()
    return _TRACER


@contextmanager
def _noop() -> Iterator[Any]:
    yield None


@contextmanager
def start_engagement_span(engagement_id: str) -> Iterator[Any]:
    """Start the top-level engagement span and set engagement-id context."""
    tracer = _get_tracer()
    eng_token = _current_engagement_id.set(engagement_id)
    if tracer is None:
        try:
            yield None
        finally:
            _current_engagement_id.reset(eng_token)
        return

    with tracer.start_as_current_span("buggy.engagement") as span:
        span.set_attribute("buggy.engagement_id", engagement_id)
        span_token = _active_engagement_span.set(span)
        try:
            yield span
        finally:
            _active_engagement_span.reset(span_token)
            _current_engagement_id.reset(eng_token)


@contextmanager
def start_agent_span(agent_name: str) -> Iterator[Any]:
    """Start an agent-run span as a child of the active engagement (if any)."""
    tracer = _get_tracer()
    agent_token = _current_agent.set(agent_name)
    if tracer is None:
        try:
            yield None
        finally:
            _current_agent.reset(agent_token)
        return

    with tracer.start_as_current_span("buggy.agent_run") as span:
        span.set_attribute("buggy.agent", agent_name)
        eng_id = _current_engagement_id.get()
        if eng_id:
            span.set_attribute("buggy.engagement_id", eng_id)
        try:
            yield span
        finally:
            _current_agent.reset(agent_token)


@contextmanager
def start_tool_span(tool_name: str) -> Iterator[Any]:
    """Start a tool-call span as a sibling of llm_call under agent_run."""
    tracer = _get_tracer()
    if tracer is None:
        yield None
        return

    with tracer.start_as_current_span("buggy.tool_call") as span:
        span.set_attribute("buggy.tool", tool_name)
        eng_id = _current_engagement_id.get()
        if eng_id:
            span.set_attribute("buggy.engagement_id", eng_id)
        agent = _current_agent.get()
        if agent:
            span.set_attribute("buggy.agent", agent)
        objective = _current_objective_id.get()
        if objective:
            span.set_attribute("buggy.opplan.objective_id", objective)
        yield span


@contextmanager
def start_llm_span(model: str) -> Iterator[Any]:
    """Start an LLM-call span; cost / token attrs land on the active span."""
    tracer = _get_tracer()
    if tracer is None:
        yield None
        return

    with tracer.start_as_current_span("buggy.llm_call") as span:
        span.set_attribute("buggy.llm.model", model)
        eng_id = _current_engagement_id.get()
        if eng_id:
            span.set_attribute("buggy.engagement_id", eng_id)
        agent = _current_agent.get()
        if agent:
            span.set_attribute("buggy.agent", agent)
        objective = _current_objective_id.get()
        if objective:
            span.set_attribute("buggy.opplan.objective_id", objective)
        llm_token = _active_llm_span.set(span)
        try:
            yield span
        finally:
            _active_llm_span.reset(llm_token)


def _set_span_attribute(span: Any, key: str, value: Any) -> bool:
    """Set a span attribute, returning False if the SDK rejected it.

    Telemetry is observability, never control flow: a failed write must not
    propagate to the caller. We log at debug instead of swallowing silently
    so a broken exporter is diagnosable.
    """
    try:
        span.set_attribute(key, value)
        return True
    except Exception as exc:
        log.debug("otel set_attribute failed key=%s: %s", key, exc)
        return False


def record_llm_cost(cost_usd: float | None) -> None:
    """Attach cost to the active llm_call span, or to engagement as fallback."""
    if cost_usd is None:
        return
    llm_span = _active_llm_span.get()
    if llm_span is not None and _set_span_attribute(
        llm_span, "buggy.llm.cost_usd", float(cost_usd)
    ):
        return
    eng_span = _active_engagement_span.get()
    if eng_span is not None:
        _set_span_attribute(eng_span, "buggy.llm.cost_usd", float(cost_usd))


def record_llm_token_usage(
    prompt_tokens: int | None = None, completion_tokens: int | None = None
) -> None:
    """Attach prompt / completion token counts to the active llm_call span."""
    span = _active_llm_span.get()
    if span is None:
        return
    if prompt_tokens is not None:
        _set_span_attribute(span, "buggy.llm.prompt_tokens", int(prompt_tokens))
    if completion_tokens is not None:
        _set_span_attribute(span, "buggy.llm.completion_tokens", int(completion_tokens))


def set_current_objective_id(objective_id: str | None) -> object | None:
    """Bind an OPPLAN objective id into the current context.

    Returns a token that the caller can pass to
    :func:`reset_current_objective_id` to unbind. Returns ``None`` when the
    feature is disabled so callers can no-op the unbind step.
    """
    if not _enabled():
        return None
    return _current_objective_id.set(objective_id)


def reset_current_objective_id(token: object | None) -> None:
    """Unbind a previously-set OPPLAN objective id."""
    if token is None:
        return
    try:
        _current_objective_id.reset(token)
    except (ValueError, LookupError):
        pass
