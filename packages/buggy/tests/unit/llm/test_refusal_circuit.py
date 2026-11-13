"""Safety-refusal circuit breaker — ``_ProxiedChatOpenAI`` + registry.

A model that answers an offensive-security engagement prompt with an
empty 200 (Anthropic-style safety refusal) makes every subsequent call
through the same chain pay the same refusal toll. The breaker memoizes
the refusal per model id with a TTL so the fallback middleware skips
the refusing model instantly instead of re-sending the full prompt.

Covers:

  - ``_check_empty_response`` raises ``LLMModelRefusalError`` (both the
    ``content_filter`` and the generic-empty shapes);
  - the wrapper marks the registry on refusal and re-raises, so the
    fallback middleware still walks the chain;
  - while the circuit is open, ``invoke``/``ainvoke`` fast-fail with
    ``LLMModelRefusalError`` *before* any upstream call is made;
  - TTL expiry re-opens the real call path;
  - ``clear_model_refusals`` resets everything.
"""

from __future__ import annotations

from collections.abc import Iterator

import pytest
from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import AIMessage

from buggy.llm.factory import (
    LLMModelRefusalError,
    _check_empty_response,
    _ProxiedChatOpenAI,
    clear_model_refusals,
    mark_model_refusal,
    model_is_refusing,
    note_model_refusal,
)


def _bare_empty() -> AIMessage:
    """Empty response with NO refusal signal — ambiguous (blip or refusal)."""
    return AIMessage(content="", response_metadata={"finish_reason": "end_turn"})


@pytest.fixture(autouse=True)
def _clean_refusal_registry() -> Iterator[None]:
    """Isolate the module-level breaker state between tests."""
    clear_model_refusals()
    yield
    clear_model_refusals()


def _proxied(model: str = "auth/claude-sonnet-5-5") -> _ProxiedChatOpenAI:
    from pydantic import SecretStr

    return _ProxiedChatOpenAI(
        model=model,
        base_url="http://localhost:4000",
        api_key=SecretStr("test-key"),
    )


def _empty_refusal() -> AIMessage:
    return AIMessage(content="", response_metadata={"finish_reason": "content_filter"})


class TestCheckEmptyResponse:
    def test_content_filter_raises_refusal_error(self) -> None:
        with pytest.raises(LLMModelRefusalError, match="content_filter"):
            _check_empty_response(_empty_refusal(), "auth/claude-fable-5")

    def test_generic_empty_raises_refusal_error(self) -> None:
        msg = AIMessage(content="", response_metadata={"finish_reason": "end_turn"})
        with pytest.raises(LLMModelRefusalError, match="empty response"):
            _check_empty_response(msg, "auth/claude-sonnet-5-5")

    def test_refusal_error_is_runtime_error_subclass(self) -> None:
        assert issubclass(LLMModelRefusalError, RuntimeError)

    def test_content_response_passes(self) -> None:
        _check_empty_response(AIMessage(content="operational"), "any/model")

    def test_tool_call_response_passes(self) -> None:
        msg = AIMessage(
            content="",
            tool_calls=[{"name": "bash", "args": {"cmd": "id"}, "id": "call_1"}],
        )
        _check_empty_response(msg, "any/model")

    def test_non_ai_message_is_ignored(self) -> None:
        _check_empty_response(object(), "any/model")


class TestRefusalRegistry:
    def test_mark_opens_circuit(self) -> None:
        assert not model_is_refusing("auth/claude-fable-5")
        mark_model_refusal("auth/claude-fable-5")
        assert model_is_refusing("auth/claude-fable-5")

    def test_other_models_unaffected(self) -> None:
        mark_model_refusal("auth/claude-fable-5")
        assert not model_is_refusing("auth/claude-sonnet-5-5")

    def test_ttl_expiry_reopens_call_path(self) -> None:
        from buggy.llm.factory import _REFUSING_MODELS

        mark_model_refusal("auth/claude-fable-5")
        # Back-date the entry past the TTL — equivalent to waiting it out.
        _REFUSING_MODELS["auth/claude-fable-5"] -= 10_000.0
        assert not model_is_refusing("auth/claude-fable-5")
        # The expired entry was evicted — a second check does not resurrect it.
        assert not model_is_refusing("auth/claude-fable-5")

    def test_clear_resets(self) -> None:
        mark_model_refusal("auth/claude-fable-5")
        clear_model_refusals()
        assert not model_is_refusing("auth/claude-fable-5")


class TestProxiedInvokeCircuit:
    def test_open_circuit_fast_fails_without_upstream_call(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        proxied = _proxied()
        mark_model_refusal(proxied.model_name)

        def boom(self, *args, **kwargs):  # pragma: no cover - must not run
            raise AssertionError("upstream invoke must not be reached while circuit open")

        monkeypatch.setattr(BaseChatModel, "invoke", boom)
        with pytest.raises(LLMModelRefusalError, match="circuit open"):
            proxied.invoke([("human", "probe the target")])

    def test_refusal_marks_circuit_and_reraises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        proxied = _proxied()

        def fake_invoke(self, *args, **kwargs):
            return _empty_refusal()

        monkeypatch.setattr(BaseChatModel, "invoke", fake_invoke)

        with pytest.raises(LLMModelRefusalError, match="content_filter"):
            proxied.invoke([("human", "probe the target")])
        assert model_is_refusing(proxied.model_name)

    def test_open_circuit_stops_next_call_immediately(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        proxied = _proxied()
        mark_model_refusal(proxied.model_name)
        with pytest.raises(LLMModelRefusalError, match="circuit open"):
            proxied.invoke([("human", "probe")])
        # Still open — the fast-fail raised, not a marked-then-cleared cycle.
        assert model_is_refusing(proxied.model_name)

    async def test_ainvoke_fast_fails_while_open(self) -> None:
        proxied = _proxied()
        mark_model_refusal(proxied.model_name)
        with pytest.raises(LLMModelRefusalError, match="circuit open"):
            await proxied.ainvoke([("human", "probe")])

    async def test_ainvoke_marks_on_refusal(self, monkeypatch: pytest.MonkeyPatch) -> None:
        proxied = _proxied()

        async def fake_ainvoke(self, *args, **kwargs):
            return _empty_refusal()

        monkeypatch.setattr(BaseChatModel, "ainvoke", fake_ainvoke)

        with pytest.raises(LLMModelRefusalError, match="content_filter"):
            await proxied.ainvoke([("human", "probe the target")])
        assert model_is_refusing(proxied.model_name)

    def test_content_response_unaffected(self, monkeypatch: pytest.MonkeyPatch) -> None:
        proxied = _proxied()
        ok = AIMessage(content="GROK-OK")

        def fake_invoke(self, *args, **kwargs):
            return ok

        monkeypatch.setattr(BaseChatModel, "invoke", fake_invoke)
        result = proxied.invoke([("human", "probe")])
        assert result is ok
        assert not model_is_refusing(proxied.model_name)


class TestStreakCorroboration:
    """Ambiguous empties need consecutive corroboration; definitive
    signals (content_filter) open the circuit on the first occurrence."""

    def test_single_bare_empty_does_not_open_circuit(self, monkeypatch: pytest.MonkeyPatch) -> None:
        proxied = _proxied()
        monkeypatch.setattr(BaseChatModel, "invoke", lambda self, *a, **k: _bare_empty())
        with pytest.raises(LLMModelRefusalError, match="empty response"):
            proxied.invoke([("human", "probe")])
        # The call still failed over — but one blip must not blacklist.
        assert not model_is_refusing(proxied.model_name)

    def test_consecutive_bare_empties_open_circuit(self, monkeypatch: pytest.MonkeyPatch) -> None:
        proxied = _proxied()
        monkeypatch.setattr(BaseChatModel, "invoke", lambda self, *a, **k: _bare_empty())
        for _ in range(2):
            with pytest.raises(LLMModelRefusalError):
                proxied.invoke([("human", "probe")])
        assert model_is_refusing(proxied.model_name)

    def test_success_between_empties_resets_streak(self, monkeypatch: pytest.MonkeyPatch) -> None:
        proxied = _proxied()
        responses = iter([_bare_empty(), AIMessage(content="ok"), _bare_empty()])
        monkeypatch.setattr(BaseChatModel, "invoke", lambda self, *a, **k: next(responses))
        with pytest.raises(LLMModelRefusalError):
            proxied.invoke([("human", "probe")])
        proxied.invoke([("human", "probe")])  # success — streak cleared
        with pytest.raises(LLMModelRefusalError):
            proxied.invoke([("human", "probe")])
        assert not model_is_refusing(proxied.model_name)

    def test_content_filter_is_definitive(self) -> None:
        assert note_model_refusal("m", definitive=True) is True
        assert model_is_refusing("m")

    def test_note_model_refusal_streak_threshold(self) -> None:
        assert note_model_refusal("m2") is False
        assert not model_is_refusing("m2")
        assert note_model_refusal("m2") is True
        assert model_is_refusing("m2")

    def test_clear_resets_streaks_too(self) -> None:
        note_model_refusal("m3")
        clear_model_refusals()
        # After clear, the streak restarts — one empty is again not enough.
        assert note_model_refusal("m3") is False
