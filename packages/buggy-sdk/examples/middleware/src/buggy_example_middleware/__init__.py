"""Custom middleware contributed to Buggy."""

from __future__ import annotations

from buggy_sdk import MiddlewareProtocol, MiddlewareSlot


class HelloMiddleware:
    """Minimal MiddlewareProtocol-compliant middleware."""

    name = "buggy_example_middleware"
    slot: MiddlewareSlot | str = MiddlewareSlot.SKILLS
    priority = 150

    def wrap_model_call(self, state: object, runtime: object, config: object) -> object:
        return state


def get_middleware(role: str | None = None, **_: object) -> list[MiddlewareProtocol]:
    """Plugin factory called by the framework's middleware loader."""
    del role
    return [HelloMiddleware()]
