"""Canonical environment-variable parsing helpers.

Boolean and numeric env flags were historically re-rolled at every call
site — ``os.environ.get(...).strip().lower() in {"1", "true", "yes"}``
with subtly different truthy/falsy sets and default behaviour per
copy, so the same value could mean different things in different
subsystems. Everything funnelled through here shares one contract:

- **truthy**: ``1`` ``true`` ``yes`` ``on``
- **falsy**: ``0`` ``false`` ``no`` ``off``
- unset, blank, or unrecognised values → the caller's ``default``

Safety direction: unrecognised values resolve to ``default``, not to
"truthy", so a misspelt flag can never silently enable a sensitive mode
(e.g. ``BENCHMARK_MODE=tru`` is OFF, not ON).
"""

from __future__ import annotations

import os

TRUTHY_ENV_VALUES = frozenset({"1", "true", "yes", "on"})
FALSY_ENV_VALUES = frozenset({"0", "false", "no", "off"})


def env_truthy(value: str | None, *, default: bool = False) -> bool:
    """Evaluate a raw env *value* against the canonical sets."""
    if value is None:
        return default
    normalized = value.strip().lower()
    if normalized in TRUTHY_ENV_VALUES:
        return True
    if normalized in FALSY_ENV_VALUES:
        return False
    return default  # blank or unrecognised


def env_flag(name: str, *, default: bool = False) -> bool:
    """Evaluate ``os.environ[name]`` against the canonical sets.

    Unset or blank resolves to ``default`` — for an opt-in flag pass
    ``default=False``, for an opt-out (disable) flag still pass
    ``default=False`` and read the result as "the disable flag is set".
    """
    return env_truthy(os.environ.get(name), default=default)


def env_float(name: str, default: float, *, positive: bool = False) -> float:
    """Parse ``os.environ[name]`` as float, falling back to ``default``.

    With ``positive=True`` non-positive values also fall back — the
    poll-interval/timeout convention where <= 0 is meaningless.
    """
    raw = os.environ.get(name)
    if raw is None or not raw.strip():
        return default
    try:
        value = float(raw)
    except ValueError:
        return default
    if positive and value <= 0:
        return default
    return value


__all__ = [
    "FALSY_ENV_VALUES",
    "TRUTHY_ENV_VALUES",
    "env_flag",
    "env_float",
    "env_truthy",
]
