"""Telemetry consent + configuration resolution.

BUGGY FORK — TELEMETRY PERMANENTLY REMOVED. This module keeps its public API
(``TelemetryMode``, ``TelemetryConfig``, ``resolve_mode``, ``resolve_config`` …)
so the ~hundreds of modules that import it keep working, but every resolver is
hard-wired to the disabled state:

* :func:`resolve_mode` always returns ``OFF`` and ignores every environment
  variable (``BUGGY_TELEMETRY``, ``DO_NOT_TRACK``, …).
* :func:`resolve_config` always returns a config with ``mode=OFF`` and
  ``endpoint=None``; no env var can supply an endpoint.
* :attr:`TelemetryConfig.enabled` always returns ``False``, so a
  ``TelemetrySink`` never constructs an exporter and nothing is ever sent.

The marker/persistence helpers (:func:`install_id`, :func:`set_opted_out`,
:func:`persisted_mode`, …) are retained for import compatibility and only ever
touch local files under ``$BUGGY_HOME`` — they cannot enable sending.
"""

from __future__ import annotations

import os
import platform
import uuid
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

from buggy_core.utils.env import env_truthy


class TelemetryMode(str, Enum):
    """How much the user consented to share.

    ``research`` adds identifier-masked reasoning/trajectory capture on top of
    the anonymous structural ``basic`` tier (see ``telemetry.trajectory``).
    """

    OFF = "off"
    BASIC = "basic"  # anonymous structural artifacts only
    RESEARCH = "research"  # basic + identifier-masked reasoning/trajectory corpus


def _truthy(raw: str | None) -> bool:
    return env_truthy(raw)


def resolve_mode(env: dict[str, str] | None = None) -> TelemetryMode:
    """Buggy: telemetry removed — always OFF, every env var ignored.

    ``env`` is accepted for signature compatibility but never read.
    """
    return TelemetryMode.OFF


def _home(env: dict[str, str]) -> Path:
    raw = env.get("BUGGY_HOME") or "~/.buggy"
    return Path(raw).expanduser()


def _opt_out_marker(env: dict[str, str]) -> Path:
    return _home(env) / "telemetry" / "opt_out"


def is_opted_out(env: dict[str, str] | None = None) -> bool:
    """True when a persistent opt-out marker exists (``telemetry off``)."""
    e = env if env is not None else dict(os.environ)
    try:
        return _opt_out_marker(e).exists()
    except OSError:
        return False


def set_opted_out(opted_out: bool, env: dict[str, str] | None = None) -> None:
    """Create/remove the persistent opt-out marker."""
    e = env if env is not None else dict(os.environ)
    marker = _opt_out_marker(e)
    if opted_out:
        marker.parent.mkdir(parents=True, exist_ok=True)
        marker.write_text("opted out\n", encoding="utf-8")
    elif marker.exists():
        marker.unlink()


def _mode_file(env: dict[str, str]) -> Path:
    return _home(env) / "telemetry" / "mode"


def persisted_mode(env: dict[str, str] | None = None) -> TelemetryMode | None:
    """Read the persisted opt-in mode (``telemetry enable …``), if any."""
    e = env if env is not None else dict(os.environ)
    try:
        raw = _mode_file(e).read_text(encoding="utf-8").strip().lower()
    except OSError:
        return None
    try:
        return TelemetryMode(raw)
    except ValueError:
        return None


def set_persisted_mode(mode: TelemetryMode, env: dict[str, str] | None = None) -> None:
    """Persist an explicit consent choice from ``telemetry enable``/``off``.

    ``OFF`` writes the opt-out marker (and clears any mode); ``basic``/
    ``extended`` write the mode and clear the opt-out marker.
    """
    e = env if env is not None else dict(os.environ)
    mfile = _mode_file(e)
    if mode is TelemetryMode.OFF:
        set_opted_out(True, e)
        if mfile.exists():
            mfile.unlink()
        return
    set_opted_out(False, e)
    mfile.parent.mkdir(parents=True, exist_ok=True)
    mfile.write_text(mode.value, encoding="utf-8")


def install_id(env: dict[str, str] | None = None) -> str:
    """Return the persistent anonymous install id, minting one on first use.

    A random UUID (never machine/IP derived) stored under
    ``$BUGGY_HOME/telemetry/install_id``. If the path is unwritable we fall
    back to an ephemeral id so telemetry degrades rather than crashes.
    """
    e = env if env is not None else dict(os.environ)
    path = _home(e) / "telemetry" / "install_id"
    try:
        if path.exists():
            existing = path.read_text(encoding="utf-8").strip()
            if existing:
                return existing
        new_id = str(uuid.uuid4())
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(new_id, encoding="utf-8")
        return new_id
    except OSError:
        return str(uuid.uuid4())


@dataclass(frozen=True, slots=True)
class TelemetryConfig:
    """Fully resolved telemetry settings for a process."""

    mode: TelemetryMode
    endpoint: str | None
    install_id: str
    version: str
    os_name: str
    # Non-identifying runtime dims (the gateway already forwards these). Defaults
    # keep existing constructors / the disabled no-op sink working unchanged.
    arch: str = ""
    py_version: str = ""

    @property
    def enabled(self) -> bool:
        """Buggy: telemetry removed — never enabled, whatever the fields say.

        Hard-returns ``False`` so even a hand-built config with a mode and an
        endpoint cannot make a :class:`TelemetrySink` construct an exporter.
        """
        return False


def resolve_config(env: dict[str, str] | None = None) -> TelemetryConfig:
    """Buggy: telemetry removed — always a fully-disabled config.

    No environment variable can supply a mode or an endpoint, so the process
    telemetry sink is always the shared disabled no-op. ``env`` is accepted for
    signature compatibility but never read; the id is the all-zero sentinel so
    nothing is minted on disk.
    """
    sys_map = {"Linux": "linux", "Darwin": "darwin", "Windows": "windows"}
    return TelemetryConfig(
        mode=TelemetryMode.OFF,
        endpoint=None,
        install_id="00000000-0000-0000-0000-000000000000",
        version=_detect_version(),
        os_name=sys_map.get(platform.system(), "linux"),
    )


def _arch() -> str:
    """CPU architecture as a gateway-safe slug (e.g. ``x86_64``, ``arm64``).

    Returned verbatim only if it matches the gateway's ``arch`` slug pattern;
    otherwise empty so a surprising ``platform.machine()`` value can never fail
    the gateway's strict schema and drop the whole batch.
    """
    import re

    raw = (platform.machine() or "").lower()
    return raw if re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,63}", raw) else ""


def _detect_version() -> str:
    try:
        from importlib.metadata import version

        return version("buggy")
    except Exception:  # noqa: BLE001 — version is best-effort, never fatal
        return "0.0.0"
