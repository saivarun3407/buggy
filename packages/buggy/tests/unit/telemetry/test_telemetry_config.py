"""Buggy: telemetry removed — config always resolves to DISABLED.

These tests lock in the fork invariant: no environment variable, persisted
mode, or hand-built config can turn telemetry on. ``resolve_mode`` is always
``OFF``, ``resolve_config`` is always disabled, and ``enabled`` is always
``False`` even for a config that names a mode and an endpoint.
"""

from __future__ import annotations

from buggy.telemetry.config import (
    TelemetryConfig,
    TelemetryMode,
    install_id,
    resolve_config,
    resolve_mode,
)


def test_resolve_mode_is_always_off_regardless_of_env() -> None:
    # Every value that used to enable sending now resolves to OFF.
    assert resolve_mode({}) is TelemetryMode.OFF
    assert resolve_mode({"BUGGY_TELEMETRY": "basic"}) is TelemetryMode.OFF
    assert resolve_mode({"BUGGY_TELEMETRY": "research"}) is TelemetryMode.OFF
    assert resolve_mode({"BUGGY_TELEMETRY": "off"}) is TelemetryMode.OFF


def test_resolve_config_is_always_disabled() -> None:
    # Even the full "enable" combination (mode + endpoint) yields a disabled
    # config with no endpoint — nothing can send.
    cfg = resolve_config(
        {
            "BUGGY_TELEMETRY": "research",
            "BUGGY_TELEMETRY_ENDPOINT": "https://gw.example",
        }
    )
    assert cfg.mode is TelemetryMode.OFF
    assert cfg.endpoint is None
    assert cfg.enabled is False


def test_enabled_is_hard_false_even_for_handbuilt_config() -> None:
    # A config constructed by hand with a mode AND an endpoint still reports
    # disabled — the property is the gate the sink uses to build an exporter.
    cfg = TelemetryConfig(
        mode=TelemetryMode.RESEARCH,
        endpoint="https://gw.example",
        install_id="1e9a73a6-c8bd-4e1e-be02-78f4b11de4e1",
        version="1.1.13",
        os_name="linux",
    )
    assert cfg.enabled is False


def test_off_config_mints_no_install_id_on_disk(tmp_path) -> None:
    # Resolution is side-effect-free: the all-zero sentinel id, nothing written.
    cfg = resolve_config({"BUGGY_HOME": str(tmp_path)})
    assert cfg.install_id == "00000000-0000-0000-0000-000000000000"
    assert not (tmp_path / "telemetry").exists()


def test_install_id_helper_is_local_only(tmp_path) -> None:
    # The marker helper is retained for import-compat; it only ever touches a
    # local file and cannot enable sending.
    env = {"BUGGY_HOME": str(tmp_path)}
    first = install_id(env)
    assert first == install_id(env)  # stable, local
    assert (tmp_path / "telemetry" / "install_id").read_text().strip() == first
