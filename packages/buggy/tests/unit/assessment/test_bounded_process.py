"""Exercise the internal runner with local synthetic Python processes only."""

from __future__ import annotations

import os
import selectors
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

import pytest

from buggy.sandbox_kernel import bounded_process
from buggy.sandbox_kernel.bounded_process import CommandResult, run_bounded


def test_preserves_raw_streams_exit_code_and_literal_arguments(tmp_path: Path) -> None:
    command = run_bounded(
        [
            sys.executable,
            "-B",
            "-c",
            "import os, sys; os.write(1, sys.argv[1].encode()); os.write(2, b'\\xff'); sys.exit(7)",
            "$(do-not-execute); literal",
        ],
        cwd=tmp_path,
        timeout=2,
    )
    assert command == CommandResult("completed", 7, b"$(do-not-execute); literal", b"\xff")


@pytest.mark.parametrize("streams", [(1,), (2,), (1, 2)])
def test_bounds_combined_output_while_capturing(tmp_path: Path, streams: tuple[int, ...]) -> None:
    size = 65536 if len(streams) == 1 else 600
    command = run_bounded(
        [
            sys.executable,
            "-B",
            "-c",
            f"import os; [os.write(fd, b'x' * {size}) for fd in {streams!r}]",
        ],
        cwd=tmp_path,
        timeout=2,
        max_output_bytes=1024,
    )
    assert command.status == "output_limit"
    assert len(command.stdout) + len(command.stderr) == 1024


def test_deadline_applies_after_both_output_streams_close(tmp_path: Path) -> None:
    started = time.monotonic()
    command = run_bounded(
        [sys.executable, "-B", "-c", "import os,time; os.close(1); os.close(2); time.sleep(2)"],
        cwd=tmp_path,
        timeout=0.15,
    )
    assert command == CommandResult("timeout", None, b"", b"")
    assert time.monotonic() - started < 1.5


@pytest.mark.parametrize("mode", ["timeout", "output_limit", "leader_exit"])
def test_stops_children_even_after_the_group_leader_exits(tmp_path: Path, mode: str) -> None:
    marker = tmp_path / "child-survived"
    child = f"import pathlib,time; time.sleep(0.6); pathlib.Path({str(marker)!r}).touch()"
    parent = (
        "import os,subprocess,sys,time; "
        f"subprocess.Popen([sys.executable, '-B', '-c', {child!r}]); "
        + ("os.write(2, b'x' * 4096); " if mode == "output_limit" else "")
        + ("sys.exit(0)" if mode == "leader_exit" else "time.sleep(2)")
    )
    command = run_bounded(
        [sys.executable, "-B", "-c", parent], cwd=tmp_path, timeout=0.2, max_output_bytes=128
    )
    time.sleep(0.8)
    assert command.status == ("output_limit" if mode == "output_limit" else "timeout")
    assert not marker.exists(), "A child survived the runner's process-group cleanup"


def test_disables_stdin_and_inherited_secrets_and_honors_cwd(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    for name in ("ASSESSMENT_TEST_SECRET", "PYTHONPATH", "HTTP_PROXY", "BASH_ENV"):
        monkeypatch.setenv(name, "fixture-secret")
    command = run_bounded(
        [
            sys.executable,
            "-B",
            "-c",
            (
                "import os,sys; "
                "print(any(k in os.environ for k in "
                "('ASSESSMENT_TEST_SECRET','PYTHONPATH','HTTP_PROXY','BASH_ENV','HOME'))); "
                "print(sys.stdin.read() == ''); print(os.getcwd() == sys.argv[1])"
            ),
            str(tmp_path),
        ],
        cwd=str(tmp_path),
        timeout=2,
    )
    assert command == CommandResult("completed", 0, b"False\nTrue\nTrue\n", b"")


@pytest.mark.parametrize(
    "overrides",
    [
        {"argv": []},
        {"argv": "fixture-secret"},
        {"argv": ("fixture-secret",)},
        {"argv": [""]},
        {"argv": [sys.executable, 1]},
        {"argv": [sys.executable, "fixture-secret\x00"]},
        {"timeout": 0},
        {"timeout": -1},
        {"timeout": float("nan")},
        {"timeout": float("inf")},
        {"timeout": True},
        {"timeout": "fixture-secret"},
        {"timeout": 301},
        {"max_output_bytes": 0},
        {"max_output_bytes": -1},
        {"max_output_bytes": 1.5},
        {"max_output_bytes": True},
        {"max_output_bytes": 2 * 1024 * 1024 + 1},
        {"cwd": None},
        {"cwd": []},
        {"cwd": ""},
        {"cwd": "fixture-secret\x00"},
    ],
)
def test_rejects_unsafe_types_and_limits_without_reflecting_input(
    tmp_path: Path, overrides: dict[str, Any]
) -> None:
    arguments = {"argv": [sys.executable, "-B", "-c", "pass"], "cwd": tmp_path, "timeout": 2}
    arguments.update(overrides)
    with pytest.raises(bounded_process.BoundedProcessInputError, match="^Invalid bounded command$"):
        run_bounded(**arguments)


@pytest.mark.parametrize("failure", ["missing_binary", "invalid_cwd", "not_executable"])
def test_launch_failures_do_not_reflect_paths_or_exceptions(tmp_path: Path, failure: str) -> None:
    private_path = tmp_path / "fixture-secret"
    argv, cwd = [sys.executable, "-B", "-c", "pass"], tmp_path
    if failure == "invalid_cwd":
        cwd = private_path
    else:
        argv = [str(private_path)]
        if failure == "not_executable":
            private_path.write_text("not an executable", encoding="utf-8")
    command = run_bounded(argv, cwd=cwd, timeout=2)
    assert command == CommandResult(
        "unavailable" if failure == "missing_binary" else "error", None, b"", b""
    )


def test_unsupported_platform_does_not_launch_a_process(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def forbidden_launch(*args: Any, **kwargs: Any) -> None:
        pytest.fail("Unsupported platforms must not launch a child")

    with monkeypatch.context() as unsupported:
        unsupported.setattr(os, "name", "nt")
        unsupported.setattr(subprocess, "Popen", forbidden_launch)
        command = run_bounded([sys.executable, "-B", "-c", "pass"], cwd=tmp_path, timeout=2)
    assert command == CommandResult("error", None, b"", b"")


@pytest.mark.parametrize("failure", ["capture", "cleanup"])
def test_runtime_errors_are_sanitized_and_do_not_leak_descriptors(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure: str
) -> None:
    def broken_operation(*args: Any, **kwargs: Any) -> Any:
        raise OSError("fixture-secret /private/arbitrary/path")

    if failure == "capture":
        monkeypatch.setattr(selectors.DefaultSelector, "select", broken_operation)
    else:
        monkeypatch.setattr(os, "killpg", broken_operation)
    descriptor_count = len(os.listdir("/dev/fd"))
    for attempt in range(3):
        command = run_bounded(
            [sys.executable, "-B", "-c", "import time; time.sleep(0.2)"], cwd=tmp_path, timeout=0.05
        )
        assert command == CommandResult("error", None, b"", b"")
    assert len(os.listdir("/dev/fd")) == descriptor_count
