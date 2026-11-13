"""Capture internal argv commands without exposing a shell interface."""

from __future__ import annotations

import os
import selectors
import signal
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, cast


class BoundedProcessInputError(ValueError):
    """The internal command arguments do not satisfy the execution bounds."""


@dataclass(frozen=True, slots=True)
class CommandResult:
    status: Literal["completed", "timeout", "output_limit", "unavailable", "error"]
    exit_code: int | None
    stdout: bytes
    stderr: bytes


MAX_TIMEOUT_SECONDS = 300
MAX_OUTPUT_BYTES = 2 * 1024 * 1024
_READ_BYTES = 64 * 1024
_REAP_TIMEOUT = 1.0


def _validate(argv: list[str], cwd: str | Path, timeout: float, limit: int) -> None:
    if (
        type(argv) is not list
        or not argv
        or any(type(argument) is not str or "\x00" in argument for argument in argv)
        or not argv[0]
        or not isinstance(cwd, (str, Path))
        or not str(cwd)
        or "\x00" in str(cwd)
        or type(timeout) not in (int, float)
        or not 0 < timeout <= MAX_TIMEOUT_SECONDS
        or type(limit) is not int
        or not 0 < limit <= MAX_OUTPUT_BYTES
    ):
        raise BoundedProcessInputError("Invalid bounded command")


def _capture(command: subprocess.Popen[bytes], deadline: float, limit: int) -> CommandResult:
    stdout, stderr = bytearray(), bytearray()
    status: Literal["completed", "timeout", "output_limit"] = "completed"
    with selectors.DefaultSelector() as selector:
        for stream, buffer in ((command.stdout, stdout), (command.stderr, stderr)):
            if stream is not None:
                os.set_blocking(stream.fileno(), False)
                selector.register(stream, selectors.EVENT_READ, buffer)
        while selector.get_map() and status == "completed":
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                status = "timeout"
                break
            for key, events in selector.select(remaining):
                budget = limit - len(stdout) - len(stderr)
                chunk = os.read(key.fd, min(_READ_BYTES, budget + 1))
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                cast(bytearray, key.data).extend(chunk[:budget])
                if len(chunk) > budget:
                    status = "output_limit"
                    break
    exit_code = None
    if status == "completed":
        try:
            exit_code = command.wait(timeout=max(0, deadline - time.monotonic()))
        except subprocess.TimeoutExpired:
            status = "timeout"
    return CommandResult(status, exit_code, bytes(stdout), bytes(stderr))


def _cleanup(command: subprocess.Popen[bytes]) -> bool:
    cleaned = True
    try:
        try:
            os.killpg(command.pid, signal.SIGKILL)
        except ProcessLookupError:
            command.poll()
        except OSError:
            cleaned = False
            command.kill()
        command.wait(timeout=_REAP_TIMEOUT)
    except (OSError, subprocess.TimeoutExpired):
        cleaned = False
    finally:
        for stream in (command.stdout, command.stderr):
            if stream is not None:
                stream.close()
    return cleaned


def run_bounded(
    argv: list[str], *, cwd: str | Path, timeout: float, max_output_bytes: int = MAX_OUTPUT_BYTES
) -> CommandResult:
    """Run trusted internal argv, not an OS sandbox; descendants must not detach.

    Limits are 300 seconds and 2 MiB combined output. Forced termination has
    no exit code; cleanup can take up to one additional second. Returned
    bytes are untrusted process output, never exception diagnostics.
    """
    _validate(argv, cwd, timeout, max_output_bytes)
    if os.name != "posix" or not callable(getattr(os, "killpg", None)):
        return CommandResult("error", None, b"", b"")
    deadline = time.monotonic() + timeout
    try:
        command = subprocess.Popen(
            argv,
            cwd=cwd,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            close_fds=True,
            bufsize=0,
            start_new_session=True,
            env={"PATH": os.defpath, "LANG": "C", "LC_ALL": "C"},
        )
    except FileNotFoundError as exc:
        return CommandResult("unavailable" if exc.filename == argv[0] else "error", None, b"", b"")
    except (OSError, ValueError, subprocess.SubprocessError):
        return CommandResult("error", None, b"", b"")
    try:
        captured = _capture(command, deadline, max_output_bytes)
    except (OSError, ValueError):
        captured = CommandResult("error", None, b"", b"")
    finally:
        cleaned = _cleanup(command)
    return captured if cleaned else CommandResult("error", None, b"", b"")
