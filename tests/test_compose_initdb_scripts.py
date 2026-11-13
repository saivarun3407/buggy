"""Postgres init scripts must be executable.

The postgres image's entrypoint runs ``*.sh`` files in
``/docker-entrypoint-initdb.d`` directly when ``[ -x ]`` is true and
sources them otherwise. Docker Desktop's macOS file sharing reports
non-executable bind-mounted files as executable to ``[ -x ]`` while
``execve`` still refuses them, so a 0644 script aborts initdb with
``bad interpreter: Permission denied`` and postgres never turns healthy.
"""

from __future__ import annotations

import stat
from pathlib import Path

import pytest

INITDB_DIR = Path(__file__).resolve().parent.parent / "containers" / "postgres-init"


@pytest.mark.parametrize("script", sorted(INITDB_DIR.glob("*.sh")), ids=lambda p: p.name)
def test_initdb_shell_script_is_executable(script: Path) -> None:
    assert script.stat().st_mode & stat.S_IXUSR, (
        f"{script.relative_to(INITDB_DIR.parent.parent)} must be committed with mode 100755 "
        "(git update-index --chmod=+x)"
    )
