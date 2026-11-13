"""``python -m buggy.skill_audit`` entrypoint."""

from __future__ import annotations

import sys

from buggy.skill_audit.cli import main

if __name__ == "__main__":
    sys.exit(int(main()))
