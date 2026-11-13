"""``buggy-cli auth`` — headless provider/auth introspection.

The interactive ``buggy onboard`` wizard (Go launcher) is the place to
*configure* credentials. This command is the headless complement: it reports
what is actually wired — API keys, subscription (OAuth) logins, local
endpoints, and agent-level subscriptions (Devin CLI delegation) — exactly
as the runtime factory will resolve them, for the SDK, CI preflights, and
debugging "why is my subscription not being used?".

Subcommands:
  status   Print every provider's auth state (default). ``--json`` for machines.
  doctor   Same report, but exit non-zero when no method is usable — drop it
           into CI before a scan so a misconfigured run fails fast and loud.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from buggy.llm.factory import AuthInventory

EXIT_OK = 0
EXIT_CONFIG = 2

_KIND_ORDER = ("subscription", "api", "local")
_KIND_HEADING = {
    "subscription": "Subscriptions (OAuth)",
    "api": "API keys",
    "local": "Local / custom endpoints",
}
_AGENT_HEADING = "Agent subscriptions (delegation)"


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="buggy-cli auth",
        description="Report provider/auth configuration (API keys + subscriptions + local).",
    )
    p.add_argument(
        "command",
        nargs="?",
        choices=("status", "doctor"),
        default="status",
        help="status (default) prints the report; doctor also exits non-zero when nothing is usable.",
    )
    p.add_argument("--json", action="store_true", help="Emit machine-readable JSON.")
    p.add_argument(
        "--env-file",
        default=None,
        help="Load this .env before inspecting (default: $BUGGY_HOME/.env or ~/.buggy/.env).",
    )
    p.add_argument(
        "--no-env-file",
        action="store_true",
        help="Inspect only the current process environment; skip .env auto-loading.",
    )
    return p


def _default_env_path() -> Path | None:
    candidates: list[Path] = []
    home = os.environ.get("BUGGY_HOME", "").strip()
    if home:
        candidates.append(Path(home) / ".env")
    candidates.append(Path.home() / ".buggy" / ".env")
    return next((c for c in candidates if c.exists()), None)


def _load_env_file(path: Path) -> int:
    """Set unset keys from a KEY=VALUE .env file. Never overrides the live env."""
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        # Missing, unreadable, or non-UTF-8 / corrupt .env: degrade to "nothing
        # loaded" rather than letting a raw decode traceback escape the CLI.
        return 0
    loaded = 0
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export ") :].strip()
        key, sep, value = line.partition("=")
        if not sep:
            continue
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key and key not in os.environ:
            os.environ[key] = value
            loaded += 1
    return loaded


def _glyph(configured: bool, active: bool) -> str:
    if active:
        return "✓ active"
    if configured:
        return "✓ idle  "
    return "·       "


def _render_text(inv: AuthInventory) -> str:
    lines: list[str] = ["Buggy auth status", "=" * 22, ""]
    for kind in _KIND_ORDER:
        group = [s for s in inv.statuses if s.kind == kind]
        if not group:
            continue
        lines.append(_KIND_HEADING[kind])
        for s in group:
            lines.append(f"  {_glyph(s.configured, s.active)}  {s.label}")
            lines.append(f"             {s.detail}")
        lines.append("")

    if inv.agent_subscriptions:
        lines.append(_AGENT_HEADING)
        for s in inv.agent_subscriptions:
            mark = "✓ avail." if s.configured else "·        "
            lines.append(f"  {mark}  {s.label}")
            lines.append(f"             {s.detail}")
        lines.append("")

    if inv.resolved_chain:
        lines.append("Resolved fallback chain (priority order):")
        lines.append("  " + " → ".join(m.value for m in inv.resolved_chain))
    else:
        lines.append("⚠ No usable credential detected.")
        lines.append("  Run `buggy onboard` (or set an API key / subscription) — every")
        lines.append("  model call will 401 until at least one method is configured.")
        if any(s.configured for s in inv.agent_subscriptions):
            lines.append("  Agent delegation IS available (see above) — the orchestrator can")
            lines.append("  delegate subtasks via devin_delegate, but the agents themselves")
            lines.append("  still need a model method to run.")
    lines.append("")

    idle = inv.configured_but_idle
    if idle:
        lines.append("⚠ Configured but NOT routed (add to BUGGY_AUTH_PRIORITY to use):")
        for s in idle:
            lines.append(f"  - {s.label}  [{s.method.value}]")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def _render_json(inv: AuthInventory) -> str:
    payload = {
        "any_active": inv.any_active,
        "priority_explicit": inv.priority_explicit,
        "resolved_chain": [m.value for m in inv.resolved_chain],
        "configured_but_idle": [s.method.value for s in inv.configured_but_idle],
        "agent_subscriptions": [
            {
                "name": s.name,
                "label": s.label,
                "env_var": s.env_var,
                "configured": s.configured,
                "detail": s.detail,
            }
            for s in inv.agent_subscriptions
        ],
        "methods": [
            {
                "method": s.method.value,
                "kind": s.kind,
                "label": s.label,
                "env_var": s.env_var,
                "configured": s.configured,
                "in_priority": s.in_priority,
                "active": s.active,
                "detail": s.detail,
            }
            for s in inv.statuses
        ],
    }
    return json.dumps(payload, indent=2, ensure_ascii=False)


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)

    if not args.no_env_file:
        path = Path(args.env_file) if args.env_file else _default_env_path()
        if args.env_file and (path is None or not path.exists()):
            print(f"error: env file not found: {args.env_file}", file=sys.stderr)
            return EXIT_CONFIG
        if path is not None and path.exists():
            _load_env_file(path)

    # Imported lazily: pulls in the LLM stack, which is overkill for --help.
    # Both the import and inventory probe touch the filesystem and parse
    # credential files; a failure there is a misconfiguration, not a crash —
    # report it actionably instead of dumping a traceback at the operator.
    try:
        from buggy.llm.factory import auth_inventory  # noqa: PLC0415

        inv = auth_inventory()
    except Exception as exc:  # noqa: BLE001 — top-level CLI guard; report, don't crash
        print(f"error: could not inspect auth configuration: {exc}", file=sys.stderr)
        return EXIT_CONFIG
    print(_render_json(inv) if args.json else _render_text(inv))

    if args.command == "doctor":
        return EXIT_OK if inv.any_active else EXIT_CONFIG
    return EXIT_OK
