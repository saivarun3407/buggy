"""``buggy-cli hunt`` — the simplest way to start a hunt.

    buggy-cli hunt example.com
    buggy-cli hunt api.example.com app.example.com --include-subdomains
    buggy-cli hunt https://example.com --scope "*.example.com" \
        --instruction "focus on auth and access control"

A deliberately small, friendly front end over ``buggy-cli engage``:

  - targets are positional — no ``--target`` flag to remember;
  - scope defaults to exactly the targets (never auto-widened);
  - ``--include-subdomains`` is the single explicit opt-in that widens each
    target host to ``<host>`` + ``*.<host>`` — useful for bug-bounty assets
    where subdomains are in scope, but you have to ask for it;
  - ``--scope`` / ``--exclude`` are the plain-English spellings of
    ``--in-scope`` / ``--out-of-scope``.

Everything downstream — plan bundle (``plan/roe.json`` + ``conops.md``),
RoE validation, and LangGraph dispatch — is the engage path, unchanged.
``hunt`` only translates its friendly flags into engage's and calls it, so
the two commands share one implementation and one set of guarantees.
"""

from __future__ import annotations

import argparse

from buggy.cli.engage import _host_from_target
from buggy.cli.engage import main as engage_main

_MODES = ("audit", "warn", "enforce")


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="buggy-cli hunt",
        description=(
            "Start a hunt against one or more authorized targets in a single "
            "command. Scope defaults to exactly the targets you name; pass "
            "--include-subdomains or --scope to widen it explicitly."
        ),
    )
    p.add_argument(
        "targets",
        nargs="+",
        metavar="TARGET",
        help="Target host, URL, IP, or CIDR you are authorized to test.",
    )
    p.add_argument(
        "--scope",
        action="append",
        default=[],
        metavar="PATTERN",
        help=(
            "Extra in-scope pattern (host, *.domain, IP, CIDR). Comma-separated "
            "and repeatable. Default: exactly the targets."
        ),
    )
    p.add_argument(
        "--exclude",
        action="append",
        default=[],
        metavar="PATTERN",
        help="Out-of-scope pattern. Comma-separated and repeatable.",
    )
    p.add_argument(
        "--include-subdomains",
        action="store_true",
        help="Explicitly add <host> and *.<host> to scope for each target.",
    )
    p.add_argument(
        "--scope-file",
        default=None,
        metavar="PATH",
        help='Scope file (JSON {"in_scope":[...],"out_of_scope":[...]} or text).',
    )
    p.add_argument(
        "--instruction",
        default="",
        help="Free-form focus/auth notes passed to the orchestrator.",
    )
    p.add_argument(
        "--mode",
        choices=_MODES,
        default="enforce",
        help="RoE enforcement mode (default: enforce).",
    )
    p.add_argument(
        "--engagement-name",
        default=None,
        help="Override engagement slug; defaults to a timestamped name.",
    )
    p.add_argument(
        "--plan-only",
        action="store_true",
        help="Write the plan bundle and exit without dispatching.",
    )
    p.add_argument(
        "--non-interactive",
        "-n",
        action="store_true",
        help="Print JSONL events to stdout instead of progress lines.",
    )
    p.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Enable debug logging to stderr.",
    )
    return p


def _to_engage_argv(args: argparse.Namespace) -> list[str]:
    """Translate the friendly hunt flags into an engage argv list."""
    argv: list[str] = []
    for target in args.targets:
        argv += ["--target", target]

    scope: list[str] = list(args.scope)
    if args.include_subdomains:
        for target in args.targets:
            host = _host_from_target(target)
            if host:
                scope += [host, f"*.{host}"]
    for pattern in scope:
        argv += ["--in-scope", pattern]
    for pattern in args.exclude:
        argv += ["--out-of-scope", pattern]

    if args.scope_file:
        argv += ["--scope-file", str(args.scope_file)]
    if args.instruction:
        argv += ["--instruction", args.instruction]
    argv += ["--mode", args.mode]
    if args.engagement_name:
        argv += ["--engagement-name", args.engagement_name]
    if args.plan_only:
        argv.append("--plan-only")
    if args.non_interactive:
        argv.append("--non-interactive")
    if args.verbose:
        argv.append("--verbose")
    return argv


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    return engage_main(_to_engage_argv(args))


if __name__ == "__main__":
    raise SystemExit(main())
