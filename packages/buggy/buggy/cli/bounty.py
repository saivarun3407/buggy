"""``buggy-cli bounty`` — start a platform bug-bounty hunt.

    buggy-cli bounty                    # HackerOne + Bugcrowd
    buggy-cli bounty --platform hackerone
    buggy-cli bounty --print-kickoff    # emit the scout kickoff only

Unlike ``hunt`` (which takes a target you already know), a platform bounty
run does not start from a target — it starts from a *program*. This command
dispatches the orchestrator straight into the ``bounty`` bundle's Scout
agent, whose human-in-the-loop intake flow is:

    authenticate (HackerOne / Bugcrowd) → list programs you can access →
    you pick one → fetch its structured scope + exclusions + reporting
    policy → you confirm in/out-of-scope → ingest_bounty_scope writes the
    hard-enforced RoE → hand off to recon / the specialist slate.

Because program selection is interactive, the smoothest experience is the
launcher's ``buggy bounty`` (it brings the stack up and drops you into
the terminal UI pre-seeded with this kickoff). This headless entry is for
automation and for composing the exact kickoff text — ``--print-kickoff``
is the single source of truth the launcher reads so the two never drift.

Credentials are read from the environment only (never flags): set
``HACKERONE_API_USERNAME`` / ``HACKERONE_API_TOKEN`` and/or
``BUGCROWD_API_TOKEN`` before launching.

Exit codes: 0 = kickoff printed or run completed; 2 = config/invocation
error; 3 = dispatch internal error.
"""

from __future__ import annotations

import argparse
import logging
import os
import sys

log = logging.getLogger(__name__)

EXIT_OK = 0
EXIT_CONFIG = 2
EXIT_INTERNAL = 3

_PLATFORMS = ("both", "hackerone", "bugcrowd")


def scout_kickoff(platform: str = "both") -> str:
    """Return the orchestrator kickoff that launches the Scout intake flow.

    Kept as one function so the headless CLI and the Go launcher's
    interactive ``BUGGY_INITIAL_MESSAGE`` share identical wording.
    """
    if platform == "hackerone":
        platforms = "HackerOne"
    elif platform == "bugcrowd":
        platforms = "Bugcrowd"
    else:
        platforms = "HackerOne and Bugcrowd"
    return (
        "Start an authorized bug-bounty engagement. Hand off to the bounty "
        f"Scout agent now: authenticate to {platforms} (credentials are in the "
        "environment), list the programs I can access, and let me pick one. "
        "Then fetch that program's structured scope, exclusions, and reporting "
        "policy, confirm in-scope / out-of-scope with me, and call "
        "ingest_bounty_scope to write the enforced RoE before any recon. Do "
        "not test anything until the scope is ingested."
    )


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="buggy-cli bounty",
        description=(
            "Start a platform bug-bounty hunt via the Scout intake flow "
            "(HackerOne / Bugcrowd). Program selection is interactive."
        ),
    )
    p.add_argument(
        "--platform",
        choices=_PLATFORMS,
        default="both",
        help="Which platform(s) the Scout should authenticate to (default: both).",
    )
    p.add_argument(
        "--print-kickoff",
        action="store_true",
        help="Print the Scout kickoff message to stdout and exit (no dispatch).",
    )
    p.add_argument(
        "--engagement-name",
        default=None,
        help="Override engagement slug; defaults to a timestamped name.",
    )
    p.add_argument(
        "--langgraph-url",
        default=os.environ.get("BUGGY_API_URL", "http://localhost:2024"),
        help="LangGraph platform API URL (default: $BUGGY_API_URL).",
    )
    p.add_argument(
        "--assistant",
        default="buggy",
        help="LangGraph assistant graph name (default: buggy).",
    )
    p.add_argument(
        "--timeout",
        type=int,
        default=14400,
        help="Wall-clock timeout in seconds (default 4h).",
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


def _resolve_engagement_name(supplied: str | None) -> str:
    if supplied:
        return supplied
    import datetime  # noqa: PLC0415

    stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    return f"bounty-{stamp}"


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        stream=sys.stderr,
    )

    kickoff = scout_kickoff(args.platform)
    if args.print_kickoff:
        print(kickoff)
        return EXIT_OK

    slug = _resolve_engagement_name(args.engagement_name)
    print(f"bounty engagement: {slug}", file=sys.stderr)
    print(f"platform: {args.platform}", file=sys.stderr)
    print(
        "note: program selection is interactive — watch the stream and answer the Scout's prompts.",
        file=sys.stderr,
    )

    # Reuse engage's SDK streaming so both commands share one dispatch path.
    from buggy.cli.engage import _stream_kickoff  # noqa: PLC0415

    try:
        result = _stream_kickoff(
            langgraph_url=args.langgraph_url,
            assistant=args.assistant,
            engagement_name=slug,
            kickoff=kickoff,
            timeout_seconds=args.timeout,
            non_interactive=args.non_interactive,
        )
        log.info("bounty run complete: %s", result)
    except RuntimeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_CONFIG
    except Exception as exc:  # noqa: BLE001
        print(f"bounty dispatch failed: {exc}", file=sys.stderr)
        return EXIT_INTERNAL
    return EXIT_OK


if __name__ == "__main__":
    raise SystemExit(main())
