"""``buggy-cli engage`` — minimal-input authorized engagement entry.

    buggy-cli engage --target api.example.com \
        --in-scope "*.example.com,example.com" \
        --out-of-scope "admin.example.com"

    buggy-cli engage --target api.example.com --scope-file scope.json

The operator supplies a target plus in/out-of-scope lists; the harness
does everything downstream. This command synthesizes the plan bundle the
interactive Soundwave interview would otherwise produce — ``plan/roe.json``
with a ``machine_enforcement`` block (the file the RoE guardrail actually
evaluates) and a minimal ``plan/conops.md`` — then dispatches the
Buggy orchestrator through the LangGraph SDK. The orchestrator
builds the OPPLAN itself and runs the recon → exploit → validation → KG
pipeline from its standard workflow.

Conservative default: when no ``--in-scope`` is given, the in-scope set
is exactly the supplied targets — the CLI never widens an authorization
boundary on its own (no implicit ``*.domain`` expansion).

Exit codes: 0 = engagement run completed (or ``--plan-only`` bundle
written); 2 = config/invocation error; 3 = dispatch internal error.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import re
import sys
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

EXIT_OK = 0
EXIT_CONFIG = 2
EXIT_INTERNAL = 3

_MODES = ("audit", "warn", "enforce")


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="buggy-cli engage",
        description=(
            "Start an authorized engagement from a target + scope lists. "
            "Writes plan/roe.json (+ CONOPS) and dispatches Buggy, "
            "which builds the OPPLAN and runs the pipeline."
        ),
    )
    p.add_argument(
        "--target",
        "-t",
        action="append",
        required=True,
        help="Engagement target (host, URL, IP, or CIDR). Repeatable.",
    )
    p.add_argument(
        "--in-scope",
        action="append",
        default=[],
        metavar="PATTERNS",
        help=(
            "Comma-separated in-scope patterns (host, *.domain, IP, CIDR). "
            "Repeatable. Default: exactly the supplied targets."
        ),
    )
    p.add_argument(
        "--out-of-scope",
        action="append",
        default=[],
        metavar="PATTERNS",
        help="Comma-separated out-of-scope patterns. Repeatable.",
    )
    p.add_argument(
        "--scope-file",
        type=Path,
        default=None,
        help=(
            'Scope file: JSON {"in_scope": [...], "out_of_scope": [...]}, '
            "or text with one pattern per line ('in: pat', 'out: pat', "
            "bare line = in-scope, '#' = comment)."
        ),
    )
    p.add_argument(
        "--mode",
        choices=_MODES,
        default="enforce",
        help="RoE enforcement mode written to roe.json (default: enforce).",
    )
    p.add_argument(
        "--instruction",
        default="",
        help="Free-form engagement instruction (focus, auth notes, constraints).",
    )
    p.add_argument(
        "--forbidden-command",
        action="append",
        default=[],
        metavar="REGEX",
        help="Extra forbidden command pattern for machine_enforcement. Repeatable.",
    )
    p.add_argument(
        "--engagement-name",
        default=None,
        help="Override engagement slug; defaults to a timestamped name.",
    )
    p.add_argument(
        "--workspace-root",
        type=Path,
        default=None,
        help=(
            "Host workspace root; default $BUGGY_ENGAGEMENT_WORKSPACE "
            "or ~/.buggy/workspace. The plan bundle lands at "
            "<root>/<slug>/plan/."
        ),
    )
    p.add_argument(
        "--plan-only",
        action="store_true",
        help="Write the plan bundle and exit without dispatching (review gate).",
    )
    p.add_argument(
        "--langgraph-url",
        default=os.environ.get("BUGGY_API_URL", "http://localhost:2024"),
        help="LangGraph platform API URL (default: $BUGGY_API_URL).",
    )
    p.add_argument(
        "--assistant",
        default=None,
        help=("LangGraph assistant graph name (default: $BUGGY_LANGGRAPH_ASSISTANT or buggy)."),
    )
    p.add_argument(
        "--timeout",
        type=int,
        default=14400,
        help="Wall-clock timeout in seconds for the engagement run (default 4h).",
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


# ── Scope input ────────────────────────────────────────────────────────


def _split_patterns(values: list[str]) -> list[str]:
    """Flatten repeatable comma-separated flags into a clean pattern list."""
    out: list[str] = []
    for value in values:
        out.extend(part.strip() for part in value.split(",") if part.strip())
    return out


def _load_scope_file(path: Path) -> tuple[list[str], list[str]]:
    """Parse a scope file into (in_scope, out_of_scope).

    JSON form: ``{"in_scope": [...], "out_of_scope": [...]}``. Text form:
    one pattern per line — ``in: <pat>`` explicit in-scope, ``out: <pat>``
    out-of-scope, a bare line is in-scope, ``#`` starts a comment.
    """
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise RuntimeError(f"failed to read --scope-file {path}: {exc}") from exc

    stripped = text.lstrip()
    if stripped.startswith("{"):
        try:
            doc = json.loads(text)
        except json.JSONDecodeError as exc:
            raise RuntimeError(f"--scope-file {path} is not valid JSON: {exc}") from exc
        if not isinstance(doc, dict):
            raise RuntimeError(f"--scope-file {path} must contain a JSON object")
        ins = doc.get("in_scope") or []
        outs = doc.get("out_of_scope") or []
        if not isinstance(ins, list) or not isinstance(outs, list):
            raise RuntimeError(f"--scope-file {path}: in_scope/out_of_scope must be arrays")
        return (
            [str(x).strip() for x in ins if str(x).strip()],
            [str(x).strip() for x in outs if str(x).strip()],
        )

    ins: list[str] = []
    outs: list[str] = []

    def _take(line: str, prefix_len: int, lineno: int) -> str:
        pattern = line[prefix_len:].strip()
        if not pattern:
            raise RuntimeError(f"--scope-file {path}: empty pattern on line {lineno}")
        return pattern

    for lineno, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        lowered = line.lower()
        if lowered.startswith("out:"):
            outs.append(_take(line, 4, lineno))
        elif lowered.startswith("in:"):
            ins.append(_take(line, 3, lineno))
        elif lowered.startswith("-"):
            outs.append(_take(line, 1, lineno))
        elif lowered.startswith("+"):
            ins.append(_take(line, 1, lineno))
        else:
            ins.append(line)
    return ins, outs


def _host_from_target(target: str) -> str:
    """Reduce a target to the host/IP token used as the default scope rule."""
    value = target.strip()
    value = re.sub(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://", "", value)
    value = value.split("@", 1)[-1]
    value = value.split("/", 1)[0]
    return value


def _validate_scope_entries(in_scope: list[str], out_of_scope: list[str]) -> list[str]:
    """Run each scope pattern through the guardrail's own entry validator.

    Returns the list of validation errors (empty = the written roe.json is
    guaranteed to load in the middleware). Reuses
    ``buggy.middleware.roe._validate_target_entry`` so the CLI cannot
    emit a document the guardrail itself would refuse to parse.
    """
    from buggy.middleware.roe import (  # noqa: PLC0415
        InvalidRoEError,
        _validate_target_entry,
    )

    errors: list[str] = []
    for field, entries in (("in_scope", in_scope), ("out_of_scope", out_of_scope)):
        for entry in entries:
            try:
                _validate_target_entry(field, entry)
            except InvalidRoEError as exc:
                errors.append(f"{field} {entry!r}: {exc}")
    return errors


# ── Plan bundle ────────────────────────────────────────────────────────


def _workspace_root(args: argparse.Namespace) -> Path:
    if args.workspace_root:
        return args.workspace_root.expanduser()
    raw = os.environ.get("BUGGY_ENGAGEMENT_WORKSPACE")
    if raw and raw.strip():
        return Path(raw.strip()).expanduser()
    return Path.home() / ".buggy" / "workspace"


def _write_plan_bundle(
    *,
    root: Path,
    slug: str,
    targets: list[str],
    in_scope: list[str],
    out_of_scope: list[str],
    mode: str,
    forbidden_commands: list[str],
    instruction: str,
) -> Path:
    """Write ``plan/roe.json`` + ``plan/conops.md`` under <root>/<slug>/.

    The bundle is what Soundwave's interview produces interactively; the
    CLI emits the same contract files non-interactively. Returns the plan
    directory. The host-side path mirrors the sandbox view because the
    launcher mounts the workspace tree at ``/workspace`` (the run's
    ``workspace_path`` configurable is ``/workspace/<slug>``).
    """
    import datetime  # noqa: PLC0415

    plan_dir = root / slug / "plan"
    plan_dir.mkdir(parents=True, exist_ok=True)
    created = datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")

    roe_doc = {
        "version": 1,
        "engagement_name": slug,
        "generated_by": "buggy-cli engage",
        "created": created,
        "machine_enforcement": {
            "mode": mode,
            "in_scope": in_scope,
            "out_of_scope": out_of_scope,
            "forbidden_command_patterns": forbidden_commands,
        },
    }
    roe_path = plan_dir / "roe.json"
    roe_path.write_text(json.dumps(roe_doc, indent=2) + "\n", encoding="utf-8")

    conops = plan_dir / "conops.md"
    conops.write_text(
        "# CONOPS — {slug}\n\n"
        "Generated by `buggy-cli engage` (non-interactive path).\n\n"
        "## Targets\n\n{targets}\n\n"
        "## Scope\n\n"
        "| In scope | Out of scope |\n"
        "|---|---|\n"
        "{scope_rows}\n\n"
        "Enforcement mode: `{mode}` (see `roe.json:machine_enforcement`).\n\n"
        "{instruction_block}"
        "Created: {created}\n".format(
            slug=slug,
            targets="\n".join(f"- `{t}`" for t in targets),
            scope_rows="\n".join(
                f"| `{i}` | `{o}` |"
                for i, o in zip(
                    in_scope + [""] * max(0, len(out_of_scope) - len(in_scope)),
                    out_of_scope + [""] * max(0, len(in_scope) - len(out_of_scope)),
                )
            )
            or "| _(derived from targets)_ |  |",
            mode=mode,
            instruction_block=(
                f"## Operator instruction\n\n{instruction}\n\n" if instruction.strip() else ""
            ),
            created=created,
        ),
        encoding="utf-8",
    )
    return plan_dir


# ── Dispatch ───────────────────────────────────────────────────────────


def _resolve_engagement_name(supplied: str | None) -> str:
    if supplied:
        return supplied
    import datetime  # noqa: PLC0415

    stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    return f"engage-{stamp}"


def _emit_jsonl_event(event: dict[str, Any]) -> None:
    print(json.dumps(event, default=str, ensure_ascii=False), flush=True)


def _stream_kickoff(
    *,
    langgraph_url: str,
    assistant: str,
    engagement_name: str,
    kickoff: str,
    timeout_seconds: int,
    non_interactive: bool,
) -> dict[str, Any]:
    """Create a thread and stream one kickoff run to completion.

    The shared dispatch path for every headless entry point (engage, hunt,
    bounty): they differ only in the ``kickoff`` text they hand the
    orchestrator. ``workspace_path`` follows the benchmark-harness
    convention (``/workspace/<slug>``) — the launcher mounts the workspace
    tree at ``/workspace``, so a plan bundle written host-side at
    ``<root>/<slug>/plan/`` resolves identically in-sandbox.
    """
    try:
        from langgraph_sdk import get_client  # noqa: PLC0415
    except ImportError as exc:
        raise RuntimeError(
            "langgraph-sdk is not installed in this Python environment. "
            "Install with: pip install langgraph-sdk"
        ) from exc

    client = get_client(url=langgraph_url)

    state_input = {
        "messages": [{"role": "user", "content": kickoff}],
        "engagement_name": engagement_name,
    }
    config = {
        "configurable": {
            "engagement_name": engagement_name,
            "workspace_path": f"/workspace/{engagement_name}",
        }
    }

    import asyncio  # noqa: PLC0415

    async def _run() -> dict[str, Any]:
        thread = await client.threads.create()
        events_collected = 0
        last_event_kind = ""
        async for chunk in client.runs.stream(
            thread["thread_id"],
            assistant_id=assistant,
            input=state_input,
            config=config,
            stream_mode=["values", "updates", "custom"],
        ):
            events_collected += 1
            last_event_kind = chunk.event
            if non_interactive:
                _emit_jsonl_event({"type": chunk.event, "data": chunk.data})
            else:
                print(f"\r  … {events_collected} events ({last_event_kind})", end="", flush=True)
        if not non_interactive:
            print()
        return {
            "thread_id": thread["thread_id"],
            "last_event": last_event_kind,
            "event_count": events_collected,
        }

    return asyncio.run(asyncio.wait_for(_run(), timeout=timeout_seconds))


def _dispatch_engagement_via_sdk(
    *,
    langgraph_url: str,
    assistant: str,
    engagement_name: str,
    targets: list[str],
    in_scope: list[str],
    out_of_scope: list[str],
    mode: str,
    instruction: str,
    timeout_seconds: int,
    non_interactive: bool,
) -> dict[str, Any]:
    """Kick off the engagement through the LangGraph SDK."""
    kickoff = (
        f"Begin authorized engagement '{engagement_name}'. "
        f"Targets: {', '.join(targets)}. "
        f"The written scope boundary is plan/roe.json "
        f"(machine_enforcement mode={mode}); in-scope and out-of-scope "
        "lists are already committed there — do not re-interview the "
        "operator for scope. "
        + (f"Operator instruction: {instruction.strip()} " if instruction.strip() else "")
        + "Build the OPPLAN and conduct the engagement."
    )
    return _stream_kickoff(
        langgraph_url=langgraph_url,
        assistant=assistant,
        engagement_name=engagement_name,
        kickoff=kickoff,
        timeout_seconds=timeout_seconds,
        non_interactive=non_interactive,
    )


# ── Entry ──────────────────────────────────────────────────────────────


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        stream=sys.stderr,
    )

    in_scope = _split_patterns(args.in_scope)
    out_of_scope = _split_patterns(args.out_of_scope)
    if args.scope_file:
        try:
            file_in, file_out = _load_scope_file(args.scope_file)
        except RuntimeError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return EXIT_CONFIG
        in_scope.extend(file_in)
        out_of_scope.extend(file_out)

    targets = [t.strip() for t in args.target if t.strip()]
    if not targets:
        print("error: at least one non-empty --target is required", file=sys.stderr)
        return EXIT_CONFIG

    if not in_scope:
        # Conservative default: scope = exactly the targets given. No
        # implicit wildcard expansion — the CLI does not widen an
        # authorization boundary on its own.
        in_scope = [_host_from_target(t) for t in targets]
        print(
            "note: no --in-scope given; in-scope defaults to the targets "
            f'exactly: {in_scope}. Pass --in-scope "*.<domain>" to '
            "include subdomains.",
            file=sys.stderr,
        )

    errors = _validate_scope_entries(in_scope, out_of_scope)
    if errors:
        for err in errors:
            print(f"error: {err}", file=sys.stderr)
        return EXIT_CONFIG

    slug = _resolve_engagement_name(args.engagement_name)
    root = _workspace_root(args)
    try:
        plan_dir = _write_plan_bundle(
            root=root,
            slug=slug,
            targets=targets,
            in_scope=in_scope,
            out_of_scope=out_of_scope,
            mode=args.mode,
            forbidden_commands=args.forbidden_command,
            instruction=args.instruction,
        )
    except OSError as exc:
        print(f"error: failed to write plan bundle: {exc}", file=sys.stderr)
        return EXIT_CONFIG

    print(f"engagement: {slug}", file=sys.stderr)
    print(f"plan bundle: {plan_dir}", file=sys.stderr)
    print(
        f"scope: {len(in_scope)} in / {len(out_of_scope)} out (mode={args.mode})",
        file=sys.stderr,
    )

    if args.plan_only:
        print("--plan-only: bundle written, dispatch skipped", file=sys.stderr)
        return EXIT_OK

    try:
        result = _dispatch_engagement_via_sdk(
            langgraph_url=args.langgraph_url,
            assistant=args.assistant or os.getenv("BUGGY_LANGGRAPH_ASSISTANT", "buggy"),
            engagement_name=slug,
            targets=targets,
            in_scope=in_scope,
            out_of_scope=out_of_scope,
            mode=args.mode,
            instruction=args.instruction,
            timeout_seconds=args.timeout,
            non_interactive=args.non_interactive,
        )
        log.info("engagement run complete: %s", result)
    except RuntimeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_CONFIG
    except Exception as exc:  # noqa: BLE001
        print(f"engagement dispatch failed: {exc}", file=sys.stderr)
        return EXIT_INTERNAL

    engagement_dir = root / slug
    findings = sorted(engagement_dir.glob("findings/FIND-*.md"))
    print(f"engagement complete: {slug}", file=sys.stderr)
    print(f"workspace: {engagement_dir}", file=sys.stderr)
    if findings:
        print(f"findings: {len(findings)} under {engagement_dir}/findings/", file=sys.stderr)
    else:
        print("findings: none recorded (see workspace + audit/ for activity)", file=sys.stderr)
    print(
        f"audit ledger: {engagement_dir}/audit/roe-decisions.jsonl (verify with `buggy-cli audit`)",
        file=sys.stderr,
    )
    return EXIT_OK


if __name__ == "__main__":
    raise SystemExit(main())
