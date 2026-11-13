from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="buggy-cli workflows")
    parser.add_argument("--workspace", type=Path)
    commands = parser.add_subparsers(dest="action", required=True)
    capabilities = commands.add_parser(
        "capabilities", help="Inspect sandbox tool availability without making target requests"
    )
    capabilities.add_argument(
        "--probe", action="store_true", help="Run bounded, fixed version and local parser checks"
    )
    commands.add_parser("catalog", help="Read exact workflow input contracts and limits")
    run = commands.add_parser(
        "run", help="Review supplied evidence, or explicitly request a scoped observation"
    )
    run.add_argument("workflow_id")
    run.add_argument("--url", required=True)
    source = run.add_mutually_exclusive_group(required=True)
    source.add_argument("--artifact", help="Workspace-relative artifact; no target requests")
    source.add_argument(
        "--observe",
        action="store_true",
        help="Operator-requested observation; enforcing RoE and scope required",
    )
    run.add_argument(
        "--ports", nargs="+", type=int, help="1 to 16 explicit ports for network observation"
    )
    run.add_argument("--method", help="HTTP capture method, default GET")
    report = commands.add_parser(
        "report", help="Reopen a run and verify its manifest/evidence integrity"
    )
    report.add_argument("run_id")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    from buggy.sandbox_kernel.capabilities import inspect_capabilities
    from buggy.sandbox_kernel.defensive_workflows import (
        DefensiveWorkflowError,
        DefensiveWorkflowRunner,
        workflow_catalog,
    )

    try:
        if args.action == "capabilities":
            report = inspect_capabilities(probe=args.probe)
        elif args.action == "catalog":
            report = workflow_catalog()
        else:
            if args.workspace is None:
                print("A workspace is required for workflow runs and reports", file=sys.stderr)
                return 2
            runner = DefensiveWorkflowRunner(args.workspace)
            if args.action == "report":
                report = runner.report(args.run_id)
            else:
                payload = {"url": args.url, "observe": args.observe}
                if args.artifact is not None:
                    payload["artifact_path"] = args.artifact
                if args.ports is not None:
                    payload["ports"] = args.ports
                if args.method is not None:
                    payload["method"] = args.method
                report = runner.run(args.workflow_id, payload)
    except (DefensiveWorkflowError, ValueError, OSError):
        print("Workflow request is invalid or unavailable", file=sys.stderr)
        return 2
    print(json.dumps(report, indent=2))
    status = report.get("status")
    return (
        2
        if status == "rejected"
        else 3
        if status in {"blocked", "unavailable", "inconclusive"}
        else 0
    )


if __name__ == "__main__":
    raise SystemExit(main())
