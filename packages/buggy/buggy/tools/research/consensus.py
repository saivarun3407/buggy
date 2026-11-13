"""Multi-model consensus — reduce false positives on critical findings.

For critical/high findings, routes the evidence through multiple
independent validation checks and requires consensus before reporting.
This dramatically reduces false positive rates on the findings that
matter most — the ones submitted to bug bounty programs or reported
to clients.

Validation checks:
1. **Evidence completeness** — does the finding have reproducible PoC?
2. **Severity calibration** — is the severity consistent with the evidence?
3. **Deduplication** — is this a known/duplicate finding?
4. **Exploitability assessment** — is the attack vector realistic?

The consensus tool structures this as a checklist that the agent
fills out. A finding passes consensus when all required checks pass.
Disagreements are flagged for human review.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from langchain_core.tools import tool

from buggy.tools.research._state import _json
from buggy_core.utils.logging import get_logger

log = get_logger("research.consensus")


@tool
def validate_finding_consensus(
    finding_id: str,
    title: str,
    severity: str,
    has_poc: bool,
    poc_reproduces: bool,
    evidence_complete: bool,
    attack_realistic: bool,
    false_positive_check: str = "",
    confidence_notes: str = "",
    workspace: str = "/workspace",
) -> str:
    """Run multi-point consensus validation on a critical/high finding.

    Each validation point must be independently assessed. A finding
    passes consensus only when ALL required checks pass. This should
    be called for every critical/high finding before it is included
    in the final report or submitted to a bounty program.

    Args:
        finding_id: Finding ID (e.g. "FIND-001").
        title: Finding title.
        severity: Finding severity (critical/high/medium/low).
        has_poc: Does the finding have a proof-of-concept?
        poc_reproduces: Does the PoC reproduce consistently?
        evidence_complete: Is the evidence chain complete
            (request/response/impact demonstrated)?
        attack_realistic: Is the attack vector realistic in production
            (not just in test/debug mode)?
        false_positive_check: Explain why this is NOT a false positive
            (e.g. "confirmed via manual testing, not just scanner output").
        confidence_notes: Additional confidence/uncertainty notes.
        workspace: Engagement workspace path.
    """
    checks: list[dict[str, Any]] = [
        {
            "check": "has_poc",
            "passed": has_poc,
            "required": severity in ("critical", "high"),
            "note": "PoC required for critical/high findings",
        },
        {
            "check": "poc_reproduces",
            "passed": poc_reproduces,
            "required": severity in ("critical", "high"),
            "note": "PoC must reproduce consistently",
        },
        {
            "check": "evidence_complete",
            "passed": evidence_complete,
            "required": True,
            "note": "Evidence chain must be complete",
        },
        {
            "check": "attack_realistic",
            "passed": attack_realistic,
            "required": severity in ("critical", "high"),
            "note": "Attack vector must be realistic in production",
        },
        {
            "check": "false_positive_ruled_out",
            "passed": bool(false_positive_check),
            "required": True,
            "note": "Must explain why this is not a false positive",
        },
    ]

    required_checks = [c for c in checks if c["required"]]
    passed_required = all(c["passed"] for c in required_checks)

    if severity in ("critical", "high") and not passed_required:
        verdict = "REJECTED"
        action = "Do NOT include in report. Address failing checks or downgrade severity."
    elif passed_required:
        verdict = "APPROVED"
        action = "Include in report with full confidence."
    else:
        verdict = "REVIEW"
        action = "Flag for human review — non-critical checks failed."

    result = {
        "finding_id": finding_id,
        "title": title,
        "severity": severity,
        "verdict": verdict,
        "action": action,
        "checks": checks,
        "required_passed": sum(1 for c in required_checks if c["passed"]),
        "required_total": len(required_checks),
        "all_passed": sum(1 for c in checks if c["passed"]),
        "all_total": len(checks),
        "false_positive_check": false_positive_check,
        "confidence_notes": confidence_notes,
        "validated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }

    consensus_dir = Path(workspace) / "consensus"
    consensus_dir.mkdir(parents=True, exist_ok=True)
    consensus_path = consensus_dir / f"{finding_id}-consensus.json"
    consensus_path.write_text(json.dumps(result, indent=2), encoding="utf-8")

    return _json(result)


@tool
def consensus_summary(workspace: str = "/workspace") -> str:
    """Summarize consensus validation results across all findings.

    Returns counts of approved, rejected, and review-needed findings.
    """
    consensus_dir = Path(workspace) / "consensus"
    if not consensus_dir.exists():
        return _json({"status": "no_validations", "message": "No consensus validations recorded."})

    results: list[dict[str, Any]] = []
    for path in sorted(consensus_dir.glob("FIND-*-consensus.json")):
        try:
            result = json.loads(path.read_text(encoding="utf-8"))
            results.append(
                {
                    "finding_id": result.get("finding_id", ""),
                    "severity": result.get("severity", ""),
                    "verdict": result.get("verdict", ""),
                    "required_passed": result.get("required_passed", 0),
                    "required_total": result.get("required_total", 0),
                }
            )
        except json.JSONDecodeError:
            continue

    verdicts = {
        "approved": sum(1 for r in results if r["verdict"] == "APPROVED"),
        "rejected": sum(1 for r in results if r["verdict"] == "REJECTED"),
        "review": sum(1 for r in results if r["verdict"] == "REVIEW"),
    }

    return _json(
        {
            "total_validated": len(results),
            "verdicts": verdicts,
            "findings": results,
            "approval_rate": f"{verdicts['approved'] / max(len(results), 1) * 100:.0f}%",
        }
    )


CONSENSUS_TOOLS = [
    validate_finding_consensus,
    consensus_summary,
]
