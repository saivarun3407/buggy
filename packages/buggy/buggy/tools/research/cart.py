"""CART — Continuous Automated Red Teaming.

Provides tools for scheduled, recurring security assessments against
the same target. Each run diffs its findings against the previous run
to surface:

- **New vulnerabilities** introduced since the last assessment
- **Patched vulnerabilities** that no longer reproduce
- **Regressions** — previously patched vulns that reappeared
- **Persistent** — vulns present across multiple consecutive runs

The CART manifest (``~/.buggy/cart/<target_hash>/manifest.json``)
tracks engagement history, finding deltas, and trend data. Each run
records its findings by hash so deduplication is automatic.

This enables the "continuous security posture management" mode where
Buggy re-assesses targets on a cron (daily/weekly) and only
reports the delta — not the full finding set — to operators.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from pathlib import Path
from typing import Any

from langchain_core.tools import tool

from buggy.tools.research._state import _json
from buggy_core.utils.logging import get_logger

log = get_logger("research.cart")


def _cart_dir() -> Path:
    override = os.environ.get("BUGGY_CART_DIR")
    if override:
        return Path(override)
    return Path.home() / ".buggy" / "cart"


def _target_key(target: str) -> str:
    normalized = target.lower().strip().rstrip("/")
    return hashlib.sha256(normalized.encode()).hexdigest()[:16]


def _manifest_path(target: str) -> Path:
    return _cart_dir() / _target_key(target) / "manifest.json"


def _load_manifest(target: str) -> dict[str, Any]:
    path = _manifest_path(target)
    if path.exists():
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            pass
    return {
        "target": target,
        "runs": [],
        "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }


def _save_manifest(manifest: dict[str, Any]) -> None:
    path = _manifest_path(manifest["target"])
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    os.replace(tmp, path)


@tool
def cart_start_run(target: str, run_id: str = "") -> str:
    """Start a new CART assessment run against a target.

    Records the run start time and prepares the finding tracker.
    Call this at the beginning of a scheduled re-assessment.

    Args:
        target: Target domain/identifier.
        run_id: Optional run identifier. Auto-generated if empty.
    """
    manifest = _load_manifest(target)

    if not run_id:
        run_id = f"run-{len(manifest['runs']) + 1:03d}"

    run: dict[str, Any] = {
        "run_id": run_id,
        "started_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "completed_at": None,
        "finding_hashes": [],
        "status": "in_progress",
    }
    manifest["runs"].append(run)
    _save_manifest(manifest)

    prev_hashes: set[str] = set()
    if len(manifest["runs"]) > 1:
        prev_run = manifest["runs"][-2]
        prev_hashes = set(prev_run.get("finding_hashes", []))

    return _json(
        {
            "target": target,
            "run_id": run_id,
            "run_number": len(manifest["runs"]),
            "previous_finding_count": len(prev_hashes),
            "note": "Record findings with cart_record_finding, then call cart_complete_run for the delta report.",
        }
    )


@tool
def cart_record_finding(
    target: str,
    finding_hash: str,
    title: str,
    severity: str,
) -> str:
    """Record a finding in the current CART run.

    Uses the ``finding_hash`` from ``emit_structured_finding`` for
    deduplication across runs. Call this for each finding discovered
    during the current assessment.

    Args:
        target: Target domain/identifier.
        finding_hash: Stable dedup hash from emit_structured_finding.
        title: Finding title for the delta report.
        severity: Finding severity.
    """
    manifest = _load_manifest(target)

    if not manifest["runs"]:
        return _json({"error": "no active run — call cart_start_run first"})

    current_run = manifest["runs"][-1]
    if current_run["status"] != "in_progress":
        return _json({"error": "current run already completed"})

    if finding_hash not in current_run["finding_hashes"]:
        current_run["finding_hashes"].append(finding_hash)

    if "finding_details" not in current_run:
        current_run["finding_details"] = {}
    current_run["finding_details"][finding_hash] = {
        "title": title,
        "severity": severity,
    }

    _save_manifest(manifest)
    return _json(
        {
            "recorded": True,
            "finding_hash": finding_hash,
            "findings_in_run": len(current_run["finding_hashes"]),
        }
    )


@tool
def cart_complete_run(target: str) -> str:
    """Complete the current CART run and generate a delta report.

    Compares findings from the current run against the previous run
    to identify new, patched, regressed, and persistent vulnerabilities.

    Args:
        target: Target domain/identifier.
    """
    manifest = _load_manifest(target)

    if not manifest["runs"]:
        return _json({"error": "no active run"})

    current_run = manifest["runs"][-1]
    current_run["completed_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    current_run["status"] = "completed"

    current_hashes = set(current_run.get("finding_hashes", []))
    details = current_run.get("finding_details", {})

    prev_hashes: set[str] = set()
    if len(manifest["runs"]) > 1:
        prev_run = manifest["runs"][-2]
        prev_hashes = set(prev_run.get("finding_hashes", []))

    new_findings = current_hashes - prev_hashes
    patched_findings = prev_hashes - current_hashes
    persistent_findings = current_hashes & prev_hashes

    regressed: set[str] = set()
    if len(manifest["runs"]) > 2:
        older_hashes: set[str] = set()
        for run in manifest["runs"][:-2]:
            older_hashes.update(run.get("finding_hashes", []))
        regressed = new_findings & older_hashes

    delta = {
        "new": [{"hash": h, **details.get(h, {})} for h in sorted(new_findings - regressed)],
        "patched": [{"hash": h} for h in sorted(patched_findings)],
        "regressed": [{"hash": h, **details.get(h, {})} for h in sorted(regressed)],
        "persistent": [{"hash": h, **details.get(h, {})} for h in sorted(persistent_findings)],
    }

    current_run["delta"] = delta
    _save_manifest(manifest)

    return _json(
        {
            "target": target,
            "run_id": current_run["run_id"],
            "run_number": len(manifest["runs"]),
            "total_findings": len(current_hashes),
            "delta": {
                "new": len(delta["new"]),
                "patched": len(delta["patched"]),
                "regressed": len(delta["regressed"]),
                "persistent": len(delta["persistent"]),
            },
            "new_findings": delta["new"][:10],
            "regressed_findings": delta["regressed"][:10],
            "patched_findings_count": len(delta["patched"]),
        }
    )


@tool
def cart_trend(target: str, last_n: int = 10) -> str:
    """Get the finding trend across recent CART runs.

    Shows how the security posture has changed over time — total
    findings per run, new/patched counts, and the overall trajectory.

    Args:
        target: Target domain/identifier.
        last_n: Number of recent runs to include (default 10).
    """
    manifest = _load_manifest(target)
    runs = manifest.get("runs", [])

    if not runs:
        return _json(
            {
                "target": target,
                "status": "no_runs",
                "message": "No CART runs recorded for this target.",
            }
        )

    trend = []
    for run in runs[-last_n:]:
        delta = run.get("delta", {})
        trend.append(
            {
                "run_id": run.get("run_id", ""),
                "date": run.get("completed_at", run.get("started_at", "")),
                "total_findings": len(run.get("finding_hashes", [])),
                "new": len(delta.get("new", [])),
                "patched": len(delta.get("patched", [])),
                "regressed": len(delta.get("regressed", [])),
            }
        )

    totals = [t["total_findings"] for t in trend]
    trajectory = (
        "improving"
        if len(totals) > 1 and totals[-1] < totals[0]
        else "stable"
        if len(totals) <= 1
        else "degrading"
        if totals[-1] > totals[0]
        else "stable"
    )

    return _json(
        {
            "target": target,
            "total_runs": len(runs),
            "trend": trend,
            "trajectory": trajectory,
            "latest_total": totals[-1] if totals else 0,
        }
    )


CART_TOOLS = [
    cart_start_run,
    cart_record_finding,
    cart_complete_run,
    cart_trend,
]
