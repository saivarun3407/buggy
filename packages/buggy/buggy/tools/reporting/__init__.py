"""Finding export + report generation.

- ``hackerone``   — HackerOne markdown template renderer
- ``bugcrowd``    — Bugcrowd submission CSV writer
- ``executive``   — Engagement-level executive summary composer
- ``timeline``    — Chronological event timeline extractor
- ``sarif``       — SARIF v2.1.0 JSON exporter for GitHub / DefectDojo

Renderers operate on ``KnowledgeGraph`` state so the same graph can
feed a bounty submission, an engagement executive summary, a SARIF
upload, and a JSON bundle for further automation.
"""

from __future__ import annotations

from buggy.tools.reporting.bugcrowd import render_bugcrowd_csv
from buggy.tools.reporting.cvss import (
    CVSS_TOOLS,
    cvss_score_tool,
    score_vector,
    severity_band,
)
from buggy.tools.reporting.executive import render_executive_summary
from buggy.tools.reporting.hackerone import HackerOneReport, render_hackerone_markdown
from buggy.tools.reporting.proof_gate import (
    GateResult,
    proof_gate_strict,
    verify_finding,
)
from buggy.tools.reporting.sarif import render_sarif
from buggy.tools.reporting.timeline import extract_timeline

__all__ = [
    "CVSS_TOOLS",
    "GateResult",
    "HackerOneReport",
    "cvss_score_tool",
    "extract_timeline",
    "proof_gate_strict",
    "render_bugcrowd_csv",
    "render_executive_summary",
    "render_hackerone_markdown",
    "render_sarif",
    "score_vector",
    "severity_band",
    "verify_finding",
]
