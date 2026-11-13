"""Structured finding output — machine-readable JSON alongside markdown.

Every finding is recorded as both ``findings/FIND-NNN.md`` (operational
markdown, existing flow) and ``findings/FIND-NNN.json`` (structured
schema). The JSON representation enables:

- Direct import into DefectDojo, Jira, ServiceNow, SOAR platforms
- Automated deduplication via stable ``finding_hash``
- Severity trending across engagements
- Compliance mapping (CWE -> OWASP Top 10 -> PCI-DSS)
- MITRE ATT&CK technique cross-reference

The schema follows CVSS 4.0 vector format and includes all fields
needed for enterprise reporting pipelines.
"""

from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path
from typing import Any

from langchain_core.tools import tool

from buggy.tools.research._state import _json
from buggy_core.utils.logging import get_logger

log = get_logger("research.structured_findings")

# CWE -> OWASP Top 10 2021 mapping (most common)
_CWE_OWASP: dict[str, str] = {
    "CWE-79": "A03:2021-Injection",
    "CWE-89": "A03:2021-Injection",
    "CWE-78": "A03:2021-Injection",
    "CWE-77": "A03:2021-Injection",
    "CWE-94": "A03:2021-Injection",
    "CWE-917": "A03:2021-Injection",
    "CWE-22": "A01:2021-Broken Access Control",
    "CWE-284": "A01:2021-Broken Access Control",
    "CWE-285": "A01:2021-Broken Access Control",
    "CWE-639": "A01:2021-Broken Access Control",
    "CWE-862": "A01:2021-Broken Access Control",
    "CWE-863": "A01:2021-Broken Access Control",
    "CWE-352": "A01:2021-Broken Access Control",
    "CWE-287": "A07:2021-Identification and Authentication Failures",
    "CWE-384": "A07:2021-Identification and Authentication Failures",
    "CWE-798": "A07:2021-Identification and Authentication Failures",
    "CWE-916": "A07:2021-Identification and Authentication Failures",
    "CWE-327": "A02:2021-Cryptographic Failures",
    "CWE-328": "A02:2021-Cryptographic Failures",
    "CWE-330": "A02:2021-Cryptographic Failures",
    "CWE-311": "A02:2021-Cryptographic Failures",
    "CWE-312": "A02:2021-Cryptographic Failures",
    "CWE-502": "A08:2021-Software and Data Integrity Failures",
    "CWE-829": "A08:2021-Software and Data Integrity Failures",
    "CWE-918": "A10:2021-Server-Side Request Forgery",
    "CWE-611": "A05:2021-Security Misconfiguration",
    "CWE-16": "A05:2021-Security Misconfiguration",
    "CWE-200": "A01:2021-Broken Access Control",
    "CWE-532": "A09:2021-Security Logging and Monitoring Failures",
    "CWE-1035": "A06:2021-Vulnerable and Outdated Components",
}


def _compute_finding_hash(
    title: str,
    endpoint: str,
    cwe: str,
) -> str:
    """Stable dedup hash for a finding."""
    key = f"{title}|{endpoint}|{cwe}".lower().strip()
    return hashlib.sha256(key.encode()).hexdigest()[:16]


@tool
def emit_structured_finding(
    finding_id: str,
    title: str,
    severity: str,
    description: str,
    evidence: str,
    agent: str,
    cwe: str = "",
    cvss_vector: str = "",
    cvss_score: float = 0.0,
    endpoint: str = "",
    method: str = "",
    parameter: str = "",
    attack_vector: str = "",
    mitre_techniques: str = "",
    vrt: str = "",
    remediation: str = "",
    references: str = "",
    workspace: str = "/workspace",
) -> str:
    """Emit a finding in structured JSON format alongside the markdown.

    Writes ``findings/FIND-NNN.json`` with a machine-readable schema
    suitable for import into DefectDojo, Jira, ServiceNow, or any
    SARIF-consuming pipeline. Also computes OWASP Top 10 mapping from
    the CWE and generates a stable deduplication hash.

    Call this AFTER writing the operational ``findings/FIND-NNN.md``.

    Args:
        finding_id: Finding ID (e.g. "FIND-001").
        title: One-line finding summary.
        severity: critical/high/medium/low/informational.
        description: Full description (2-4 sentences).
        evidence: Evidence details (request/response/PoC).
        agent: Which agent discovered it.
        cwe: CWE identifier (e.g. "CWE-89").
        cvss_vector: CVSS 4.0 vector string.
        cvss_score: CVSS numeric score (0-10).
        endpoint: Affected endpoint/URL.
        method: HTTP method if applicable (GET/POST/etc).
        parameter: Vulnerable parameter name.
        attack_vector: The specific attack used.
        mitre_techniques: Comma-separated MITRE ATT&CK IDs.
        vrt: Bugcrowd VRT path.
        remediation: Recommended fix.
        references: Comma-separated reference URLs.
        workspace: Engagement workspace path.
    """
    findings_dir = Path(workspace) / "findings"
    findings_dir.mkdir(parents=True, exist_ok=True)

    techniques = [t.strip() for t in mitre_techniques.split(",") if t.strip()]
    refs = [r.strip() for r in references.split(",") if r.strip()]

    owasp = _CWE_OWASP.get(cwe.upper(), "")

    finding: dict[str, Any] = {
        "schema_version": "1.0",
        "finding_id": finding_id,
        "title": title,
        "severity": severity.lower(),
        "description": description,
        "evidence": evidence,
        "agent": agent,
        "discovered_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "classification": {
            "cwe": cwe,
            "owasp_top_10": owasp,
            "cvss_vector": cvss_vector,
            "cvss_score": cvss_score,
            "vrt": vrt,
            "mitre_attack": techniques,
        },
        "location": {
            "endpoint": endpoint,
            "method": method,
            "parameter": parameter,
        },
        "attack_vector": attack_vector,
        "remediation": remediation,
        "references": refs,
        "finding_hash": _compute_finding_hash(title, endpoint, cwe),
    }

    json_path = findings_dir / f"{finding_id}.json"
    json_path.write_text(json.dumps(finding, indent=2), encoding="utf-8")

    return _json(
        {
            "finding_id": finding_id,
            "json_path": str(json_path),
            "finding_hash": finding["finding_hash"],
            "owasp_mapping": owasp,
        }
    )


@tool
def export_findings_bulk(
    output_format: str = "json",
    workspace: str = "/workspace",
) -> str:
    """Export all structured findings in bulk for downstream integration.

    Reads all ``findings/FIND-*.json`` files and produces a unified
    export suitable for DefectDojo, Jira, or generic JSON consumers.

    Args:
        output_format: Export format — ``json`` (array of findings),
            ``defectdojo`` (DefectDojo Generic Findings Import format),
            ``sarif`` (SARIF 2.1.0 format).
        workspace: Engagement workspace path.
    """
    findings_dir = Path(workspace) / "findings"
    findings: list[dict[str, Any]] = []

    for path in sorted(findings_dir.glob("FIND-*.json")):
        try:
            finding = json.loads(path.read_text(encoding="utf-8"))
            findings.append(finding)
        except json.JSONDecodeError:
            continue

    if not findings:
        return _json({"error": "no structured findings found", "format": output_format})

    if output_format == "defectdojo":
        export = _to_defectdojo(findings)
    elif output_format == "sarif":
        export = _to_sarif(findings)
    else:
        export = {"findings": findings, "count": len(findings)}

    export_path = Path(workspace) / "report" / f"findings-export.{output_format}.json"
    export_path.parent.mkdir(parents=True, exist_ok=True)
    export_path.write_text(json.dumps(export, indent=2), encoding="utf-8")

    return _json(
        {
            "format": output_format,
            "findings_count": len(findings),
            "export_path": str(export_path),
        }
    )


def _to_defectdojo(findings: list[dict[str, Any]]) -> dict[str, Any]:
    """Convert to DefectDojo Generic Findings Import format."""
    dd_findings = []
    for f in findings:
        dd = {
            "title": f.get("title", ""),
            "description": f.get("description", ""),
            "severity": (f.get("severity", "medium") or "medium").capitalize(),
            "date": f.get("discovered_at", "")[:10],
            "cwe": int(f.get("classification", {}).get("cwe", "CWE-0").replace("CWE-", "") or 0),
            "cvssv3": f.get("classification", {}).get("cvss_score", 0),
            "cvssv3_vector": f.get("classification", {}).get("cvss_vector", ""),
            "endpoints": [f.get("location", {}).get("endpoint", "")],
            "references": "\n".join(f.get("references", [])),
            "mitigation": f.get("remediation", ""),
            "unique_id_from_tool": f.get("finding_hash", ""),
            "vuln_id_from_tool": f.get("finding_id", ""),
        }
        dd_findings.append(dd)
    return {"findings": dd_findings}


def _to_sarif(findings: list[dict[str, Any]]) -> dict[str, Any]:
    """Convert to SARIF 2.1.0 format."""
    results = []
    rules = []
    rule_ids: set[str] = set()

    for f in findings:
        cwe = f.get("classification", {}).get("cwe", "")
        rule_id = cwe if cwe else f.get("finding_id", "unknown")

        if rule_id not in rule_ids:
            rule_ids.add(rule_id)
            rules.append(
                {
                    "id": rule_id,
                    "shortDescription": {"text": f.get("title", "")},
                    "helpUri": f"https://cwe.mitre.org/data/definitions/{cwe.replace('CWE-', '')}.html"
                    if cwe
                    else "",
                }
            )

        sev_map = {
            "critical": "error",
            "high": "error",
            "medium": "warning",
            "low": "note",
            "informational": "note",
        }
        level = sev_map.get(f.get("severity", "medium"), "warning")

        result: dict[str, Any] = {
            "ruleId": rule_id,
            "level": level,
            "message": {"text": f.get("description", "")},
            "fingerprints": {"finding_hash": f.get("finding_hash", "")},
        }

        endpoint = f.get("location", {}).get("endpoint", "")
        if endpoint:
            result["locations"] = [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": endpoint},
                    },
                }
            ]

        results.append(result)

    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Buggy",
                        "version": "1.0.0",
                        "rules": rules,
                    },
                },
                "results": results,
            }
        ],
    }


STRUCTURED_FINDING_TOOLS = [
    emit_structured_finding,
    export_findings_bulk,
]
