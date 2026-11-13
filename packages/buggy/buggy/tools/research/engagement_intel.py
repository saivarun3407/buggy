"""Cross-session engagement intelligence — persistent per-target memory.

Stores and retrieves per-target intelligence across engagements so the
Nth engagement against a target compounds on prior knowledge:

- **Prior findings** with severity, status, and evidence summaries
- **Tech-stack fingerprints** (frameworks, languages, versions)
- **Attack paths** that succeeded or failed
- **Vulnerability patterns** recurring for this target/org

Storage is a JSON file per target domain at
``~/.buggy/intel/<domain_hash>.json``, kept outside the engagement
workspace so it survives workspace cleanup. No external services
(ChromaDB, pgvector) are required — the store is self-contained.

OSINT feed tools (CISA KEV proactive check, GitHub Security Advisories)
cross-reference the detected tech stack against known-exploited
vulnerabilities to surface high-value attack vectors *before* scanning.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

import httpx
from langchain_core.tools import tool

from buggy.tools.research._state import _json
from buggy_core.utils.logging import get_logger

log = get_logger("research.engagement_intel")

# ── Storage ─────────────────────────────────────────────────────────────

_INTEL_DIR = Path(os.environ.get("BUGGY_INTEL_DIR", ""))


def _intel_dir() -> Path:
    """Resolve the persistent intelligence store directory."""
    if _INTEL_DIR and _INTEL_DIR != Path(""):
        return _INTEL_DIR
    return Path.home() / ".buggy" / "intel"


def _target_key(target: str) -> str:
    """Normalize target to a filesystem-safe key."""
    normalized = target.lower().strip().rstrip("/")
    return hashlib.sha256(normalized.encode()).hexdigest()[:16]


def _target_path(target: str) -> Path:
    return _intel_dir() / f"{_target_key(target)}.json"


@dataclass
class Finding:
    """A prior finding summary for cross-session recall."""

    title: str
    severity: str
    status: str  # confirmed, patched, false-positive
    evidence_summary: str
    discovered_at: str
    agent: str = ""
    cwe: str = ""
    endpoint: str = ""


@dataclass
class AttackPath:
    """A previously attempted attack path."""

    description: str
    succeeded: bool
    techniques: list[str] = field(default_factory=list)
    notes: str = ""


@dataclass
class TargetIntel:
    """Persistent intelligence record for a target domain/org."""

    target: str
    tech_stack: dict[str, Any] = field(default_factory=dict)
    findings: list[dict[str, Any]] = field(default_factory=list)
    attack_paths: list[dict[str, Any]] = field(default_factory=list)
    failed_approaches: list[str] = field(default_factory=list)
    vuln_patterns: list[str] = field(default_factory=list)
    last_engagement: str = ""
    engagement_count: int = 0
    notes: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "tech_stack": self.tech_stack,
            "findings": self.findings,
            "attack_paths": self.attack_paths,
            "failed_approaches": self.failed_approaches,
            "vuln_patterns": self.vuln_patterns,
            "last_engagement": self.last_engagement,
            "engagement_count": self.engagement_count,
            "notes": self.notes,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> TargetIntel:
        return cls(
            target=data.get("target", ""),
            tech_stack=data.get("tech_stack", {}),
            findings=data.get("findings", []),
            attack_paths=data.get("attack_paths", []),
            failed_approaches=data.get("failed_approaches", []),
            vuln_patterns=data.get("vuln_patterns", []),
            last_engagement=data.get("last_engagement", ""),
            engagement_count=data.get("engagement_count", 0),
            notes=data.get("notes", ""),
        )


def _load_intel(target: str) -> TargetIntel:
    path = _target_path(target)
    if path.exists():
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            return TargetIntel.from_dict(data)
        except (json.JSONDecodeError, KeyError):
            log.warning("corrupt intel file %s — starting fresh", path)
    return TargetIntel(target=target)


def _save_intel(intel: TargetIntel) -> None:
    path = _target_path(intel.target)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(intel.to_dict(), indent=2), encoding="utf-8")
    os.replace(tmp, path)


# ── Tools: Store & Recall ───────────────────────────────────────────────


@tool
def recall_target_intel(target: str) -> str:
    """Retrieve prior engagement intelligence for a target domain/org.

    Returns a JSON briefing with prior findings, tech stack, successful
    attack paths, failed approaches, and vulnerability patterns from
    all previous engagements against this target. Returns empty sections
    if this is the first engagement.

    Call this at the START of every engagement to benefit from
    cumulative intelligence.
    """
    intel = _load_intel(target)
    if intel.engagement_count == 0:
        return _json(
            {
                "target": target,
                "status": "first_engagement",
                "message": "No prior intelligence for this target.",
            }
        )

    briefing: dict[str, Any] = {
        "target": intel.target,
        "engagement_count": intel.engagement_count,
        "last_engagement": intel.last_engagement,
        "tech_stack": intel.tech_stack,
        "prior_findings_count": len(intel.findings),
        "prior_findings": intel.findings[-20:],  # last 20
        "successful_attack_paths": [p for p in intel.attack_paths if p.get("succeeded")],
        "failed_approaches": intel.failed_approaches[-10:],
        "vuln_patterns": intel.vuln_patterns,
        "notes": intel.notes,
    }
    return _json(briefing)


@tool
def store_finding_intel(
    target: str,
    title: str,
    severity: str,
    status: str,
    evidence_summary: str,
    agent: str = "",
    cwe: str = "",
    endpoint: str = "",
) -> str:
    """Store a finding in the persistent per-target intelligence store.

    Call this after confirming a finding so future engagements against
    the same target can recall it. The finding persists across sessions.

    Args:
        target: Target domain/org identifier (e.g. "example.com").
        title: One-line finding summary.
        severity: critical/high/medium/low/informational.
        status: confirmed/patched/false-positive.
        evidence_summary: Brief evidence description (1-2 sentences).
        agent: Which agent discovered it (e.g. "asvs", "api_security").
        cwe: CWE identifier if known (e.g. "CWE-89").
        endpoint: Affected endpoint/path if applicable.
    """
    intel = _load_intel(target)
    finding = Finding(
        title=title,
        severity=severity,
        status=status,
        evidence_summary=evidence_summary,
        discovered_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        agent=agent,
        cwe=cwe,
        endpoint=endpoint,
    )
    intel.findings.append(asdict(finding))
    _save_intel(intel)
    return _json({"stored": True, "finding_count": len(intel.findings)})


@tool
def store_attack_path(
    target: str,
    description: str,
    succeeded: bool,
    techniques: str = "",
    notes: str = "",
) -> str:
    """Record an attack path (successful or failed) for future reference.

    Args:
        target: Target domain/org identifier.
        description: What the attack path was (e.g. "BOLA on /api/users/{id}").
        succeeded: Whether the attack path led to a confirmed finding.
        techniques: Comma-separated MITRE ATT&CK technique IDs.
        notes: Additional context about why it succeeded/failed.
    """
    intel = _load_intel(target)
    path = AttackPath(
        description=description,
        succeeded=succeeded,
        techniques=[t.strip() for t in techniques.split(",") if t.strip()],
        notes=notes,
    )
    intel.attack_paths.append(asdict(path))
    if not succeeded and notes:
        intel.failed_approaches.append(f"{description}: {notes}")
    _save_intel(intel)
    return _json({"stored": True, "attack_path_count": len(intel.attack_paths)})


@tool
def store_tech_stack(
    target: str,
    tech_stack_json: str,
) -> str:
    """Store or update the detected tech stack for a target.

    Args:
        target: Target domain/org identifier.
        tech_stack_json: JSON object with tech stack info, e.g.
            ``{"language": "python", "framework": "django", "server": "nginx",
              "database": "postgresql", "auth": "jwt"}``.
    """
    try:
        stack = json.loads(tech_stack_json)
    except json.JSONDecodeError as e:
        return _json({"error": f"invalid JSON: {e}"})

    intel = _load_intel(target)
    intel.tech_stack.update(stack)
    _save_intel(intel)
    return _json({"stored": True, "tech_stack": intel.tech_stack})


@tool
def close_engagement_intel(target: str, notes: str = "") -> str:
    """Mark the current engagement as complete and increment the counter.

    Call this at the END of an engagement to update the engagement count
    and add any closing notes for future reference.
    """
    intel = _load_intel(target)
    intel.engagement_count += 1
    intel.last_engagement = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    if notes:
        intel.notes = notes
    _save_intel(intel)
    return _json(
        {
            "engagement_count": intel.engagement_count,
            "total_findings": len(intel.findings),
            "total_attack_paths": len(intel.attack_paths),
        }
    )


# ── Tools: OSINT Feed Cross-Reference ──────────────────────────────────

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
GHSA_API_URL = "https://api.github.com/advisories"
_KEV_TIMEOUT = httpx.Timeout(15.0, connect=5.0)


@tool
def kev_check_tech_stack(tech_components: str) -> str:
    """Check CISA Known Exploited Vulnerabilities for a target's tech stack.

    Cross-references detected technology components (product names,
    versions) against the full CISA KEV catalog to find actively
    exploited CVEs that affect the target's stack.

    Args:
        tech_components: Comma-separated product names to check, e.g.
            ``"apache httpd 2.4,wordpress 6.2,php 8.1,jquery 3.6"``.
    """
    components = [c.strip().lower() for c in tech_components.split(",") if c.strip()]
    if not components:
        return _json({"error": "no components provided"})

    try:
        resp = httpx.get(CISA_KEV_URL, timeout=_KEV_TIMEOUT)
        resp.raise_for_status()
        kev_data = resp.json()
    except (httpx.HTTPError, json.JSONDecodeError) as e:
        log.warning("CISA KEV fetch failed: %s", e)
        return _json({"error": f"CISA KEV fetch failed: {e}", "components": components})

    vulns = kev_data.get("vulnerabilities", [])
    matches: list[dict[str, Any]] = []

    for vuln in vulns:
        vendor = (vuln.get("vendorProject") or "").lower()
        product = (vuln.get("product") or "").lower()
        vuln_name = f"{vendor} {product}"

        for comp in components:
            comp_parts = comp.split()
            comp_name = " ".join(comp_parts[:-1]) if len(comp_parts) > 1 else comp
            if (
                (comp_name and comp_name in vuln_name)
                or (product and product in comp)
                or (vendor and vendor in comp)
            ):
                matches.append(
                    {
                        "cve_id": vuln.get("cveID", ""),
                        "vendor": vuln.get("vendorProject", ""),
                        "product": vuln.get("product", ""),
                        "vulnerability_name": vuln.get("vulnerabilityName", ""),
                        "date_added": vuln.get("dateAdded", ""),
                        "due_date": vuln.get("dueDate", ""),
                        "required_action": vuln.get("requiredAction", ""),
                        "matched_component": comp,
                        "known_ransomware": vuln.get("knownRansomwareCampaignUse", "Unknown"),
                    }
                )

    return _json(
        {
            "components_checked": components,
            "kev_matches": matches[:50],
            "total_matches": len(matches),
            "kev_catalog_size": len(vulns),
        }
    )


@tool
def ghsa_check_packages(packages: str) -> str:
    """Check GitHub Security Advisories for specific packages.

    Queries the GitHub Advisory Database for known vulnerabilities
    affecting the listed packages.

    Args:
        packages: Comma-separated ``ecosystem:package`` pairs, e.g.
            ``"npm:express,pip:django,npm:lodash"``.
    """
    pairs = [p.strip() for p in packages.split(",") if p.strip()]
    if not pairs:
        return _json({"error": "no packages provided"})

    gh_token = os.environ.get("GITHUB_TOKEN", "")
    headers: dict[str, str] = {"Accept": "application/vnd.github+json"}
    if gh_token:
        headers["Authorization"] = f"Bearer {gh_token}"

    all_advisories: list[dict[str, Any]] = []

    for pair in pairs[:10]:
        parts = pair.split(":", 1)
        if len(parts) != 2:
            continue
        ecosystem, package = parts[0].strip(), parts[1].strip()

        try:
            resp = httpx.get(
                GHSA_API_URL,
                params={
                    "ecosystem": ecosystem,
                    "package": package,
                    "severity": "critical,high",
                    "per_page": "10",
                },
                headers=headers,
                timeout=_KEV_TIMEOUT,
            )
            if resp.status_code == 200:
                for adv in resp.json():
                    all_advisories.append(
                        {
                            "ghsa_id": adv.get("ghsa_id", ""),
                            "cve_id": adv.get("cve_id", ""),
                            "summary": adv.get("summary", ""),
                            "severity": adv.get("severity", ""),
                            "published_at": adv.get("published_at", ""),
                            "package": pair,
                            "cvss_score": (adv.get("cvss", {}) or {}).get("score"),
                        }
                    )
        except httpx.HTTPError as e:
            log.warning("GHSA fetch failed for %s: %s", pair, e)

    return _json(
        {
            "packages_checked": pairs[:10],
            "advisories": all_advisories[:30],
            "total_advisories": len(all_advisories),
        }
    )


# ── Public tool list ────────────────────────────────────────────────────

ENGAGEMENT_INTEL_TOOLS = [
    recall_target_intel,
    store_finding_intel,
    store_attack_path,
    store_tech_stack,
    close_engagement_intel,
    kev_check_tech_stack,
    ghsa_check_packages,
]
