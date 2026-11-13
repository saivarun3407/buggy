"""Bug-bounty scope ingestion — pasted program scope → enforceable RoE.

``ingest_bounty_scope`` turns a HackerOne / Bugcrowd program's scope (the
in-scope assets, out-of-scope assets, and excluded vulnerability classes
the operator copy-pastes off the program page) into the machine-enforceable
``machine_enforcement`` block of ``<workspace>/plan/roe.json``.

That single block drives BOTH RoE enforcement layers — one scope
definition, two enforcement points:

  * **Layer-1 (command parser).** ``RoEGuardrailMiddleware`` reads the
    block fresh on every tool call and refuses commands aimed at
    out-of-scope / forbidden targets.
  * **Layer-2 (sandbox network edge).** ``compile_egress_policy`` turns
    the same block into the sandbox nftables connect-allowlist + DNS
    allowlist, so a packet to an out-of-scope host cannot leave the
    sandbox even when the parser misses the target.

Writing the block in ``enforce`` mode is therefore the hard-enforcement
switch the bug-bounty workflow needs: out-of-scope hosts are blocked at
both the command parser and the network boundary. Cloud-metadata
endpoints (169.254.169.254 et al.) stay denied unless the operator
explicitly opts in.
"""

from __future__ import annotations

import json
import os
import re
import time
from pathlib import Path
from typing import Any

from langchain_core.tools import tool

from buggy.middleware.egress import compile_egress_policy
from buggy.tools.research.bounty_intake import SCANNER_COMMAND_PATTERNS
from buggy_core.types.roe import (
    MAX_INTER_REQUEST_DELAY_MS,
    EnforcementMode,
    MachineEnforcement,
)
from buggy_core.utils.logging import get_logger

log = get_logger("research.bounty_scope")

_WORKSPACE_ENV = "BUGGY_WORKSPACE_PATH"
_DEFAULT_WORKSPACE = "/workspace"

_VALID_MODES = {m.value for m in EnforcementMode}

# Best-effort asset token matcher for the freeform ``scope_text`` fallback:
# wildcard domains (``*.acme.com``), bare hostnames (``api.acme.com``), and
# IPv4 / CIDR literals. URLs are accepted and reduced to their host.
_ASSET_RE = re.compile(
    r"(?:https?://)?"
    r"(\*\.[a-z0-9.-]+"
    r"|(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}"
    r"|\d{1,3}(?:\.\d{1,3}){3}(?:/\d{1,2})?)",
    re.IGNORECASE,
)


def _workspace_path() -> Path:
    return Path(os.environ.get(_WORKSPACE_ENV) or _DEFAULT_WORKSPACE)


def _parse_json_array(raw: str) -> list[str]:
    """Parse a JSON-array string into a clean list of non-empty strings.

    Tolerant of a bare comma/space separated string too, since operators
    sometimes paste ``a.com, b.com`` instead of a JSON array.
    """
    raw = (raw or "").strip()
    if not raw:
        return []
    try:
        data = json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        data = [tok for tok in re.split(r"[,\s]+", raw) if tok]
    if isinstance(data, str):
        data = [data]
    if not isinstance(data, list):
        return []
    out: list[str] = []
    for item in data:
        token = str(item).strip().rstrip("/")
        if token:
            out.append(token)
    return out


def _normalize_asset(token: str) -> str:
    """Reduce a URL / host token to the bare host or CIDR, lowercased."""
    token = token.strip().lower()
    token = re.sub(r"^https?://", "", token)
    # Keep CIDR/IP intact; otherwise drop any path/query/port.
    if "/" in token and not re.match(r"^\d{1,3}(?:\.\d{1,3}){3}/\d{1,2}$", token):
        token = token.split("/", 1)[0]
    token = token.split("?", 1)[0]
    if ":" in token and not token.startswith("["):
        host, _, port = token.rpartition(":")
        if port.isdigit():
            token = host
    return token.rstrip(".")


def _extract_assets(text: str) -> list[str]:
    seen: dict[str, None] = {}
    for match in _ASSET_RE.finditer(text or ""):
        token = _normalize_asset(match.group(1))
        if token and token not in seen:
            seen[token] = None
    return list(seen)


def _dedupe(tokens: list[str]) -> list[str]:
    seen: dict[str, None] = {}
    for tok in tokens:
        norm = _normalize_asset(tok)
        if norm and norm not in seen:
            seen[norm] = None
    return list(seen)


def _normalize_class(cls: str) -> str:
    return cls.strip().lower().replace(" ", "-").replace("_", "-")


def _scope_rules(patterns: list[str]) -> list[dict[str, str]]:
    return [{"target": pat, "type": "auto"} for pat in patterns]


@tool
def ingest_bounty_scope(
    in_scope: str = "[]",
    out_of_scope: str = "[]",
    excluded_classes: str = "[]",
    platform: str = "hackerone",
    program_handle: str = "",
    program_url: str = "",
    mode: str = "enforce",
    allow_cloud_metadata: bool = False,
    scope_text: str = "",
    no_automated_tools: bool = False,
    forbidden_command_patterns: str = "[]",
    min_inter_request_delay_ms: int = 0,
    max_concurrent_connections: int = 0,
) -> str:
    """Ingest a bug-bounty program's scope and hard-enforce it via the RoE.

    WHEN TO USE: At the very start of a bug-bounty engagement, as soon as
    the operator pastes a HackerOne / Bugcrowd program's scope. Extract the
    in-scope assets, out-of-scope assets, and excluded vulnerability classes
    from the pasted policy and pass them here. This writes the engagement's
    machine-enforceable Rules of Engagement so every later agent is blocked
    from touching anything out of scope — at both the command parser and the
    sandbox network edge.

    Run this BEFORE any recon or testing. Until it runs (in ``enforce``
    mode) the engagement is audit-only and nothing is network-restricted.

    Args:
        in_scope: JSON array of in-scope assets — domains, wildcard domains,
            IPs, or CIDRs. Example: ``'["*.example.com", "api.example.com",
            "203.0.113.0/24"]'``.
        out_of_scope: JSON array of explicitly out-of-scope assets. The
            denylist takes precedence over the allowlist.
            Example: ``'["blog.example.com", "*.test.example.com"]'``.
        excluded_classes: JSON array of vulnerability classes the program
            does not accept (stored for ``bounty_scope_check`` and report
            metadata). Example: ``'["dos", "self-xss", "clickjacking"]'``.
        platform: ``hackerone`` or ``bugcrowd`` (report-format metadata).
        program_handle: Program handle / slug (e.g. ``"acme"``).
        program_url: URL of the program's policy / scope page.
        mode: RoE enforcement mode — ``enforce`` (block + log, recommended),
            ``warn`` (log + warn, proceed), or ``audit`` (log only).
        allow_cloud_metadata: When ``False`` (default) the cloud-metadata
            endpoints (169.254.169.254 etc.) stay force-denied even if an
            over-broad wildcard would otherwise allow them. Only set ``True``
            if the program explicitly authorises metadata-service testing.
        scope_text: Optional raw pasted scope text. Used only as a
            best-effort fallback to populate ``in_scope`` when the JSON
            array is empty — always prefer passing structured arrays.
        no_automated_tools: Set ``True`` when the program forbids automated
            scanning. Expands a curated set of scanner command regexes into
            ``forbidden_command_patterns`` so the command parser refuses to
            launch them (nuclei, sqlmap, gobuster, ffuf, ZAP, …).
        forbidden_command_patterns: JSON array of extra regex patterns to
            block at the command parser (merged with the curated scanner set
            when ``no_automated_tools`` is true). Example:
            ``'["(?i)\\bmasscan\\b"]'``.
        min_inter_request_delay_ms: Minimum delay between requests, in
            milliseconds, when the program states a request-rate cap (e.g. a
            10 req/s cap → ``100``). ``0`` leaves it unset. Values above
            one hour (3,600,000 ms) are rejected without writing the policy.
        max_concurrent_connections: Cap on concurrent connections when the
            program limits parallelism. ``0`` leaves it unset.

    Returns:
        JSON with the resolved scope, the path to the written ``roe.json``,
        a preview of the compiled sandbox egress policy, and any warnings.
    """
    warnings: list[str] = []

    mode_norm = (mode or "").strip().lower()
    if mode_norm not in _VALID_MODES:
        warnings.append(f"unknown mode {mode!r}; defaulting to 'enforce'")
        mode_norm = EnforcementMode.ENFORCE.value

    in_scope_assets = _dedupe(_parse_json_array(in_scope))
    out_scope_assets = _dedupe(_parse_json_array(out_of_scope))

    if not in_scope_assets and scope_text:
        extracted = _extract_assets(scope_text)
        # Drop anything that also appears out of scope.
        out_set = set(out_scope_assets)
        in_scope_assets = [a for a in extracted if a not in out_set]
        if in_scope_assets:
            warnings.append(
                "in_scope was empty — populated it by extracting assets from "
                "scope_text. Verify the list before testing; the text parser "
                "is best-effort and may miss or over-match assets."
            )

    excluded = sorted({_normalize_class(c) for c in _parse_json_array(excluded_classes)})

    if not in_scope_assets:
        warnings.append(
            "no in-scope assets resolved — RoE will not constrain targets to an "
            "allowlist. Pass the program's in-scope domains/IPs as a JSON array."
        )
    if mode_norm == EnforcementMode.ENFORCE.value and not in_scope_assets:
        warnings.append(
            "enforce mode with an empty allowlist does NOT default-drop egress; "
            "out-of-scope denies still apply but any host not explicitly denied "
            "remains reachable. Provide in-scope assets for a tight boundary."
        )

    forbidden_patterns: list[str] = list(_parse_json_array(forbidden_command_patterns))
    if no_automated_tools:
        forbidden_patterns = list(SCANNER_COMMAND_PATTERNS) + forbidden_patterns
    # De-dupe while preserving order.
    forbidden_patterns = list(dict.fromkeys(p for p in forbidden_patterns if p))

    delay_ms = max(0, int(min_inter_request_delay_ms or 0))
    if delay_ms > MAX_INTER_REQUEST_DELAY_MS:
        return json.dumps(
            {
                "error": "invalid_min_inter_request_delay",
                "detail": (
                    "min_inter_request_delay_ms must not exceed "
                    f"{MAX_INTER_REQUEST_DELAY_MS}; RoE policy was not changed"
                ),
                "hard_enforced": False,
                "roe_path": None,
            }
        )
    max_conn = int(max_concurrent_connections or 0)

    machine_enforcement: dict[str, Any] = {
        "mode": mode_norm,
        "in_scope": _scope_rules(in_scope_assets),
        "out_of_scope": _scope_rules(out_scope_assets),
        "allow_cloud_metadata": bool(allow_cloud_metadata),
        "forbidden_command_patterns": forbidden_patterns,
        "min_inter_request_delay_ms": delay_ms,
    }
    if max_conn > 0:
        machine_enforcement["max_concurrent_connections"] = max_conn

    bounty_meta: dict[str, Any] = {
        "platform": (platform or "hackerone").strip().lower(),
        "program_handle": program_handle.strip(),
        "program_url": program_url.strip(),
        "excluded_classes": excluded,
        "ingested_at": time.time(),
    }

    # Merge into any existing roe.json so we never clobber Soundwave's
    # human-readable in_scope / out_of_scope / prohibited_actions prose.
    workspace = _workspace_path()
    roe_path = workspace / "plan" / "roe.json"
    existing: dict[str, Any] = {}
    if roe_path.exists():
        try:
            loaded = json.loads(roe_path.read_text(encoding="utf-8"))
            if isinstance(loaded, dict):
                existing = loaded
        except (OSError, json.JSONDecodeError) as exc:
            warnings.append(f"could not read existing roe.json ({exc}); overwriting")

    existing["machine_enforcement"] = machine_enforcement
    existing["bounty"] = bounty_meta
    # Mirror the assets into the human-readable arrays when absent so the
    # operator-facing RoE and the enforced RoE agree.
    existing.setdefault("in_scope", in_scope_assets)
    existing.setdefault("out_of_scope", out_scope_assets)

    wrote = True
    try:
        roe_path.parent.mkdir(parents=True, exist_ok=True)
        roe_path.write_text(json.dumps(existing, indent=2, sort_keys=False), encoding="utf-8")
    except OSError as exc:
        wrote = False
        warnings.append(f"failed to write roe.json: {exc}")
        log.warning("ingest_bounty_scope: write failed: %s", exc)

    # Compile the egress policy from the same block so the operator can see
    # exactly what the sandbox network boundary will enforce.
    rules = MachineEnforcement.from_dict(machine_enforcement)
    policy = compile_egress_policy(rules)
    egress_preview = {
        "enforce": policy.enforce,
        "default_drop": policy.default_drop,
        "allowed_hosts": list(policy.allowed_hosts),
        "allowed_cidrs": list(policy.allowed_cidrs),
        "denied_hosts": list(policy.denied_hosts),
        "denied_cidrs": list(policy.denied_cidrs),
    }

    return json.dumps(
        {
            "roe_path": str(roe_path) if wrote else None,
            "mode": mode_norm,
            "in_scope": in_scope_assets,
            "out_of_scope": out_scope_assets,
            "excluded_classes": excluded,
            "platform": bounty_meta["platform"],
            "program_handle": bounty_meta["program_handle"],
            "forbidden_command_patterns": forbidden_patterns,
            "min_inter_request_delay_ms": delay_ms,
            "max_concurrent_connections": max_conn or None,
            "egress_policy": egress_preview,
            "hard_enforced": mode_norm == EnforcementMode.ENFORCE.value and wrote,
            "warnings": warnings,
        },
        indent=2,
    )


BOUNTY_SCOPE_TOOLS = [ingest_bounty_scope]
