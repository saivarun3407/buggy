"""Prioritize supplied CVE assertions against a supplied CISA KEV snapshot."""

from __future__ import annotations

import re
from datetime import date, datetime, timedelta, timezone
from urllib.parse import urlsplit


class KEVInputError(ValueError):
    pass


_SOURCE = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
_ABSENCE = "Absence from this catalog does not establish safety or non-exploitability."
_WARNINGS = (
    "Supplied-artifact evaluation only; not independent vulnerability verification.",
    _ABSENCE,
    "CISA due dates are FCEB context, not automatic client remediation SLAs.",
)
_PRIORITY_REASONS = {
    "urgent": "Fresh supplied listing and affected assertion warrant urgent defensive remediation review.",
    "investigate": "Unknown applicability or missing/stale artifacts require investigation.",
    "normal": "No KEV-specific escalation; normal does not mean safe or not exploitable.",
    "not_applicable": "Only a supplied not_affected assertion supports this label; not independently verified.",
}


def _require(valid: bool, field: str) -> None:
    if not valid:
        raise KEVInputError(f"Invalid {field}")


def _text(value: object, field: str, maximum: int = 4096) -> str:
    if (
        type(value) is not str
        or not 0 < len(value) <= maximum
        or not value.strip()
        or any(ord(char) < 32 or ord(char) == 127 for char in value)
    ):
        raise KEVInputError(f"Invalid {field}")
    return value.strip()


def _choice(value: object, choices: tuple[str, ...], field: str) -> str:
    if type(value) is not str or value not in choices:
        raise KEVInputError(f"Invalid {field}")
    return value


def _items(value: object, field: str) -> list[dict]:
    if type(value) is not list:
        raise KEVInputError(f"Invalid {field}")
    _require(len(value) <= 50_000, f"{field} record limit")
    return value


def _cve(value: object) -> str:
    text = _text(value, "CVE ID", 32).upper()
    _require(re.fullmatch(r"CVE-[0-9]{4}-[0-9]{4,}", text) is not None, "CVE ID")
    return text


def _timestamp(value: object, field: str, current: datetime) -> datetime:
    text = _text(value, field, 40)
    pattern = (
        r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
        r"(?:\.[0-9]{1,6})?(?:Z|[+-](?:[01][0-9]|2[0-3]):[0-5][0-9])"
    )
    _require(re.fullmatch(pattern, text) is not None, field)
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00")).astimezone(timezone.utc)
    except (ValueError, OverflowError):
        raise KEVInputError(f"Invalid {field}") from None
    _require(parsed <= current, field)
    return parsed


def _date(value: object, field: str) -> date:
    text = _text(value, field, 10)
    _require(re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}", text) is not None, field)
    try:
        return date.fromisoformat(text)
    except ValueError:
        raise KEVInputError(f"Invalid {field}") from None


def _asset(value: object) -> None:
    text = _text(value, "asset", 8192)
    _require(text == value and not re.search(r"[\s\\]|%(?![0-9A-Fa-f]{2})", text), "asset")
    try:
        parts = urlsplit(text)
        host, port = parts.hostname or "", parts.port
    except ValueError:
        raise KEVInputError("Invalid asset") from None
    _require(parts.scheme in ("http", "https") and bool(host) and "@" not in parts.netloc, "asset")
    _require(port is None or 1 <= port <= 65535, "asset port")
    _require(
        re.fullmatch(r"(?:[A-Za-z0-9.-]+|\[[0-9A-Fa-f:.]+\])(?::[0-9]{1,5})?", parts.netloc)
        is not None,
        "asset",
    )
    if ":" not in host:
        _require(
            len(host) <= 253
            and all(
                re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
                for label in host.removesuffix(".").split(".")
            ),
            "asset host",
        )


def _catalog(catalog: dict, current: datetime) -> tuple[str, datetime, dict[str, str]]:
    _require(type(catalog) is dict, "catalog")
    version = _text(catalog.get("catalogVersion"), "catalogVersion", 32)
    _require(re.fullmatch(r"[0-9]+(?:\.[0-9]+)*", version) is not None, "catalogVersion")
    released = _timestamp(catalog.get("dateReleased"), "dateReleased", current)
    entries = _items(catalog.get("vulnerabilities"), "catalog vulnerabilities")
    count = catalog.get("count")
    _require(type(count) is int and count == len(entries), "catalog count")
    due_dates = {}
    for entry in entries:
        _require(type(entry) is dict, "catalog entry")
        cve_id = _cve(entry.get("cveID"))
        if cve_id in due_dates:
            raise KEVInputError("Duplicate catalog CVE ID")
        for field in (
            "vendorProject",
            "product",
            "vulnerabilityName",
            "shortDescription",
            "requiredAction",
        ):
            _text(entry.get(field), field)
        added, due = (
            _date(entry.get("dateAdded"), "dateAdded"),
            _date(entry.get("dueDate"), "dueDate"),
        )
        _require(added <= released.date() and due >= added, "catalog date range")
        _choice(
            entry.get("knownRansomwareCampaignUse", "Unknown"),
            ("Known", "Unknown"),
            "ransomware use",
        )
        due_dates[cve_id] = due.isoformat()
    return version, released, due_dates


def prioritize_kev(
    catalog: dict, observation: dict, *, now: datetime | None = None, max_age_days: int = 14
) -> dict:
    _require(type(max_age_days) is int and 1 <= max_age_days <= 3650, "max_age_days")
    current = now if now is not None else datetime.now(timezone.utc)
    _require(isinstance(current, datetime), "now")
    try:
        _require(current.utcoffset() is not None, "now timezone")
        current = current.astimezone(timezone.utc)
    except (ValueError, TypeError, OverflowError):
        raise KEVInputError("Invalid now") from None
    version, released, entries = _catalog(catalog, current)
    _require(type(observation) is dict, "observation")
    _require(
        type(observation.get("schema_version")) is int and observation["schema_version"] == 1,
        "schema_version",
    )
    _asset(observation.get("asset"))
    observed = _timestamp(observation.get("observed_at"), "observed_at", current)
    kind = _choice(
        observation.get("evidence_kind"),
        ("scanner_export", "vendor_advisory", "operator_attestation"),
        "evidence_kind",
    )
    items = _items(observation.get("vulnerabilities"), "observation vulnerabilities")
    age_limit = timedelta(days=max_age_days)
    intelligence_fresh = bool(entries) and current - released <= age_limit
    observation_fresh = current - observed <= age_limit
    warnings = list(_WARNINGS)
    if not entries:
        warnings.append(
            "Supplied catalog is empty; intelligence is missing and requires investigation."
        )
    if current - released > age_limit:
        warnings.append(
            "Supplied catalog is stale; obtain current intelligence before drawing conclusions."
        )
    if not observation_fresh:
        warnings.append("Observation snapshot is stale; refresh applicability evidence.")
    if not items:
        warnings.append("Observation snapshot is empty; no asset assessment can be concluded.")
    records, seen = [], set()
    for item in items:
        _require(type(item) is dict, "observation record")
        cve_id = _cve(item.get("cve_id"))
        if cve_id in seen:
            raise KEVInputError("Duplicate observation CVE ID")
        seen.add(cve_id)
        listed = cve_id in entries
        applicability = _choice(
            item.get("applicability", "unknown"),
            ("affected", "not_affected", "unknown"),
            "applicability",
        )
        basis = _choice(
            item.get("basis"), ("vendor_advisory", "scanner_result", "manual_review"), "basis"
        )
        if not intelligence_fresh or not observation_fresh:
            priority = "investigate"
        elif applicability == "not_affected":
            priority = "not_applicable"
        elif applicability == "unknown":
            priority = "investigate"
        else:
            priority = "urgent" if listed else "normal"
        assertion = (
            "Applicability is unknown; no affectedness was inferred."
            if applicability == "unknown"
            else f"Supplied {basis} assertion: {applicability}; not independently verified."
        )
        records.append(
            {
                "cve_id": cve_id,
                "kev_status": "listed" if listed else "not_listed",
                "applicability": applicability,
                "basis": basis,
                "priority": priority,
                "intelligence_fresh": intelligence_fresh,
                "observation_fresh": observation_fresh,
                "cisa_due_date": entries.get(cve_id),
                "reasons": [
                    "Listed in the supplied CISA KEV catalog." if listed else _ABSENCE,
                    assertion,
                    _PRIORITY_REASONS[priority],
                ],
            }
        )
    return {
        "schema_version": 1,
        "evaluation_mode": "supplied_artifact",
        "evaluated_at": current.isoformat(),
        "observed_at": observed.isoformat(),
        "evidence_kind": kind,
        "catalog": {
            "version": version,
            "source": _SOURCE,
            "released_at": released.isoformat(),
            "count": len(entries),
        },
        "intelligence_fresh": intelligence_fresh,
        "observation_fresh": observation_fresh,
        "warnings": warnings,
        "records": records,
    }
