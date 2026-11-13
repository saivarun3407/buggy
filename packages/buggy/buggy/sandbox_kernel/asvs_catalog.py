"""Serve the pinned, unmodified OWASP ASVS 5.0.0 release as an offline catalog."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

__all__ = ["ASVSCatalogError", "CATALOG_SHA256", "CATALOG_VERSION", "catalog", "requirements"]

CATALOG_VERSION: str = "5.0.0"
CATALOG_SHA256: str = "bcdbec214d70abcfad9284a31d4f9e5134305831d628aad3aa85d7e26626cb35"
_BUNDLE_NAME = "OWASP_Application_Security_Verification_Standard_5.0.0_en.json"
_BUNDLE_SIZE = 149_407


class ASVSCatalogError(ValueError):
    """Invalid catalog input or an unavailable or untrustworthy bundled release."""


def _validate_level(level: int) -> None:
    if type(level) is not int or level not in (1, 2, 3):
        raise ASVSCatalogError("level must be an integer from 1 to 3")


def _load_requirements() -> list[dict[str, Any]]:
    try:
        with Path(__file__).with_name(_BUNDLE_NAME).open("rb") as stream:
            raw = stream.read(_BUNDLE_SIZE + 1)
    except OSError:
        raise ASVSCatalogError("Bundled ASVS catalog is unavailable") from None
    if len(raw) != _BUNDLE_SIZE or hashlib.sha256(raw).hexdigest() != CATALOG_SHA256:
        raise ASVSCatalogError("Bundled ASVS catalog failed integrity verification")
    data = json.loads(raw)
    return [
        {
            "requirement_id": f"v{CATALOG_VERSION}-{item['Shortcode'][1:]}",
            "shortcode": item["Shortcode"],
            "chapter_id": chapter["Shortcode"],
            "chapter": chapter["Name"],
            "section_id": section["Shortcode"],
            "section": section["Name"],
            "level": int(item["L"]),
            "description": item["Description"],
        }
        for chapter in data["Requirements"]
        for section in chapter["Items"]
        for item in section["Items"]
    ]


def requirements(level: int = 2) -> list[dict[str, Any]]:
    """Return every requirement up to the selected level in official release order."""
    _validate_level(level)
    return [item for item in _load_requirements() if item["level"] <= level]


def catalog(level: int = 2, *, offset: int = 0, limit: int = 50) -> dict[str, Any]:
    """Return a page of cumulative requirements with release and pagination metadata."""
    _validate_level(level)
    if type(offset) is not int or offset < 0:
        raise ASVSCatalogError("offset must be a non-negative integer")
    if type(limit) is not int or not 1 <= limit <= 1000:
        raise ASVSCatalogError("limit must be an integer from 1 to 1000")
    all_requirements = _load_requirements()
    selected = [item for item in all_requirements if item["level"] <= level]
    end = offset + limit
    return {
        "standard": "ASVS",
        "version": CATALOG_VERSION,
        "level": level,
        "sha256": CATALOG_SHA256,
        "source_commit": "5cf9b032440be53ce345ab3c130fda46ba1ce7a2",
        "source_url": "https://github.com/OWASP/ASVS/releases/tag/v5.0.0_release",
        "attribution": "OWASP ASVS project and contributors",
        "license": "CC-BY-SA-4.0",
        "license_url": "https://creativecommons.org/licenses/by-sa/4.0/",
        "catalog_total": len(all_requirements),
        "total": len(selected),
        "cumulative_level_counts": {
            str(threshold): sum(item["level"] <= threshold for item in all_requirements)
            for threshold in (1, 2, 3)
        },
        "requirements": selected[offset:end],
        "offset": offset,
        "limit": limit,
        "next_offset": end if end < len(selected) else None,
        "has_more": end < len(selected),
        "notice": (
            "Catalog membership or plan completion does not constitute "
            "automatic control verification or OWASP certification."
        ),
    }
