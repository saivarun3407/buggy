"""Normalize assessment prerequisites without asserting availability or authority."""

from __future__ import annotations

import json
import re
import unicodedata
from typing import Any

MAX_ASSESSMENT_CONTRACT_BYTES = 16_384
_MAX_LIST_ENTRIES = 64
_MAX_TEXT_BYTES = 256
_CAPABILITY_ID = re.compile(r"[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*")
_VERIFICATION_MODES = {"bounded_observation", "artifact_review", "reviewer_attestation"}
_LIST_FIELDS = (
    "asset_types",
    "required_capabilities",
    "required_roles",
    "input_artifacts",
    "output_artifacts",
    "standard_refs",
)
_FIELDS = frozenset(_LIST_FIELDS) | {
    "version",
    "source_required",
    "verification_mode",
    "approval_required",
}


class AssessmentContractError(ValueError):
    """Assessment prerequisite metadata is malformed or exceeds its bounds."""


def _normalize_list(value: object, field: str) -> list[str]:
    if not isinstance(value, list) or len(value) > _MAX_LIST_ENTRIES:
        raise AssessmentContractError(
            f"assessment_contract.{field} must be a list of at most 64 strings"
        )
    normalized: list[str] = []
    for entry in value:
        if not isinstance(entry, str) or not entry.strip() or len(entry) > _MAX_TEXT_BYTES:
            raise AssessmentContractError(
                f"assessment_contract.{field} requires nonempty bounded strings"
            )
        if any(
            unicodedata.category(char).startswith("C") or char in "\u2028\u2029" for char in entry
        ):
            raise AssessmentContractError(
                f"assessment_contract.{field} contains control characters"
            )
        if len(entry.encode("utf-8")) > _MAX_TEXT_BYTES:
            raise AssessmentContractError(f"assessment_contract.{field} string exceeds 256 bytes")
        normalized.append(entry.strip())
    return list(dict.fromkeys(normalized))


def normalize_assessment_contract(value: object) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != _FIELDS:
        raise AssessmentContractError("assessment_contract must contain exactly the v1 fields")
    if type(value["version"]) is not int or value["version"] != 1:
        raise AssessmentContractError("assessment_contract.version must be the integer 1")
    if any(type(value[field]) is not bool for field in ("source_required", "approval_required")):
        raise AssessmentContractError(
            "assessment_contract source_required and approval_required must be bools"
        )
    mode = value["verification_mode"]
    if not isinstance(mode, str) or mode not in _VERIFICATION_MODES:
        raise AssessmentContractError("assessment_contract.verification_mode is not supported")
    normalized = dict(value)
    for field in _LIST_FIELDS:
        normalized[field] = _normalize_list(value[field], field)
    if any(not _CAPABILITY_ID.fullmatch(entry) for entry in normalized["required_capabilities"]):
        raise AssessmentContractError(
            "assessment_contract.required_capabilities must be stable identifiers"
        )
    if (
        len(json.dumps(value, sort_keys=True, separators=(",", ":")))
        > MAX_ASSESSMENT_CONTRACT_BYTES
    ):
        raise AssessmentContractError("assessment_contract exceeds 16384 bytes")
    return normalized


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    if len(dict(pairs)) != len(pairs):
        raise AssessmentContractError("assessment_contract contains duplicate fields")
    return dict(pairs)


def decode_assessment_contract(value: object) -> dict[str, Any] | None:
    if value is None:
        return None
    if not isinstance(value, str) or len(value) > MAX_ASSESSMENT_CONTRACT_BYTES:
        raise AssessmentContractError("assessment_contract_json must be a bounded JSON string")
    try:
        if len(value.encode("utf-8")) > MAX_ASSESSMENT_CONTRACT_BYTES:
            raise AssessmentContractError("assessment_contract_json exceeds 16384 bytes")
        decoded = json.loads(value, object_pairs_hook=_unique_object)
    except (json.JSONDecodeError, UnicodeError, RecursionError) as exc:
        raise AssessmentContractError("assessment_contract_json is malformed") from exc
    return normalize_assessment_contract(decoded)
