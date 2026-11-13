"""SKILL.md YAML frontmatter parsing.

The corpus uses a leading ``---`` delimited YAML block followed by the
markdown body. This module isolates the parse so the validator can
report ``FrontmatterParseError`` per-file rather than crashing the
whole run on one bad file.
"""

from __future__ import annotations

import re
from collections.abc import Hashable
from typing import Any

import yaml

from buggy.skill_audit.assessment_contract import AssessmentContractError

_FRONTMATTER_RE = re.compile(
    r"^---\s*\n(.*?)\n---\s*(?:\n(.*))?\Z",
    re.DOTALL,
)


class FrontmatterParseError(ValueError):
    """Raised when a SKILL.md has no frontmatter or malformed YAML."""


class _ContractSafeLoader(yaml.SafeLoader):
    def construct_mapping(self, node: yaml.Node, deep: bool = False) -> dict[Hashable, Any]:
        if not isinstance(node, yaml.MappingNode):
            raise FrontmatterParseError("YAML mapping tag requires a mapping")
        metadata = [value for key, value in node.value if key.value == "metadata"]
        if len(metadata) > 1 and any(
            isinstance(value, yaml.MappingNode)
            and any(key.value == "assessment_contract" for key, _ in value.value)
            for value in metadata
        ):
            raise AssessmentContractError("assessment_contract has duplicate metadata blocks")
        contracts = [value for key, value in node.value if key.value == "assessment_contract"]
        if len(contracts) > 1:
            raise AssessmentContractError("assessment_contract block is duplicated")
        for contract in contracts:
            if isinstance(contract, yaml.MappingNode):
                fields = [key.value for key, _ in contract.value]
                if any(not isinstance(field, str) for field in fields) or len(set(fields)) != len(
                    fields
                ):
                    raise AssessmentContractError(
                        "assessment_contract has invalid or duplicate fields"
                    )
        return super().construct_mapping(node, deep=deep)


def parse_frontmatter(text: str) -> tuple[dict[str, Any], str]:
    """Split a SKILL.md into (frontmatter_dict, body).

    The frontmatter dict is the raw YAML mapping; nested ``metadata``
    stays nested. The body is the markdown after the closing ``---``,
    with no leading newline.
    """
    match = _FRONTMATTER_RE.match(text)
    if not match:
        raise FrontmatterParseError("no YAML frontmatter block found")
    raw_yaml, raw_body = match.group(1), match.group(2) or ""
    try:
        loader = _ContractSafeLoader(raw_yaml)
        try:
            parsed = loader.get_single_data()
        finally:
            loader.dispose()
    except yaml.YAMLError as exc:
        raise FrontmatterParseError(f"YAML parse failed: {exc}") from exc
    if parsed is None:
        return {}, raw_body
    if not isinstance(parsed, dict):
        raise FrontmatterParseError(
            f"frontmatter must be a YAML mapping, got {type(parsed).__name__}"
        )
    return parsed, raw_body
