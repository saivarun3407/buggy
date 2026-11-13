"""Assessment prerequisites survive graph compilation without granting authority."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest
import yaml
from fastapi.testclient import TestClient

from buggy.middleware.skillogy import SkillogyMiddleware
from buggy.skill_audit.assessment_contract import AssessmentContractError
from buggy.skill_audit.frontmatter import FrontmatterParseError, parse_frontmatter
from buggy.skill_audit.rules import RuleId, validate_skill_file
from buggy.skillogy.builder.emit import cypher_literal, emit_cypher
from buggy.skillogy.builder.skills import emit_skill_records
from buggy.skillogy.server.app import build_app
from buggy.skillogy.server.neo4j_backend import Neo4jBackend
from tests.unit.skillogy.conftest import SkillGraphDriver

BUILT_AT = datetime(2026, 9, 5, tzinfo=timezone.utc)
BODY = "# Bounded inventory\n\nReview the approved asset list.\n"
CONTRACT = {
    "version": 1,
    "asset_types": ["host"],
    "required_capabilities": ["network-inventory", "approved-browser-session"],
    "required_roles": ["recon"],
    "source_required": False,
    "input_artifacts": ["approved-assets.json"],
    "output_artifacts": ["inventory.json"],
    "verification_mode": "bounded_observation",
    "approval_required": True,
    "standard_refs": ["NIST SP 800-115"],
}


def skill_text(**metadata: Any) -> str:
    frontmatter = {
        "name": "bounded-inventory",
        "description": "Review bounded network inventory",
        "allowed-tools": ["read_file"],
        "metadata": {
            "subdomain": "reconnaissance",
            "when_to_use": "network inventory",
            "mitre_attack": ["T1595"],
            **metadata,
        },
    }
    return "---\n" + yaml.safe_dump(frontmatter) + "---\n" + BODY


def build_skill(tmp_path: Path, text: str) -> tuple[list[Any], list[Any]]:
    skill_dir = tmp_path / "standard/recon/bounded-inventory"
    skill_dir.mkdir(parents=True, exist_ok=True)
    (skill_dir / "SKILL.md").write_text(text, encoding="utf-8")
    return emit_skill_records(tmp_path, commit_sha="fixture-commit", built_at=BUILT_AT)


def test_builder_stores_normalized_contract_as_canonical_json_with_provenance(
    tmp_path: Path,
) -> None:
    authored = CONTRACT | {"asset_types": [" host ", "host"]}
    nodes, edges = build_skill(tmp_path, skill_text(assessment_contract=authored))
    props = next(node.properties for node in nodes if node.label == "Skill")
    encoded = json.dumps(CONTRACT, sort_keys=True, separators=(",", ":"))
    assert props["assessment_contract_json"] == encoded
    assert not any(isinstance(value, dict) for value in props.values())
    assert f"n.assessment_contract_json = {cypher_literal(encoded)}" in emit_cypher(nodes, edges)
    assert props["allowed_tools"] == ["read_file"]
    assert props["when_to_use"] == "network inventory"
    assert props["content_sha256"] == "sha256:" + hashlib.sha256(BODY.encode()).hexdigest()
    assert props["commit_sha"] == "fixture-commit"
    assert props["built_at"] == BUILT_AT.isoformat()
    assert props["body"] == BODY
    assert authored["asset_types"] == [" host ", "host"]


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("version", True),
        ("version", 1.0),
        ("version", "1"),
        ("version", 2),
        ("asset_types", "host"),
        ("required_capabilities", {"network-inventory": True}),
        ("required_capabilities", ["execute arbitrary tools"]),
        ("required_roles", [False]),
        ("input_artifacts", [None]),
        ("input_artifacts", [42]),
        ("input_artifacts", [""]),
        ("input_artifacts", ["   "]),
        ("output_artifacts", [["nested"]]),
        ("source_required", 1),
        ("source_required", "false"),
        ("source_required", None),
        ("approval_required", 0),
        ("approval_required", "true"),
        ("approval_required", []),
        ("verification_mode", "execute"),
        ("verification_mode", None),
        ("verification_mode", ["artifact_review"]),
        ("standard_refs", ["reference\n"]),
        ("standard_refs", ["reference\x00"]),
        ("standard_refs", ["reference\x7f"]),
        ("standard_refs", ["reference\u202e"]),
        ("standard_refs", ["reference\u200b"]),
        ("standard_refs", ["reference\ud800"]),
        ("standard_refs", ["reference\u2028"]),
        ("asset_types", ["x" * 257]),
        ("asset_types", ["host"] * 65),
        ("standard_refs", [str(index) + "x" * 250 for index in range(64)]),
    ],
)
def test_malformed_contract_is_rejected_by_audit_and_builder(
    tmp_path: Path, field: str, value: object
) -> None:
    text = skill_text(assessment_contract=CONTRACT | {field: value})
    with pytest.raises(AssessmentContractError):
        build_skill(tmp_path, text)
    violations = validate_skill_file("/skills/standard/recon/bounded-inventory/SKILL.md", text)
    assert len(violations) == 1
    assert violations[0].rule_id is RuleId.BAD_ASSESSMENT_CONTRACT


@pytest.mark.parametrize("mode", ["bounded_observation", "artifact_review", "reviewer_attestation"])
def test_each_verification_mode_allows_explicitly_empty_prerequisites(
    tmp_path: Path, mode: str
) -> None:
    contract = CONTRACT | {key: [] for key, value in CONTRACT.items() if isinstance(value, list)}
    contract["verification_mode"] = mode
    text = skill_text(assessment_contract=contract)
    nodes, _edges = build_skill(tmp_path, text)
    props = next(node.properties for node in nodes if node.label == "Skill")
    assert json.loads(props["assessment_contract_json"]) == contract
    assert validate_skill_file("/skills/standard/recon/review/SKILL.md", text) == []


@pytest.mark.parametrize(
    "contract",
    [None, {}, [], "", CONTRACT | {"available_capabilities": ["tls-inspection"]}]
    + [{key: value for key, value in CONTRACT.items() if key != missing} for missing in CONTRACT],
)
def test_present_but_null_partial_or_unknown_contract_is_not_legacy(
    tmp_path: Path, contract: object
) -> None:
    text = skill_text(assessment_contract=contract)
    with pytest.raises(AssessmentContractError):
        build_skill(tmp_path, text)
    violations = validate_skill_file("/skills/standard/recon/review/SKILL.md", text)
    assert len(violations) == 1
    assert violations[0].rule_id is RuleId.BAD_ASSESSMENT_CONTRACT


def test_legacy_search_does_not_invent_assessment_prerequisites_or_missing_provenance(
    make_backend: Callable[[SkillGraphDriver], Neo4jBackend],
) -> None:
    backend = make_backend(
        SkillGraphDriver([{"name": "legacy", "path": "/skills/shared/legacy/SKILL.md"}])
    )
    hit = backend.find_skill(query="legacy")[0]
    assert hit["assessment_contract"] is None
    for field in ("allowed_tools", "when_to_use", "content_sha256", "commit_sha", "built_at"):
        assert hit[field] is None


def test_legacy_build_explicitly_clears_removed_contract_without_changing_body(
    tmp_path: Path,
) -> None:
    text = skill_text()
    nodes, edges = build_skill(tmp_path, text)
    props = next(node.properties for node in nodes if node.label == "Skill")
    assert props["assessment_contract_json"] is None
    assert "n.assessment_contract_json = null" in emit_cypher(nodes, edges)
    assert props["body"] == BODY
    assert validate_skill_file("/skills/standard/recon/legacy/SKILL.md", text) == []


@pytest.mark.parametrize("query", [None, "network inventory", "inspect approved assets"])
def test_find_exposes_prerequisites_and_provenance_without_widening_acl_or_load_body(
    tmp_path: Path,
    make_backend: Callable[[SkillGraphDriver], Neo4jBackend],
    query: str | None,
) -> None:
    nodes, _edges = build_skill(tmp_path, skill_text(assessment_contract=CONTRACT))
    props = next(node.properties for node in nodes if node.label == "Skill")
    props["embedding"] = [1.0, 0.0]
    outside = props | {"name": "outside", "path": "/skills/standard/exploit/review/SKILL.md"}
    driver = SkillGraphDriver([outside, props])
    driver.query_vectors["inspect approved assets"] = [1.0, 0.0]
    backend = make_backend(driver)
    prefixes = ["/skills/standard/recon/", "/skills/shared/"]
    filters = {"query": query, "subdomain": "reconnaissance"}
    with TestClient(build_app(backend, api_key="")) as client:
        response = client.post(
            "/v1/skills:find", json=filters | {"allowed_path_prefixes": prefixes}
        )
    assert response.status_code == 200
    payload = response.json()
    assert payload["count"] == 1
    hit = payload["hits"][0]
    assert hit["assessment_contract"] == CONTRACT
    assert "assessment_contract_json" not in hit
    assert "body" not in hit and "embedding" not in hit
    for field in ("allowed_tools", "when_to_use", "content_sha256", "commit_sha", "built_at"):
        assert hit[field] == props[field]
    middleware = SkillogyMiddleware(
        backend=backend, append_policy_to_system=False, allowed_path_prefixes=prefixes
    )
    tools = {tool.name: tool for tool in middleware.tools}
    assert json.loads(tools["find_skill"].invoke(filters)) == payload
    body = tools["load_skill"].invoke({"name_or_path": props["path"]})
    assert body == (
        "Base directory for this skill: /skills/standard/recon/bounded-inventory\n"
        "Skill: bounded-inventory — Review bounded network inventory\n\n" + BODY
    )
    assert backend.load_skill(outside["path"], allowed_path_prefixes=prefixes) is None
    assert backend.load_skill("outside", allowed_path_prefixes=prefixes) is None


@pytest.mark.parametrize(
    "encoded",
    [
        "{",
        "",
        1,
        True,
        {},
        [],
        json.dumps(CONTRACT) + " " * 16_385,
        json.dumps(CONTRACT).replace('"version": 1', '"version": 2, "version": 1'),
        "[" * 2000 + "]" * 2000,
    ],
)
def test_find_rejects_corrupt_graph_contracts_with_the_named_error(
    make_backend: Callable[[SkillGraphDriver], Neo4jBackend], encoded: object
) -> None:
    driver = SkillGraphDriver(
        [
            {
                "name": "review",
                "path": "/skills/shared/review/SKILL.md",
                "assessment_contract_json": encoded,
            }
        ]
    )
    with pytest.raises(AssessmentContractError):
        make_backend(driver).find_skill(query="review")


@pytest.mark.parametrize("tagged", ["!!map [a, b]", "!!map scalar"])
def test_invalid_yaml_mapping_tags_keep_named_parse_failures(tagged: str) -> None:
    with pytest.raises(FrontmatterParseError):
        parse_frontmatter("---\nmetadata: " + tagged + "\n---\nbody\n")


def test_unknown_assessment_contract_field_has_a_distinct_audit_violation() -> None:
    text = (
        "---\n"
        "name: defensive-review\n"
        "description: Review supplied artifacts\n"
        "metadata:\n"
        "  subdomain: analyst\n"
        "  when_to_use: artifact review\n"
        "  assessment_contract:\n"
        "    version: 1\n"
        "    grants_tools: true\n"
        "---\n"
        "Review artifacts only.\n"
    )
    violations = validate_skill_file("/skills/standard/analyst/review/SKILL.md", text)
    assert len(violations) == 1
    assert violations[0].rule_id.value == "R-bad-assessment-contract"
    assert "assessment_contract" in violations[0].detail


@pytest.mark.parametrize("duplicate", ["approval_required", "assessment_contract", "metadata"])
def test_duplicate_yaml_fields_cannot_override_assessment_prerequisites(
    tmp_path: Path, duplicate: str
) -> None:
    text = skill_text(assessment_contract=CONTRACT)
    if duplicate == "approval_required":
        text = text.replace(
            "    approval_required: true",
            "    approval_required: false\n    approval_required: true",
        )
    elif duplicate == "assessment_contract":
        text = text.replace(
            "  assessment_contract:\n", "  assessment_contract: null\n  assessment_contract:\n"
        )
    else:
        text = text.replace("metadata:\n", "metadata: {}\nmetadata:\n")
    with pytest.raises(AssessmentContractError):
        build_skill(tmp_path, text)
    violations = validate_skill_file("/skills/standard/recon/bounded-inventory/SKILL.md", text)
    assert len(violations) == 1
    assert violations[0].rule_id is RuleId.BAD_ASSESSMENT_CONTRACT
