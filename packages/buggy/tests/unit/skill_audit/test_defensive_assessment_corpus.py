"""Keep defensive product skills discoverable without adding execution grants."""

from __future__ import annotations

import ast
import re
from datetime import datetime, timezone
from pathlib import Path

import pytest
from pydantic import BaseModel

from buggy.agents.middleware_slots import skills_sources_for
from buggy.sandbox_kernel.asvs_catalog import catalog as asvs_catalog
from buggy.sandbox_kernel.threat_scenarios import list_scenarios
from buggy.skill_audit.assessment_contract import (
    decode_assessment_contract,
    normalize_assessment_contract,
)
from buggy.skill_audit.cli import scan_corpus
from buggy.skill_audit.frontmatter import parse_frontmatter
from buggy.skill_audit.rules import validate_skill_file
from buggy.skillogy.builder.model import Node
from buggy.skillogy.builder.skills import emit_skill_records
from buggy.tools.assessment import ASSESSMENT_TOOLS

SKILLS_ROOT = Path(__file__).resolve().parents[3] / "buggy" / "skills"
PACK_ROOT = SKILLS_ROOT / "shared" / "defensive-assessment"
SCENARIO_SKILLS = {
    "oauth-consent-review": ("saas.oauth-consent",),
    "mfa-enrollment-review": ("identity.mfa-enrollment", "identity.phishing-resistant-mfa"),
    "saas-guest-access-review": ("saas.guest-access",),
    "session-revocation-review": ("session.revocation",),
    "export-detection-review": ("detection.saas-export",),
}
SKILLS = (
    "authenticated-surface-review",
    "authorization-evidence-matrix",
    *SCENARIO_SKILLS,
    "remediation-retest",
)
CONTRACT_LISTS = {
    "asset_types",
    "required_capabilities",
    "required_roles",
    "input_artifacts",
    "output_artifacts",
    "standard_refs",
}
CONTRACT_FIELDS = CONTRACT_LISTS | {
    "version",
    "source_required",
    "verification_mode",
    "approval_required",
}
CAPABILITIES = {
    "network-inventory",
    "dns-inventory",
    "tls-inspection",
    "http-capture-review",
    "sarif-review",
}


def _example_calls(body: str) -> list[tuple[str, dict[str, object]]]:
    calls = []
    for snippet in re.findall(r"`(assessment_[a-z_]+\([^`\n]*\))`", body):
        call = ast.parse(snippet, mode="eval").body
        assert isinstance(call, ast.Call) and isinstance(call.func, ast.Name)
        assert not call.args
        arguments = {}
        for keyword in call.keywords:
            assert keyword.arg is not None
            arguments[keyword.arg] = ast.literal_eval(keyword.value)
        calls.append((call.func.id, arguments))
    return calls


@pytest.fixture(scope="module")
def skill_nodes() -> list[Node]:
    assert {path for path in PACK_ROOT.rglob("*") if path.is_file()} == {
        PACK_ROOT / slug / "SKILL.md" for slug in SKILLS
    }
    report = scan_corpus(PACK_ROOT)
    assert report.files_scanned == len(SKILLS)
    assert report.violations == []
    nodes, _edges = emit_skill_records(
        SKILLS_ROOT, built_at=datetime(2026, 9, 5, tzinfo=timezone.utc)
    )
    return [node for node in nodes if node.label == "Skill"]


@pytest.mark.parametrize("slug", SKILLS)
def test_shared_defensive_skill_is_discoverable_without_tool_grants(
    slug: str, skill_nodes: list[Node]
) -> None:
    path = PACK_ROOT / slug / "SKILL.md"
    text = path.read_text(encoding="utf-8")
    meta, body = parse_frontmatter(text)
    assert validate_skill_file(str(path), text) == []
    assert len(text.splitlines()) < 100
    assert meta["name"] == f"defensive-{slug}"
    assert meta["allowed-tools"] == []
    assert "allowed_tools" not in meta
    contract = meta["metadata"]["assessment_contract"]
    assert set(contract) == CONTRACT_FIELDS
    assert type(contract["version"]) is int and contract["version"] == 1
    for field in CONTRACT_LISTS:
        assert isinstance(contract[field], list)
        assert all(isinstance(value, str) and value.strip() for value in contract[field])
        assert len(contract[field]) == len(set(contract[field]))
    assert set(contract["required_capabilities"]) <= CAPABILITIES
    assert contract["required_roles"] == []
    assert contract["source_required"] is False
    assert contract["approval_required"] is True
    assert contract["verification_mode"] in {"artifact_review", "reviewer_attestation"}
    assert contract["input_artifacts"] and contract["output_artifacts"]
    assert contract["asset_types"] and contract["standard_refs"]
    matching = [node for node in skill_nodes if node.key == meta["name"]]
    assert len(matching) == 1
    skill = matching[0].properties
    assert skill["path"] == f"/skills/shared/defensive-assessment/{slug}/SKILL.md"
    assert skill["body"] == body
    assert normalize_assessment_contract(contract) == contract
    assert decode_assessment_contract(skill["assessment_contract_json"]) == contract
    assert skill["allowed_tools"] == []
    assert "defensive-assessment" in skill["tags_raw"]
    for role in ("buggy", "asvs_assessor", "analyst"):
        assert any(skill["path"].startswith(prefix) for prefix in skills_sources_for(role))


@pytest.mark.parametrize("slug,scenario_ids", SCENARIO_SKILLS.items())
def test_scenario_skill_reuses_versioned_ids_and_primary_sources(
    slug: str, scenario_ids: tuple[str, ...]
) -> None:
    meta, body = parse_frontmatter((PACK_ROOT / slug / "SKILL.md").read_text(encoding="utf-8"))
    catalog = list_scenarios()
    scenarios = {scenario["scenario_id"]: scenario for scenario in catalog["scenarios"]}
    assert meta["metadata"]["scenario_catalog_version"] == catalog["catalog_version"]
    assert meta["metadata"]["scenario_ids"] == list(scenario_ids)
    assert set(scenario_ids) <= scenarios.keys()
    refs = meta["metadata"]["assessment_contract"]["standard_refs"]
    for scenario_id in scenario_ids:
        assert {source["url"] for source in scenarios[scenario_id]["source_refs"]} <= set(refs)
    tools = {tool.name: tool for tool in ASSESSMENT_TOOLS}
    referenced = set(re.findall(r"\bassessment_[a-z_]+\b", body))
    assert {"assessment_scenario_catalog", "assessment_evaluate_scenario"} <= referenced
    assert referenced <= tools.keys()
    evaluated = {
        arguments["scenario_id"]
        for name, arguments in _example_calls(body)
        if name == "assessment_evaluate_scenario"
    }
    assert evaluated == set(scenario_ids)


@pytest.mark.parametrize("slug", SKILLS)
def test_asvs_references_and_call_examples_use_public_contracts(slug: str) -> None:
    meta, body = parse_frontmatter((PACK_ROOT / slug / "SKILL.md").read_text(encoding="utf-8"))
    catalog = asvs_catalog(level=3, limit=1000)
    assert catalog["version"] == "5.0.0"
    assert catalog["source_url"] in meta["metadata"]["assessment_contract"]["standard_refs"]
    qualified_ids = set(re.findall(r"\bv\d+\.\d+\.\d+-\d+\.\d+\.\d+\b", body))
    assert qualified_ids <= {row["requirement_id"] for row in catalog["requirements"]}
    tools = {tool.name: tool for tool in ASSESSMENT_TOOLS}
    examples = _example_calls(body)
    assert examples
    called = set()
    for name, arguments in examples:
        schema = tools[name].tool_call_schema
        assert not isinstance(schema, dict)
        assert issubclass(schema, BaseModel)
        assert arguments.keys() <= schema.model_json_schema()["properties"].keys()
        schema.model_validate(arguments)
        called.add(name)
    assert "assessment_asvs_catalog" in called
    if slug == "remediation-retest":
        assert {"assessment_asvs_status", "assessment_asvs_record"} <= called
