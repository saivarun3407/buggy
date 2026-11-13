from __future__ import annotations

import importlib
from types import SimpleNamespace

import pytest


def test_orchestrator_factory_exposes_the_complete_assessment_interface(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("BUGGY_PLUGINS", "assessment-test-only")
    module = importlib.import_module("buggy.agents.standard.buggy")
    from buggy.tools.assessment import ASSESSMENT_TOOLS

    def capture_agent(*args, **kwargs):
        return SimpleNamespace(with_config=lambda config: kwargs)

    monkeypatch.setattr(module, "create_agent", capture_agent)
    graph = module.create_buggy_agent(
        llm=object(), fallback_models=[], subagents=[], middleware=[], system_prompt="Fixture"
    )
    assert {tool.name for tool in ASSESSMENT_TOOLS} <= {tool.name for tool in graph["tools"]}


def test_asvs_specialists_share_assessment_review_tools(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("BUGGY_PLUGINS", "assessment-test-only")
    assessor = importlib.import_module("buggy.agents.standard.asvs_assessor")
    from buggy.agents.bounty._common import build_bounty_tools
    from buggy.tools.assessment import ASSESSMENT_REVIEW_TOOLS

    expected = {tool.name for tool in ASSESSMENT_REVIEW_TOOLS}
    assert expected <= set(assessor._STANDARD_TOOLS)
    assert expected <= {tool.name for tool in build_bounty_tools("asvs", [])}


@pytest.mark.parametrize("role", ["buggy", "asvs_assessor", "asvs"])
def test_assessment_prompts_require_explicit_coverage_review(role: str) -> None:
    from buggy.agents.prompts import load_prompt

    shared = ["bounty_workflow"] if role == "asvs" else []
    prompt = load_prompt(role, shared=shared)
    assert "assessment_status" in prompt
    assert "not full ASVS" in prompt


def test_asvs_assessor_uses_version_five_chapter_names() -> None:
    from buggy.agents.prompts import load_prompt

    prompt = load_prompt("asvs_assessor", shared=[])
    assert "V1  — Encoding and Sanitization" in prompt
    assert "V6  — Authentication" in prompt
    assert "V17 — WebRTC" in prompt
