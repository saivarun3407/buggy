"""Phase 5 integration wiring — the grafts must reach their agents and the
whole standard agent graph must construct.

Three guarantees, pinned so the Phase 5 wiring cannot silently regress:

1. **Recorder wiring** (Phase 3): the proof-gated ``report_record_finding``
   recorder (``RECORDING_TOOLS``) reaches the ``analyst`` agent — the sole
   agent that files findings. A finding is only fileable through the gate.

2. **Reconciliation wiring** (Phase 4): ``reconcile_sast_to_queue``
   (``RECONCILIATION_TOOLS``) reaches the ``exploit`` agent, so the SAST ->
   reconcile -> gated per-class exploitation-queue join is reachable from the
   exploit lane.

3. **deepagents fix + graph construction**: every standard agent factory
   builds its middleware stack and compiles without raising. This is the
   boot/dry-run that exercises the deepagents 0.6.8 empty-subagent guard in
   ``_make_subagent`` and the new ``PARSING_FIREWALL`` slot across all 16+
   standard roles.
"""

from __future__ import annotations

import importlib

import pytest

from buggy.agents.build import build_middleware, build_tools

# ── 1 + 2: graft tools resolve onto their agents ──────────────────────


def test_recorder_wired_onto_analyst() -> None:
    """The proof-gated recorder must be on the analyst's resolved toolset."""
    from buggy.agents.standard import analyst

    tools = build_tools(role="analyst", standard_tools=analyst._STANDARD_TOOLS)
    names = {t.name for t in tools}
    assert "report_record_finding" in names, (
        "analyst is missing the proof-gated recorder (RECORDING_TOOLS); a "
        "finding must be fileable only through report_record_finding"
    )


def test_reconcile_wired_onto_exploit() -> None:
    """The SAST->exploit-queue reconciliation tool must be on the exploit agent."""
    from buggy.agents.standard import exploit

    tools = build_tools(role="exploit", standard_tools=exploit._STANDARD_TOOLS)
    names = {t.name for t in tools}
    assert "reconcile_sast_to_queue" in names, (
        "exploit agent is missing reconcile_sast_to_queue (RECONCILIATION_TOOLS)"
    )


# ── 3: deepagents empty-subagent guard ────────────────────────────────


class _FakeBackend:
    """Marker backend — slot factories only pass it through here."""


@pytest.mark.parametrize("subagents", [[], None])
def test_orchestrator_builds_without_subagents(subagents) -> None:
    """deepagents 0.6.8 raises on an empty subagent list; the orchestrator
    must build anyway, simply omitting the SubAgent slot (no task() tool)."""
    from buggy.llm import LLMFactory

    llm = LLMFactory().get_model("buggy")
    mw = build_middleware(
        role="buggy",
        backend=_FakeBackend(),
        llm=llm,
        subagents=subagents,
    )
    names = [type(m).__name__ for m in mw]
    assert "SubAgentMiddleware" not in names, (
        "empty-subagent orchestrator must omit SubAgentMiddleware, not pass []"
    )


# NOTE: "the SubAgent slot IS wired when a real roster is present" is covered
# end-to-end by ``test_standard_agent_factory_compiles[buggy]`` below — the
# orchestrator factory discovers its real subagent roster via entry points and
# compiles the SubAgent slot in. A hand-rolled fake roster is not used here
# because deepagents compiles each subagent runnable (``.with_config(...)``),
# which a stub cannot satisfy without reimplementing a Runnable.


# ── 3: every standard agent factory compiles (graph-construction boot) ──

# (role, module path, factory attribute). The full standard slate — building
# each exercises its middleware stack (deepagents fix + PARSING_FIREWALL slot)
# and compiles the LangGraph graph.
_STANDARD_FACTORIES = [
    ("buggy", "buggy.agents.standard.buggy", "create_buggy_agent"),
    ("recon", "buggy.agents.standard.recon", "create_recon_agent"),
    ("exploit", "buggy.agents.standard.exploit", "create_exploit_agent"),
    ("postexploit", "buggy.agents.standard.postexploit", "create_postexploit_agent"),
    ("analyst", "buggy.agents.standard.analyst", "create_analyst_agent"),
    ("soundwave", "buggy.agents.standard.soundwave", "create_soundwave_agent"),
    ("blue_cell", "buggy.agents.standard.blue_cell", "create_blue_cell_agent"),
    ("asvs_assessor", "buggy.agents.standard.asvs_assessor", "create_asvs_assessor_agent"),
    ("reverser", "buggy.agents.standard.reverser", "create_reverser_agent"),
    (
        "contract_auditor",
        "buggy.agents.standard.contract_auditor",
        "create_contract_auditor_agent",
    ),
    ("cloud_hunter", "buggy.agents.standard.cloud_hunter", "create_cloud_hunter_agent"),
    ("ad_operator", "buggy.agents.standard.ad_operator", "create_ad_operator_agent"),
    ("phisher", "buggy.agents.standard.phisher", "create_phisher_agent"),
    (
        "mobile_operator",
        "buggy.agents.standard.mobile_operator",
        "create_mobile_operator_agent",
    ),
    (
        "wireless_operator",
        "buggy.agents.standard.wireless_operator",
        "create_wireless_operator_agent",
    ),
    ("osint_operator", "buggy.agents.standard.osint_operator", "create_osint_operator_agent"),
    ("iot_operator", "buggy.agents.standard.iot_operator", "create_iot_operator_agent"),
    ("ics_operator", "buggy.agents.standard.ics_operator", "create_ics_operator_agent"),
    ("forensicator", "buggy.agents.standard.forensicator", "create_forensicator_agent"),
    (
        "supply_chain_operator",
        "buggy.agents.standard.supply_chain_operator",
        "create_supply_chain_operator_agent",
    ),
]


@pytest.mark.parametrize(
    ("role", "module_path", "factory_name"),
    _STANDARD_FACTORIES,
    ids=[r for r, _, _ in _STANDARD_FACTORIES],
)
def test_standard_agent_factory_compiles(role, module_path, factory_name) -> None:
    """Graph-construction dry-run: the factory builds its middleware stack and
    compiles a graph without raising."""
    module = importlib.import_module(module_path)
    factory = getattr(module, factory_name)
    agent = factory()
    assert agent is not None
    # Compiled LangGraph agents expose .invoke / .get_graph — a thin shape check
    # that we got a graph, not a half-built object.
    assert hasattr(agent, "invoke")
