"""Fork-only ``bounty`` bundle — appsec / bug-bounty specialist slate.

Ten bash-executing, RoE-scoped, HITL-gated specialists attached to the
``buggy`` orchestrator: ASVS 5.0, MITRE ATT&CK, API security,
AuthN/session, business-logic & race conditions, GraphQL, SSRF &
cloud-metadata, client-side, LLM/AI app security, and secrets & CI/CD
exposure.

The bundle is wired exactly like the OSS ``plugins`` bundle — each
subagent's ``SUBAGENT_SPEC`` declares ``bundle="bounty"`` and
``parent_agents=("buggy",)``, registered under the
``buggy.subagents`` entry-point group in ``pyproject.toml`` — but
kept in its own bundle (and out of ``langgraph.json`` / the standard
graph manifest) so the ``standard`` bundle can still track upstream
cleanly. It is opt-in via ``BUGGY_PLUGINS`` /
``[tool.buggy.plugins] enabled``; this fork ships it enabled.

Every specialist carries the bug-bounty workflow surface (scope
ingestion → enforced RoE, scope check, HackerOne / Bugcrowd report
generation) on top of its domain tools, so any one of them can
scope-check a candidate finding and emit a platform-ready submission.
The shared factory scaffolding lives in :mod:`._common`.
"""
