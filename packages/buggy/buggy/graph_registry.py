"""LangGraph Platform graph registry — OSS built-ins merged with plugins.

LangGraph Platform expects a graph manifest (``langgraph.json``) or the
``LANGSERVE_GRAPHS`` environment variable mapping each graph name to a
``module:attr`` path. Buggy's built-in agents are listed in the
``langgraph.json`` shipped with the repo. External packages add their own
agents by declaring entry-points in the ``buggy.agents`` group.

This module produces a merged manifest at runtime so external plugins
(e.g. a downstream plugin package shipped separately) can extend the available
graphs without editing ``langgraph.json``.

Typical usage in a container startup script:

    LANGSERVE_GRAPHS="$(python -m buggy.graph_registry)" \\
        langgraph dev --host 0.0.0.0 --port 2024
"""

from __future__ import annotations

import json

from buggy_core.plugin_loader import is_bundle_enabled, load_plugin_agents

# Built-in graphs split by bundle. ``build_langserve_graphs`` merges only
# the bundles active under BUGGY_PLUGINS / config file (see
# ``buggy_core.plugin_loader._enabled_bundles``). External plugin
# packages register agents under the ``buggy.agents`` entry-point
# group and are always loaded when installed.

# Standard bundle — official OSS main agent + subagents + soundwave.
STANDARD_GRAPHS: dict[str, str] = {
    "buggy": "./buggy/agents/standard/buggy.py:graph",
    "recon": "./buggy/agents/standard/recon.py:graph",
    "soundwave": "./buggy/agents/standard/soundwave.py:graph",
    "exploit": "./buggy/agents/standard/exploit.py:graph",
    "postexploit": "./buggy/agents/standard/postexploit.py:graph",
    "analyst": "./buggy/agents/standard/analyst.py:graph",
    "asvs_assessor": "./buggy/agents/standard/asvs_assessor.py:graph",
    "reverser": "./buggy/agents/standard/reverser.py:graph",
    "contract_auditor": "./buggy/agents/standard/contract_auditor.py:graph",
    "cloud_hunter": "./buggy/agents/standard/cloud_hunter.py:graph",
    "ad_operator": "./buggy/agents/standard/ad_operator.py:graph",
    "blue_cell": "./buggy/agents/standard/blue_cell.py:graph",
    "phisher": "./buggy/agents/standard/phisher.py:graph",
    "mobile_operator": "./buggy/agents/standard/mobile_operator.py:graph",
    "wireless_operator": "./buggy/agents/standard/wireless_operator.py:graph",
    "osint_operator": "./buggy/agents/standard/osint_operator.py:graph",
    "iot_operator": "./buggy/agents/standard/iot_operator.py:graph",
    "ics_operator": "./buggy/agents/standard/ics_operator.py:graph",
    "forensicator": "./buggy/agents/standard/forensicator.py:graph",
    "supply_chain_operator": "./buggy/agents/standard/supply_chain_operator.py:graph",
}

# Plugins bundle — vulnresearch family (community-plugin shape demonstrated
# from inside OSS). Opt-in via ``BUGGY_PLUGINS=standard,plugins`` or
# ``[plugins] enabled = ["standard", "plugins"]`` in ``.buggy.toml``.
PLUGIN_GRAPHS: dict[str, str] = {
    "vulnresearch": "./buggy/agents/plugins/vulnresearch.py:graph",
    "scanner": "./buggy/agents/plugins/scanner.py:graph",
    "detector": "./buggy/agents/plugins/detector.py:graph",
    "verifier": "./buggy/agents/plugins/verifier.py:graph",
    "patcher": "./buggy/agents/plugins/patcher.py:graph",
    "exploiter": "./buggy/agents/plugins/exploiter.py:graph",
}

# Bounty bundle — fork-only appsec / bug-bounty specialist slate. Opt-in via
# ``BUGGY_PLUGINS=standard,plugins,bounty`` or
# ``[plugins] enabled = ["standard", "plugins", "bounty"]`` in
# ``.buggy.toml`` (the fork ships it enabled in pyproject). Kept in its
# own dict — and deliberately OUT of ``langgraph.json`` / ``STANDARD_GRAPHS`` —
# so the standard bundle can still track upstream cleanly.
BOUNTY_GRAPHS: dict[str, str] = {
    "scout": "./buggy/agents/bounty/scout.py:graph",
    "asvs": "./buggy/agents/bounty/asvs.py:graph",
    "mitre_attack": "./buggy/agents/bounty/mitre_attack.py:graph",
    "api_security": "./buggy/agents/bounty/api_security.py:graph",
    "authn_session": "./buggy/agents/bounty/authn_session.py:graph",
    "business_logic": "./buggy/agents/bounty/business_logic.py:graph",
    "graphql_security": "./buggy/agents/bounty/graphql_security.py:graph",
    "ssrf_cloud": "./buggy/agents/bounty/ssrf_cloud.py:graph",
    "clientside_security": "./buggy/agents/bounty/clientside_security.py:graph",
    "llm_security": "./buggy/agents/bounty/llm_security.py:graph",
    "secrets_cicd": "./buggy/agents/bounty/secrets_cicd.py:graph",
}

# Mapping from bundle name to its graph dict — used by build_langserve_graphs.
_BUNDLE_TO_GRAPHS: dict[str, dict[str, str]] = {
    "standard": STANDARD_GRAPHS,
    "plugins": PLUGIN_GRAPHS,
    "bounty": BOUNTY_GRAPHS,
}

# Backward-compat alias — full unfiltered manifest (every OSS-shipped graph).
# Prefer ``build_langserve_graphs()`` which respects BUGGY_PLUGINS.
BUILTIN_GRAPHS: dict[str, str] = {**STANDARD_GRAPHS, **PLUGIN_GRAPHS, **BOUNTY_GRAPHS}


def build_langserve_graphs() -> dict[str, str]:
    """Return ``{name: module:graph}`` for active bundles + discovered plugins.

    OSS-internal bundles (``standard``, ``plugins``) are filtered by
    ``BUGGY_PLUGINS`` / config-file allowlist. Plugin-contributed
    agents (registered under the ``buggy.agents`` entry-point group
    by external packages) are always merged in — installing the package
    is the user's opt-in.

    Name collisions: plugin-contributed agents override built-in entries.
    """
    merged: dict[str, str] = {}
    for bundle_name, graphs in _BUNDLE_TO_GRAPHS.items():
        if is_bundle_enabled(bundle_name):
            merged.update(graphs)
    merged.update(load_plugin_agents())
    return merged


def emit_langserve_env() -> str:
    """Serialize the merged manifest as compact JSON for ``LANGSERVE_GRAPHS``."""
    return json.dumps(build_langserve_graphs(), separators=(",", ":"))


def main() -> None:
    """CLI entry: print the merged graph manifest as JSON to stdout."""
    print(emit_langserve_env())


if __name__ == "__main__":
    main()
