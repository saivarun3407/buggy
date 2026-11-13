"""Custom agent contributed to Buggy."""

from __future__ import annotations


def get_agent() -> object:
    """Plugin factory returning a compiled agent (LangGraph CompiledGraph).

    Replace this stub with your real agent construction — see
    ``buggy.agents.standard.recon.create_recon_agent`` for an
    example of the framework's factory pattern.
    """
    raise NotImplementedError(
        "buggy_example_agent: replace get_agent() with your compiled-graph factory"
    )


# LangGraph platform discovers ``graph`` as the module-level attribute.
graph = None
