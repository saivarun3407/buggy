"""Prompt fragments contributed to one or more roles."""

from __future__ import annotations

from buggy_sdk import PromptContribution


def get_contribution() -> PromptContribution:
    """Plugin factory called by the framework's prompt loader."""
    return PromptContribution(
        fragments={"recon": "<buggy_example_prompt>...</buggy_example_prompt>"},
        mode="append",
        roles=("recon",),
    )
