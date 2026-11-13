"""Operator-interaction tools — agent-driven CLI prompts.

Tools in this package pause graph execution and surface a structured prompt
to the human operator. The CLI renders an interactive picker and resumes the
graph with the operator's choice.
"""

from buggy.tools.interaction.ask_user import ask_user_question
from buggy.tools.interaction.complete_planning import (
    complete_engagement_planning,
)
from buggy.tools.interaction.scope_amendment import request_scope_amendment

__all__ = ["ask_user_question", "complete_engagement_planning", "request_scope_amendment"]
