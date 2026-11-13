from buggy.tools.bash.bash import (
    bash,
    bash_kill,
    bash_output,
    bash_status,
)
from buggy.tools.bash.prompt import BASH_PROMPT
from buggy.tools.discovery import capability_search

# ``capability_search`` ships alongside the bash session tools: any agent
# that can run commands in the sandbox should first be able to discover
# WHICH registry-backed Kali tools exist and how to reach them, rather
# than hand-rolling scripts or assuming a tool is missing. It is
# read-only (static registry query, no commands, no engagement state).
BASH_TOOLS = [bash, bash_output, bash_kill, bash_status, capability_search]

__all__ = [
    "BASH_PROMPT",
    "BASH_TOOLS",
    "bash",
    "bash_kill",
    "bash_output",
    "bash_status",
    "capability_search",
]
