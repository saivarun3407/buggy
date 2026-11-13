# Buggy as a Library

Buggy is built on top of `langchain` / `langgraph` / `deepagents`
and follows the same composition idiom: opinionated middleware + tools
+ prompts you can either consume pre-built or compose into something
of your own. This document covers the three usage paths and the
override surface plugin authors have access to.

If you only run Buggy via the bundled Docker stack and never
touch the Python code, none of this applies — keep using `curl | bash`
and the CLI launcher. This document is for commercial / research
integrators building on top of the agent code.

---

## Three usage paths

### 1. Pre-built agents (OSS default)

The 16 agent factories ship preconfigured. Module-level `graph`
constants are what LangGraph Platform picks up from `langgraph.json`.

```python
from buggy.agents.standard.recon import create_recon_agent, graph

agent = create_recon_agent()  # default OSS configuration
# `graph` is the same thing, built once at import time.
```

No arguments needed; every dependency (LLM, sandbox, backend,
fallback chain) is resolved at call time using `LLMFactory` + the
configured sandbox URL.

### 2. Factory with explicit overrides

The 16 factories accept langchain-style keyword arguments. Provide a
value to replace the default for that field; leave `None` to keep the
baseline (and apply any plugin overrides discovered via entry-points).

```python
from langchain_core.tools import tool

from buggy.agents.standard.soundwave import create_soundwave_agent

@tool
def vendor_slack_ask_user(question: str, header: str = "") -> str:
    """Send the operator's question to a Slack channel and block until reply."""
    ...

agent = create_soundwave_agent(
    tools=[vendor_slack_ask_user],        # full tool list (replaces baseline)
    system_prompt="<your custom prompt>", # full prompt replace
    recursion_limit=500,                  # tuning
)
```

Available kwargs on every factory:

| Kwarg | Default | Effect when provided |
|-------|---------|---------------------|
| `backend` | `make_agent_backend(build_sandbox_backend())` | injected `BackendProtocol` |
| `llm` | `LLMFactory().get_model(role)` | injected chat model |
| `fallback_models` | `LLMFactory().get_fallback_models(role)` | passed to `ModelFallbackMiddleware` |
| `sandbox` | `build_sandbox_backend()` (bash agents only) | injected `HTTPSandbox` |
| `subagents` | `load_subagents_for_parent(role)` (orchestrators only) | full subagent list |
| `tools` | per-role registry | **full tool list** — replaces baseline |
| `middleware` | per-role slot stack | **full middleware list** — replaces slot assembly |
| `system_prompt` | `load_prompt(role)` (plugin overrides applied) | **full prompt** — replaces baseline |
| `recursion_limit` | per-role (60–1000) | `with_config({"recursion_limit": ...})` |

> When `tools` / `middleware` / `system_prompt` is `None` (the
> default), the factory builds the OSS baseline AND applies any plugin
> overrides discovered via the `buggy.bundles` entry-point group.
> When an explicit value is supplied, the baseline AND the plugin
> overrides for that surface are bypassed — the caller takes full
> control.

### 3. Direct composition with `langchain.create_agent`

For total control, import Buggy's building blocks and assemble
with langchain's generic agent constructor. Buggy's factory is
bypassed entirely.

```python
from langchain.agents import create_agent
from langchain.agents.middleware import ModelFallbackMiddleware
from langchain_anthropic.middleware import AnthropicPromptCachingMiddleware
from deepagents.middleware.patch_tool_calls import PatchToolCallsMiddleware

from buggy.agents.prompts import load_prompt
from buggy.backends import build_sandbox_backend, make_agent_backend
from buggy.llm import LLMFactory
from buggy.middleware import (
    EngagementContextMiddleware,
    FilesystemMiddleware,
    SandboxNotificationMiddleware,
    SkillsMiddleware,
)
from buggy.tools.bash import BASH_TOOLS
from buggy.tools.bash.bash import set_sandbox
from buggy.tools.research.tools import kg_query, kg_stats

sandbox = build_sandbox_backend()
set_sandbox(sandbox)
backend = make_agent_backend(sandbox)
llm = LLMFactory().get_model("recon")  # or your own ChatModel

agent = create_agent(
    llm,
    system_prompt=load_prompt("recon", shared=["bash"]),
    tools=[*BASH_TOOLS, kg_query, kg_stats, my_custom_tool],
    middleware=[
        EngagementContextMiddleware(),
        SkillsMiddleware(backend=backend, sources=["/skills/my-vendor/"]),
        FilesystemMiddleware(backend=backend),
        SandboxNotificationMiddleware(sandbox=sandbox),
        ModelFallbackMiddleware(...),
        my_audit_middleware,
        AnthropicPromptCachingMiddleware(unsupported_model_behavior="ignore"),
        PatchToolCallsMiddleware(),
    ],
    name="vendor-recon-v2",
)
```

This is the canonical path for commercial / research integrators who want
to ship their own service on top of Buggy's agent code.

### 3b. Plugin orchestrator with the OSS slot system (`build_middleware(slots=...)`)

When a downstream product wants to ship a **new orchestrator agent
type** (not one of the OSS 16) but still wants Buggy's slot
system, safety gate, and plugin-override pipeline, pass an explicit
``slots`` set to ``build_middleware``:

```python
from buggy.agents.build import build_middleware, build_tools
from buggy.agents.middleware_slots import MiddlewareSlot
from buggy.agents.prompts import load_prompt
from buggy.llm import LLMFactory

PRO_SLOTS = frozenset({
    MiddlewareSlot.ENGAGEMENT_CONTEXT,
    MiddlewareSlot.SKILLS,
    MiddlewareSlot.FILESYSTEM,
    MiddlewareSlot.SUBAGENT,
    MiddlewareSlot.OPPLAN,
    MiddlewareSlot.MODEL_FALLBACK,
    MiddlewareSlot.SUMMARIZATION,
    MiddlewareSlot.PROMPT_CACHING,
    MiddlewareSlot.PATCH_TOOL_CALLS,
})

PRO_SKILL_SOURCES = [
    "/skills/vendor-pro/orchestrator/",
    "/skills/shared/",
]

def create_buggy_pro_agent(**kwargs):
    # LLMFactory only knows OSS role assignments; pass default_role=
    # to inherit one as fallback until the plugin registers its own.
    llm_factory = LLMFactory()
    llm = llm_factory.get_model("buggy-pro", default_role="buggy")
    fallbacks = llm_factory.get_fallback_models("buggy-pro", default_role="buggy")

    middleware = build_middleware(
        role="buggy-pro",         # custom role — NOT in SLOTS_PER_ROLE
        slots=PRO_SLOTS,               # plugin author declares its slot set
        skill_sources=PRO_SKILL_SOURCES,  # bypass OSS skills_sources_for() lookup
        backend=..., llm=llm, fallback_models=fallbacks, subagents=[...],
    )
    return create_agent(..., middleware=middleware, ...)
```

Three plugin-orchestrator escape hatches converge here:

- ``slots=`` — without it, ``build_middleware`` raises ``KeyError`` for
  unknown roles. Silent fallback to an empty stack would mask real
  bugs in plugin code.
- ``skill_sources=`` — without it, the SKILLS slot calls
  ``skills_sources_for(role)`` which only knows the 10 OSS standard
  roles. Plugin specialists/orchestrators pass an explicit list.
- ``default_role=`` on ``LLMFactory.get_model`` /
  ``LLMFactory.get_fallback_models`` — without it, the factory raises
  ``KeyError`` for roles not in ``AGENT_TIERS``. Plugin can inherit any
  OSS role's model assignment until it ships its own.

---

## Declarative plugin overrides (`PluginBundle`)

Plugin authors who pip-install on top of an existing Buggy Docker
image (rather than composing a service from scratch) ship a
`PluginBundle` under the `buggy.bundles` entry-point group.
Factories discover and apply it automatically — no factory kwargs
needed.

```python
# vendor_pkg/bundles.py
from buggy.plugin_loader import PluginBundle
from vendor_pkg.tools import vendor_slack_ask
from vendor_pkg.middleware import vendor_skills_factory

VENDOR_BUNDLE = PluginBundle(
    bundle="vendor",
    # Tools
    replaced_tools={"ask_user_question": vendor_slack_ask},
    disabled_tools=("complete_engagement_planning",),
    # Middleware (slot names = MiddlewareSlot values)
    replaced_middleware={"skills": vendor_skills_factory},
    disabled_middleware=("prompt-caching",),
    # Prompt patches per role
    prompts={
        "soundwave": {"append": "<VENDOR_AUDIT_POLICY>...</VENDOR_AUDIT_POLICY>"},
        "recon": {"prepend": "<VENDOR_HEADER>..."},
    },
    # Sub-agents
    replaced_subagents={"recon": vendor_pkg.agents.recon.SUBAGENT_SPEC},
    # Optional role scoping (empty tuple = applies to every role)
    roles=("soundwave", "recon"),
)
```

```toml
# vendor_pkg/pyproject.toml
[project.entry-points."buggy.bundles"]
vendor = "vendor_pkg.bundles:VENDOR_BUNDLE"
```

Activation also honors the existing `BUGGY_PLUGINS` env / config
allowlist via `bundle="vendor"`. Set
`BUGGY_PLUGINS=standard,vendor` to opt in.

### Adding skills via entry-points

Skill packages (the `/skills/<bundle>/` markdown trees consumed by
`SkillsMiddleware`) plug in through their own entry-point group so
plugin authors can layer skills onto OSS without overriding the
SKILLS slot factory.

```python
# vendor_pkg/skills.py
def skill_sources(role: str) -> list[str]:
    if role in ("recon", "exploit"):
        return ["/skills/vendor-pro/", "/skills/vendor-shared/"]
    return []
```

```toml
# vendor_pkg/pyproject.toml
[project.entry-points."buggy.skills"]
vendor = "vendor_pkg.skills:skill_sources"
```

Plugin paths are appended after the OSS baseline returned by
`buggy.agents.middleware_slots.skills_sources_for`, so OSS skills
keep their priority in the progressive-disclosure budget.

### Override resolution order

1. Plugin `buggy.bundles` entries (merged across all installed
   plugins, last-write-wins on conflicts).
2. Explicit kwargs passed to the factory (`tools=`, `middleware=`,
   `system_prompt=`, …). Always win.

When `tools=` / `middleware=` / `system_prompt=` is `None`, plugins
apply normally. When the kwarg is non-None, plugin overrides for that
specific surface are skipped — the caller has taken full control.

---

## Safety gate

A small allowlist of slots and tools is flagged safety-critical:

| Kind | Item | Why |
|------|------|-----|
| Middleware slot | `engagement-context` | Carries RoE constraints into every tool call |
| Middleware slot | `sandbox-notification` | Tracks background-job completion — operator visibility |
| Tool | `ask_user_question` | Operator-approval channel |
| Tool | `complete_engagement_planning` | Mandatory engagement-handoff signal |

Disabling or replacing any of these (whether via factory kwarg, plugin
bundle, or both) raises `SafetyOverrideViolation` at agent-construction
time unless `BUGGY_ALLOW_SAFETY_OVERRIDES=1` is set in the
environment. The gate exists so an accidentally-installed plugin
cannot silently subvert the safety story — operators must explicitly
opt in.

The gate does not validate that a replacement honors the same contract
(e.g. a substitute `EngagementContextMiddleware` still injects RoE
scope). It only prevents accidental holes. Replacements are expected
to honor the original semantics.

---

## Building blocks reference

| Import | Purpose |
|--------|---------|
| `buggy.agents.standard.*`, `buggy.agents.plugins.*` | Pre-built per-role agent factories |
| `buggy_core.contracts.slots` | `MiddlewareSlot` enum, `SLOTS_PER_ROLE`, `DEFAULT_SLOT_FACTORIES` |
| `buggy.agents.build` | `build_middleware`, `build_tools`, `resolve_prompt_overrides`, `SafetyOverrideViolation` |
| `buggy.agents.prompts` | `load_prompt`, `PromptBuilder` |
| `buggy.middleware` | `SkillsMiddleware`, `FilesystemMiddleware`, `EngagementContextMiddleware`, `OPPLANMiddleware`, `SandboxNotificationMiddleware`, `OpsControlNotificationMiddleware`, `KGMiddleware`, `SkillogyMiddleware`, … |
| `buggy.tools.bash` | `BASH_TOOLS` (the four bash tools), `set_sandbox` |
| `buggy.tools.research`, `buggy.tools.references` | KG / CVE / payload tools |
| `buggy.tools.interaction` | `ask_user_question`, `complete_engagement_planning` |
| `buggy.tools.ops` | `ops_start`, `ops_stop`, `ops_status` (orchestrator-only, ADR-0006) |
| `buggy.backends` | `HTTPSandbox`, `build_sandbox_backend`, `make_agent_backend` |
| `buggy.llm` | `LLMFactory` |
| `buggy_core.types.engagement` | `RoE`, `CONOPS`, `DeconflictionPlan`, `OPPLAN`, `ThreatProfile`, `CleanupPlan`, `AbortPlan`, `ContactPlan`, `DataHandlingPlan` |
| `buggy_core.types.kg` | `KnowledgeGraph`, `Node`, `Edge`, `EdgeKind` |
| `buggy_core.plugin_loader` | `PluginBundle`, `SubAgentSpec`, `is_bundle_enabled`, `load_plugin_*` |

The schema / contract types live in **`buggy-core`** (the contracts package); the framework re-exports them via the compat shim in `buggy/__init__.py` for one minor cycle (`buggy.core.schemas`, `buggy.plugin_loader`, `buggy.agents.middleware_slots`). New code should import from `buggy_core.*` directly.

---

## Common patterns

### Add a single vendor tool to the default agent

```python
from buggy.agents.standard.recon import create_recon_agent

# Easiest: ship a PluginBundle (items=(my_tool,)) under buggy.bundles
# and the default factory picks it up automatically.

# Or pass explicitly — but you have to include the full tool list:
from buggy.agents.standard.recon import _STANDARD_TOOLS
all_tools = [*_STANDARD_TOOLS.values(), my_tool]
agent = create_recon_agent(tools=all_tools)
```

### Run an OSS agent with a different model

```python
from langchain_anthropic import ChatAnthropic

custom_llm = ChatAnthropic(model="claude-opus-4-5", temperature=0)
agent = create_recon_agent(llm=custom_llm, fallback_models=[])
```

### Replace `SkillsMiddleware` with a vendor caching version

Plugin path (declarative, recommended):

```python
PluginBundle(
    bundle="vendor",
    replaced_middleware={"skills": vendor_skills_factory},
)
```

Library path (full control):

```python
# Compose your own middleware list with langchain.create_agent.
# See path 3 above.
```

### Disable a non-critical slot for one agent

```python
from buggy.agents.middleware_slots import MiddlewareSlot
from buggy.agents.standard.soundwave import create_soundwave_agent

# Drop AnthropicPromptCachingMiddleware (we have our own cache layer).
# This is library-style direct call; for plugin-wide disable, use
# PluginBundle(disabled_middleware=("prompt-caching",)).
import os
os.environ["BUGGY_ALLOW_SAFETY_OVERRIDES"] = "0"  # default — only non-critical slots ok
# … then use the factory's `middleware=` kwarg with your own composed list,
# or rely on a plugin bundle.
```

---

## Versioning

Buggy-core follows SemVer 0.x semantics until the API has settled
through real commercial integrations. Public surface listed above is
the intended stability target; internals (`_resolve_overrides`,
private factory helpers, etc.) may change without notice.

Install from PyPI and pin a compatible range in your `pyproject.toml`:

```toml
[project]
dependencies = [
    "buggy>=1.0,<2",           # core SDK
    # "buggy[neo4j]>=1.0,<2",  # add the extra for the KG graph tools
]
```

The published wheel bundles the `standard`/`shared`/`plugins` skill trees
as package data; benchmark skills are intentionally excluded. Heavy
optional dependencies (e.g. `neo4j`) live behind extras to keep the base
install lean.
