# Contributor Architecture Guide

Audience: an OSS contributor adding features, fixing bugs, or
refactoring internals within the Buggy repo. The three-package
split (`buggy-core` / `buggy` / `buggy-sdk`) shapes
where new code lives and how to keep the dependency graph clean.

## The three packages, one paragraph each

`buggy-core` is the **contract layer**. Defines what a plugin
*can be*: protocols it implements, dataclasses it parametrizes,
registry it appears in. Imports only `pydantic`, `typing_extensions`,
`importlib.metadata`. Roughly 3,000 LOC target. Versioned strictly
per SemVer (current series 1.1.x → 1.2.0 with this redesign;
shim removal at 2.0.0). Breaking changes here mean a major bump for
the entire ecosystem.

`buggy` is the **framework**. Implements the current agent
execution model: factories using `langchain.agents.create_agent`,
the 11 middleware classes, the bash/cloud/AD/etc. tools, the LLM
proxy router, the sandbox HTTP client, skill catalogs, prompt
builder. Depends on `buggy-core` for every contract it touches.

`buggy-sdk` is the **plugin author entrypoint**. A thin re-export
layer over `buggy-core` plus pytest fixtures, a scaffolding
CLI, and runnable example plugins.

## Where new code goes

Use this table when deciding which package owns a new feature:

| New code looks like | Lives in | Why |
|---------------------|----------|-----|
| Pydantic schema, frozen dataclass, enum | `buggy-core/types/` | Pure data — every consumer benefits |
| Plugin extension contract (Protocol, Contribution) | `buggy-core/contracts/` or `protocols/` | Plugin authors implement these |
| Registry primitive (pluggable catalog) | `buggy-core/registry/` | Cross-cutting; framework consumes it |
| Utility used by multiple framework subsystems | `buggy-core/utils/` | Cheap to share if no runtime deps |
| Agent factory (`create_*_agent`) | `buggy/agents/` | Uses langchain, langgraph — framework-only |
| Middleware implementation | `buggy/middleware/` | Uses langchain — framework-only |
| Tool implementation (the `@tool`-decorated callable) | `buggy/tools/` | Uses langchain — framework-only |
| Bash sandbox client logic | `buggy/backends/` or `sandbox_kernel/` | HTTP + framework-internal |
| Pytest fixture for plugin authors | `buggy-sdk/testing/` | Shipped to plugin authors |
| Scaffolding template / CLI command | `buggy-sdk/scaffold/` | Author tooling |

## Core stays thin

The contract layer's promise is "zero langchain / langgraph /
deepagents runtime dependency." A test
(`packages/buggy-core/tests/test_no_runtime_deps.py`) verifies
this at every CI run — it walks every submodule under `buggy_core`
and asserts none of the forbidden packages end up in `sys.modules`
after import.

If a contributor adds code to `buggy-core` that pulls in
langchain, the CI gate catches it immediately. The fix is usually to
move the offending logic into `buggy/` (the framework) and
leave the type signatures behind in core.

A planned `[tool.ruff.lint.flake8-tidy-imports.banned-api]` rule
will surface these at lint time. Until then the runtime test is
the canonical guard.

## Refactor rules

1. **Framework imports core — never the other way.** Anywhere a
   contract or type lives in core, the framework consumes it via
   `from buggy_core.X import Y`. Code in
   `buggy-core/*.py` may not contain `from buggy import ...`.

2. **Adding a new public name to core = minor bump.** Adding a new
   plugin contract surface (a Protocol, a Contribution, a registry
   class) is additive and SemVer-minor (e.g. 1.1.x → 1.1.2 / 1.2.0).
   Renaming or
   removing one is major.

3. **Framework `_internal/` is freely mutable.** The framework
   package ships private modules under `buggy._internal/`
   (or any underscore-prefixed module). These have no SemVer
   guarantee — refactor them at will.

4. **SDK re-exports follow core.** When you add a new name to
   `buggy-core` public API, also add it to `buggy_sdk/__init__.py`'s
   re-export list. Plugin authors must reach every contract via a
   single SDK import.

5. **Tests live with the package they cover.** Add tests under
   `packages/<pkg>/tests/`. `pytest` testpaths covers all three.

## Workspace layout

```text
.
├── pyproject.toml                  workspace root (virtual project)
├── uv.lock                         single lock for all members
├── packages/
│   ├── buggy-core/
│   │   ├── pyproject.toml
│   │   ├── src/buggy_core/
│   │   │   ├── types/              (Phase 1.A)
│   │   │   ├── protocols/          (Phase 1.D)
│   │   │   ├── contracts/          (Phase 1.C / 1.F)
│   │   │   ├── registry/           (Phase 1.E / 2.x.1)
│   │   │   ├── plugin_loader.py    (Phase 1.B)
│   │   │   └── utils/              (Phase 1.B)
│   │   └── tests/
│   ├── buggy/
│   │   ├── pyproject.toml
│   │   ├── src/buggy/
│   │   │   ├── agents/             16 factories
│   │   │   ├── middleware/         11 implementations
│   │   │   ├── tools/              langchain @tool wrappers
│   │   │   ├── backends/           HTTPSandbox + make_agent_backend
│   │   │   ├── llm/                LLMFactory + router
│   │   │   ├── skills/             markdown skill catalog
│   │   │   ├── compat/             Phase 1 shim re-exports
│   │   │   ├── _boot.py            framework boot wiring (Phase 2)
│   │   │   └── sandbox_server/     FastAPI daemon
│   │   └── tests/                  ~890 unit tests
│   └── buggy-sdk/
│       ├── pyproject.toml
│       ├── src/buggy_sdk/
│       │   ├── __init__.py         single-import re-exports
│       │   ├── testing/            FakeBackend / FakeLLM / FakeSandbox
│       │   └── scaffold/           typer CLI + templates
│       ├── examples/               6 runnable example plugins
│       └── tests/
└── docs/                           audience-specific guides + migration
```

## Versioning

All three packages share a version string (single source of truth =
git tag). The release workflow stamps the tag into all three
pyprojects via `sed` and publishes them atomically.

## See also

- The redesign spec at
  [`docs/superpowers/specs/2026-05-23-core-framework-sdk-split-design.md`](superpowers/specs/2026-05-23-core-framework-sdk-split-design.md)
  — full design rationale, gap analysis, and per-phase acceptance
  criteria.
- Plugin author guide:
  [`docs/plugin-author-guide.md`](plugin-author-guide.md).
- Library consumer guide:
  [`docs/library-consumer-guide.md`](library-consumer-guide.md).
- Migration:
  [`docs/migration/from-0.0.x.md`](migration/from-0.0.x.md).
