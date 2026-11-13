# buggy-core

The Buggy contract layer. Pure types, protocols, plugin contracts,
and registry primitives — zero `langchain` / `langgraph` / `deepagents`
runtime dependency. Suitable to import from any context: CLI tooling,
serverless workers, type-checking-only environments.

Stable surface for plugin authors and downstream commercial layers
(e.g. dashboards, B2B API services). See the umbrella
[`README.md`](../../README.md) and the design spec at
[`docs/superpowers/specs/2026-05-23-core-framework-sdk-split-design.md`](../../docs/superpowers/specs/2026-05-23-core-framework-sdk-split-design.md).

## Install

```bash
pip install buggy-core
```

Most consumers should install `buggy` (which depends on this) or
`buggy-sdk` (the plugin-author entrypoint).
