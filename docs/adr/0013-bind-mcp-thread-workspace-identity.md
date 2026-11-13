# 0013. Bind MCP threads to launcher-selected workspaces

- **Status:** Proposed
- **Date:** 2026-11-07
- **Deciders:** @ddanntheman
- **Related:** [selected-workspace enforcement](https://github.com/ddanntheman/Buggy/pull/58)

## Context

The launcher binds a selected host directory to `/workspace`. Agent state stores
that runtime path, which cannot distinguish two host workspaces. Conversely,
requiring state to contain the host path rejects legitimate CLI threads. A new
asynchronous MCP run can also be controlled before its state is hydrated.

## Decision

Create CLI and selected MCP threads with metadata containing `engagement_name`,
`workspace_identity`, and `workspace_path`. Identity is the launcher-selected
host workspace path, carried by `BUGGY_ENGAGEMENT_WORKSPACE`; it is an opaque
identifier to the backend, not a runtime filesystem path or a secret. MCP uses
its selected workspace resolver for the expected identity. Runtime path is
`BUGGY_WORKSPACE_PATH`, defaulting to `/workspace`.

Validate that binding at the MCP tool boundary before reading state or issuing
control calls. Empty pending state is allowed only with a valid binding; present
state context must agree. Legacy unbound threads fail closed. Listing catches
only the named thread-access error, not SDK/configuration failures. Selected
starts default to the selected name and cannot choose a different engagement.

### Threat model

An MCP caller controls thread IDs, tool arguments, and messages, but not the
launcher/MCP environment or thread metadata. Matching names or container paths
alone grant no access, nor can agent-produced state replace the identity binding.
The LangGraph deployment and its authenticated administrative API clients are
trusted: direct API access can edit metadata and is outside this tool boundary.
This is a workspace control boundary, not LangGraph tenant authentication.

Identity belongs to the configured deployment's host workspace namespace.
Deployments sharing a backend must not reuse the same host workspace identifier
for unrelated directories on different machines. Moving or renaming a workspace
changes its identity; there is no automatic cross-path adoption.

## Consequences

- **Easier:** CLI and MCP threads use the same binding before the first checkpoint,
  including initial runs and CLI handoff threads.
- **Harder:** selected operations require an additional thread-metadata read.
- **Given up:** inferring ownership from `/workspace` or mutable agent state.
- **Migration:** upgrade launcher, CLI, and MCP together and create new threads.
  Previously created threads are not adopted automatically. Manually launched
  CLIs must receive the same host workspace identifier as the selected MCP server.
  Unselected MCP behavior is unchanged.

No agent state, middleware contract, public MCP tool signature, shared state-read
method, or continuation routing changes.

## Alternatives considered

- **Unconditional `/workspace` alias:** cannot distinguish unrelated workspaces.
- **Identity in agent state with initial graph supersteps:** requires changing the
  safety-critical state contract and resolving assistant aliases before dispatch.
- **Persistent UUID marker:** introduces another identity store and migration
  protocol; the trusted launcher already supplies the deployment's workspace ID.
