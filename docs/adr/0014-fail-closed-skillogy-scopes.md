# 0014. Fail closed on Skillogy scope errors and bound runtime reads

- **Status:** Proposed
- **Date:** 2026-11-07
- **Deciders:** Pending maintainer review
- **Related:** [ADR 0008](0008-skillogy-hard-acl-phase1a.md), [ADR 0011](0011-skillogy-lightrag-hybrid-retrieval.md), [upstream hardening](https://github.com/BitterSecurity/Buggy/commit/031029bbaec4a1de5db15bc8f31c231cab1e6713)

## Context

ADR 0008 binds agent skill retrieval to role-specific path prefixes. A failed
role lookup currently returns `None`, the unrestricted library sentinel. An
explicit empty list has the same effect. A configuration failure therefore
widens access instead of stopping initialization. Row caps also do not limit
how long Neo4j spends computing a result.

## Decision

A role-bearing caller must resolve a nonempty, restricted prefix list before
Skillogy tools are installed. Explicit scopes, including scopes passed directly
to `SkillogyMiddleware`, receive the same validation. Prefixes must be strings
under `/skills/`, end in `/`, exclude `..`, and not equal the root `/skills/`.
Invalid scopes and resolver failures raise a private `_SkillogyScopeError`
with the original cause retained where applicable. They never become the
unrestricted sentinel. A stack without a skills slot is returned unchanged.

Only a caller with neither a role nor an explicit scope retains the existing
unrestricted library behavior. The role catalog, REST schema, tool signatures,
hybrid ranking, assessment contracts, and existing backend ACL checks remain
unchanged.

Use Neo4j `Query` transaction deadlines of five seconds for all agent-facing
reads: loading, health, lexical and semantic search, phase summaries, traversal,
and read-only Cypher. Preserve read-mode sessions and row caps. Boot-time graph
and embedding operations retain their existing behavior. The deadline limits
server execution, not connection acquisition, retries, or total HTTP latency.

### Threat model

Role and plugin configuration are trusted inputs that can nevertheless be
missing or malformed; neither condition may grant wider skill access. Agents
can request expensive reads, so execution must have a server-side bound.
This is not a new tenant authorization mechanism. Direct database access and
unscoped standalone callers remain outside the role-bound middleware boundary.
No sandbox, RoE, approval, or audit control is relaxed.

## Consequences

- **Easier:** missing dependencies and invalid scopes fail visibly before tools
  become available; expensive runtime reads have a transaction deadline.
- **Harder:** large runtime reads can time out and must be narrowed.
- **Given up:** continuing with unrestricted tools after a scope failure.
- **Migration:** callers using empty, root-wide, malformed, or traversal-bearing
  prefixes must supply restricted prefixes. Valid role scopes and omitted
  standalone scopes keep their current behavior. No data migration is required.

## Alternatives considered

- **Log and use unrestricted access:** rejected because a configuration error
  would widen permissions.
- **Keep only row caps:** rejected because a bounded result can require an
  unbounded amount of work before the first row is returned.
