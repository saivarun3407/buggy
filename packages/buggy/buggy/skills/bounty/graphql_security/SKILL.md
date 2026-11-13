---
name: graphql-security
description: Hunt GraphQL-specific bugs — introspection-driven schema recovery, resolver-level authorization gaps and IDOR via node/edges, alias/batching rate-limit amplification, and complexity/depth DoS. Targets /graphql and GraphQL-over-GET endpoints.
metadata:
  subdomain: web-exploitation
  when_to_use: "graphql introspection schema resolver authorization idor node edges alias batching amplification rate limit bypass complexity depth dos apollo hasura graphene mutation"
  mitre_attack: T1190
---

# GraphQL Security Playbook

GraphQL collapses an entire API behind one endpoint; its flexibility is
its attack surface. Find the endpoint (`/graphql`, `/api/graphql`,
`/v1/graphql`, GraphQL-over-GET), fingerprint the engine, then attack
the recovered schema.

## 1. Discover & fingerprint

- Locate endpoint(s); fingerprint engine with `graphw00f` (Apollo,
  Hasura, graphene, etc.) — engine dictates which bypasses apply.

## 2. Lane A — Introspection & schema recovery

- Run the introspection query. If disabled, recover the schema via
  field-suggestion errors and known-type probing (`clairvoyance`).
- Introspection-on alone is at most info/low — its value is as a **map**
  to a real bug. Report the impactful bug; cite introspection as the
  enabler.

## 3. Lane B — Resolver authZ / IDOR

Authorization is per-resolver and frequently inconsistent across paths.

- Access objects via `node(id:)`, edges, and nested relations across two
  identities.
- Find fields exposed through one query path but guarded on another.

## 4. Lane C — Batching / alias amplification

- Alias-stack or array-batch sensitive mutations (login, OTP verify,
  promo redeem) to bypass per-request rate limits — turns one HTTP
  request into thousands of operations.

## 5. Lane D — Complexity / injection

- Deeply nested / cyclic queries for complexity/depth DoS — keep it
  **measured and in-scope**; do not actually take the target down.
- Test resolver arguments for SQL/NoSQL injection and SSRF sinks.

## 6. Mutations are the dangerous verbs

Enumerate every mutation and test authZ + mass-assignment on each — they
change state.

## 7. Proof & report

Capture the query/response proving impact. `bounty_scope_check`, then
`report_hackerone` / `report_bugcrowd_csv`. `payload_search` for GraphQL
payloads.
