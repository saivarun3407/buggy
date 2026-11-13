---
name: api-security-top10
description: Hunt the OWASP API Security Top 10 (2023) — BOLA/IDOR (API1), broken function-level authorization (API5), mass assignment and excessive data exposure (API3/API6), and resource/inventory abuse (API4/API9). Two-identity authZ testing against the live API surface.
metadata:
  subdomain: web-exploitation
  when_to_use: "api security owasp api top 10 bola idor object level authorization bfla function level mass assignment excessive data exposure rest openapi swagger postman two account cross tenant"
  mitre_attack: T1190
---

# OWASP API Security Top 10 Playbook

Modern bounties live in APIs because authorization is business logic and
scanners can't reason about it. The single most important habit:
**always test with two accounts.**

## 1. Build the API surface

- Pull specs when available: OpenAPI/Swagger (`/openapi.json`,
  `/swagger.json`, `/v3/api-docs`), GraphQL introspection, Postman
  collections in `/workspace`.
- Otherwise observe traffic and fuzz the path/verb space
  (`ffuf`/`feroxbuster`), discover params with `arjun`.
- For each endpoint record: object acted on, expected authorization,
  data returned.

## 2. Lane A — BOLA / IDOR (API1, the #1 bug)

1. Capture an authenticated request containing an object ID.
2. Replay it as a *second* identity; swap/increment IDs (numeric, UUID,
   hashids, base64-wrapped).
3. Cross-tenant read or write = finding. A single-account "it returned
   data" is **not** a finding.

## 3. Lane B — Broken function-level authZ (API5 / BFLA)

- Map role-gated endpoints (admin, internal, management).
- Call them as a low-priv user; flip verbs (`GET`→`PUT`/`DELETE`);
  strip or forge role claims/headers.

## 4. Lane C — Mass assignment & data exposure (API3 / API6)

- Mass assignment: add fields the client never sends (`role`,
  `is_admin`, `verified`, `balance`) and confirm they persist.
- Excessive data exposure: inspect raw JSON for fields the UI hides
  (tokens, internal IDs, PII) — the server over-returns, client filters.

## 5. Lane D — Resource & inventory (API4 / API9)

- Rate-limit / pagination abuse for resource exhaustion (measured, no
  real DoS).
- Probe old versions (`/v1` vs `/v2`), staging hosts, undocumented
  routes — improper inventory management.

## 6. Proof & report

Capture the request/response pair that demonstrates the broken control.
`bounty_scope_check` the asset and vuln class, then `report_hackerone` /
`report_bugcrowd_csv`. Use `h1_search` for disclosed API chains and
`payload_search` for class payloads.
