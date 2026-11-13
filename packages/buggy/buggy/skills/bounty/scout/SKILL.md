---
name: bounty-scout-intake
description: Stand up a bug-bounty engagement from the HackerOne / Bugcrowd APIs — list accessible programs, have the operator select one, fetch the program's structured scope and reporting policy, confirm scope and per-program rules with the operator, then hard-enforce them into the RoE before any recon begins.
metadata:
  subdomain: planning
  when_to_use: "bug bounty intake scout program selection hackerone bugcrowd api token scope out-of-scope reporting policy rules rate limit no automated scanning ingest scope roe enforce engagement setup"
  mitre_attack: T1591, T1593
---

# Bug-Bounty Intake Playbook

Intake is a human-in-the-loop setup step, not a test. The scout turns a
HackerOne / Bugcrowd program into an enforced engagement: the operator
picks the program and confirms the scope, and the scout writes the
machine-enforceable RoE. No target is probed during intake.

## 1. Credentials (environment only)

API tokens are read from the environment — never from chat, never written
to `roe.json`, never logged:

| Platform | Identifier env | Token env |
|---|---|---|
| HackerOne | `H1_API_USERNAME` | `H1_API_TOKEN` |
| Bugcrowd | `BUGCROWD_API_USERNAME` | `BUGCROWD_API_TOKEN` |

Call `bounty_intake_status` first. If a platform is missing credentials,
tell the operator the exact `needed_env` variables and wait — do not
proceed. If the operator pastes a token into the chat, tell them to set it
as an environment variable instead.

## 2. List → select (operator decides)

- `h1_list_programs(handle_contains=, only_bounties=, limit=)`
- `bugcrowd_list_programs(name_contains=, limit=)`

Present a short numbered list (handle/code, name, offers-bounties). The
OPERATOR picks exactly one. Never auto-select.

## 3. Fetch structured scope

- `h1_get_program_scope(program_handle=)`
- `bugcrowd_get_program_scope(program=)`

Returns normalized in-scope / out-of-scope network assets, non-network
assets (mobile app IDs, source repos, hardware — informational only),
excluded vulnerability classes, per-asset severity caps, a policy excerpt,
and `suggested_rules`. Run `analyze_program_rules` on the full policy text
when the excerpt is thin.

## 4. Confirm (three gates)

Get explicit operator confirmation of: (a) the program, (b) the in-scope /
out-of-scope / excluded-class lists, and (c) the reporting requirements and
per-program rules. The rule heuristics are advisory — confirm before
enforcing.

## 5. Enforce into the RoE

Call `ingest_bounty_scope` in `enforce` mode with the confirmed values:

- `in_scope` / `out_of_scope` — JSON arrays of confirmed hosts.
- `excluded_classes`, `platform`, `program_handle`, `program_url`.
- `no_automated_tools=true` when the program forbids automated scanning
  (expands a curated scanner-command denylist into the parser).
- `min_inter_request_delay_ms` / `max_concurrent_connections` for a stated
  request-rate / parallelism cap.
- `allow_cloud_metadata=true` ONLY if metadata-service testing is
  explicitly authorised.

Scope is then enforced at two layers — the command parser and the sandbox
egress allowlist. Re-fetch and re-enforce if the operator returns later, as
programs change scope.

## 6. Hand off

Report the enforced in-scope / out-of-scope lists, the egress-policy
preview, the rules now in force, and the `roe.json` path. The engagement is
ready for recon → ASVS → the specialist slate.
