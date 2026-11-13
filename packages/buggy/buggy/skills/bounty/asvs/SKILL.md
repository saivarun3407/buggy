---
name: asvs-audit
description: Run a structured OWASP ASVS 5.0 verification pass over an in-scope application — per-chapter, per-level PASS/FAIL/N-A verdicts backed by evidence. Consumes recon's endpoint inventory and works hybrid (black-box DAST + white-box source review).
metadata:
  subdomain: web-exploitation
  when_to_use: "asvs owasp application security verification standard 5.0 audit checklist requirement chapter level l1 l2 l3 pass fail verdict compliance verification"
  mitre_attack: T1190, T1595
---

# OWASP ASVS 5.0 Verification Playbook

ASVS is a checklist of *verifiable* security requirements, not a scanner
run. Each requirement gets a deliberate test and a verdict
(PASS / FAIL / N-A) anchored to its identifier (chapter.section.req, e.g.
`V6.2.1`) and the target level (L1 default, L2/L3 on demand). The output
is organised by chapter and level so the report reads like a compliance
matrix.

## 1. Inputs

- Recon's host / service / endpoint inventory in `/workspace`.
- Any source tree under `/workspace` (enables white-box verification of
  requirements that can't be settled black-box).
- The engagement RoE — only verify assets in scope.

## 2. Chapters you will almost always exercise

| Chapter | Focus | Cheapest decisive probe |
|---|---|---|
| V1 Encoding & Sanitization | output encoding, injection defense | crafted inputs per context |
| V2 Validation / Business Logic | input validation, workflow | boundary + logic probes |
| V3 Web Frontend Security | headers, CSP, cookies | `curl -ski` |
| V6 Authentication | password policy, MFA | login-flow probes |
| V7 Session Management | session lifecycle, cookie flags | login → inspect cookies |
| V8 Authorization | access control | two-identity matrix |
| V9 Self-contained Tokens | JWT / PASETO handling | decode + tamper |
| V11 Cryptography | TLS, ciphers, randomness | `testssl.sh` / `sslyze` |
| V13 API & Web Service | REST/GraphQL controls | endpoint probes |

## 3. Workflow

1. Pull recon endpoints; group by app / host.
2. For each in-scope ASVS requirement, choose the cheapest decisive
   probe and record the verdict immediately (don't batch at the end).
3. For every FAIL, capture the exact request/response or code location
   that proves it.
4. Cross-reference disclosed reports with `h1_search` when a requirement
   maps to a known bug pattern; pull payloads via `payload_search`.

## 4. Verdict discipline

- `PASS` — tested and the requirement holds (evidence attached).
- `FAIL` — tested and violated (evidence + repro).
- `N-A` — not applicable OR not assessed. "Looks fine" without a probe
  is `N-A`, never `PASS`.

## 5. Output

A per-chapter / per-level matrix of verdicts, plus a finding
(`findings/FIND-NNN.md`) for each FAIL that is reportable under the
program scope. Render reportable findings with `report_hackerone` /
`report_bugcrowd_csv` after a `bounty_scope_check`.
