---
name: business-logic-race
description: Hunt business-logic flaws and race conditions — workflow/state-machine abuse, economic/quantity logic bugs, and TOCTOU/parallel-request races (double-spend, coupon reuse, limit overrun). The bugs scanners structurally cannot find.
metadata:
  subdomain: web-exploitation
  when_to_use: "business logic flaw race condition toctou parallel request double spend limit overrun coupon reuse workflow state machine multi step price tampering negative quantity quota bypass concurrency"
  mitre_attack: T1190
---

# Business-Logic & Race-Condition Playbook

These are flaws in what the app is *supposed* to allow — there is no
signature for "the discount stacked." Find them by understanding intent,
then violating it.

## 1. Reconstruct intent

Map the workflow / state machine and its invariants: order of steps,
ownership, balance/quota, single-use constraints. Name each invariant
explicitly — that is what you will try to break.

## 2. Lane A — Workflow / state abuse

- **Step-skipping** — reach step N without completing N-1 (e.g. checkout
  without payment).
- **Out-of-order / replay** — replay a single-use action; reorder steps.
- **Trusted carried state** — tamper a value the server trusts from an
  earlier step (price, user ID, status baked into a hidden field/token).

## 3. Lane B — Race conditions (TOCTOU)

The bug is a timing window between check and use.

1. Identify limit-once operations: redeem, withdraw, vote, apply-coupon,
   accept-invite.
2. Fire **N concurrent requests** at the window. Use single-packet /
   last-byte-sync when HTTP/2 is available, else a parallel `curl` /
   `asyncio`+`httpx` burst.
3. Confirm the limit-once operation happened M>1 times (double-spend,
   coupon reuse, balance overrun).

## 4. Lane C — Economic / quantity logic

Negative or fractional quantities, currency/rounding abuse, price
tampering, refund > purchase, stacking single-use discounts.

## 5. Lane D — Privilege & ownership logic

Role transitions that skip approval, ownership reassignment,
tenant-boundary violations driven by workflow rather than direct authZ.

## 6. Proof & report

State the invariant violated and the concrete impact (money, data,
privilege) with before/after state. `bounty_scope_check`, then
`report_hackerone` / `report_bugcrowd_csv`. `h1_search` for disclosed
logic/race chains.
