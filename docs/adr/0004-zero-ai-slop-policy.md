# 0004. Zero AI-slop policy — the 100% quality bar

- **Status:** Accepted
- **Date:** 2026-06-04
- **Deciders:** @PurpleCHOIms
- **Related:** [docs/QUALITY_BAR.md](../QUALITY_BAR.md), [CONTRIBUTING_AGENT.md](../../CONTRIBUTING_AGENT.md), [ADR-0003](0003-ai-contributor-self-review.md)

## Context

ADR-0003 introduced a self-review charter for AI-assisted
contributions. After watching it in practice for a short stretch, the
charter alone is not enough. It correctly raises the **process** bar
("read the diff before pushing; do not bundle unrelated work") but
leaves the **code** bar implicit. The result is that
charter-compliant PRs still arrive with the visual fingerprints of
AI generation: defensive overcoding, try/except wrappers around calls
that should propagate, single-use helper functions, premature
kwargs, vague test names, comments that translate the next line into
English, em-dashes everywhere, and prose that reads as "leverages X
to robustly handle Y in a comprehensive manner."

These do not, on a single PR, break anything. Across hundreds of
PRs they break the architecture by drift. They also break review:
a reviewer cannot scan a 300-line AI-generated diff in 60 seconds the
way they can scan a 50-line surgical diff written by someone who
read the surrounding code first.

The project's sole maintainer (`@PurpleCHOIms`) cannot afford that.
"Passes CI" was never the bar — `docs/COWORK.md §4.5` and the
existing CODEOWNERS strategy already say so. This ADR makes the bar
**explicit, enumerated, and inescapable**.

## Decision

We adopt `docs/QUALITY_BAR.md` as the closed contract for what
"100% quality" means for Buggy. The bar:

1. Restates the [Karpathy Four](../QUALITY_BAR.md#the-karpathy-four)
   (Think Before Coding / Simplicity First / Surgical Changes /
   Goal-Driven Execution) as the standing philosophy.
2. Sets **hard diff-size limits** (≤ 400 runtime-code lines, ≤ 10
   files, 1 logical concern per PR). Tests, docs, and configuration
   do not count. Exceeding requires an `@PurpleCHOIms`-applied
   `large-diff-approved` label.
3. Enumerates **banned patterns** that close a PR on sight —
   `except Exception: pass`, bare `# type: ignore`, mutable
   defaults, wildcard imports, vague test names, mocked-system-under-test
   tests, cosmetic drive-bys, etc.
4. Enumerates **AI-slop signatures** with concrete code examples,
   so neither a contributor nor an AI assistant generating their
   work can plead ignorance.
5. Enumerates **required positive patterns** — typed public APIs,
   named exception classes, failing-then-passing test commits for
   fixes, justified magic numbers, linked TODOs.
6. Adds a **self-review standard** with binary questions: every "no"
   means do not request review yet.
7. Names exactly three escape valves: ADR, `large-diff-approved`
   label, or a documented exception in the file itself (which is
   itself ADR-gated).

The bar is referenced from `CONTRIBUTING_AGENT.md`, from the PR
template, and from `CONTRIBUTING.md`. It is CODEOWNERS-protected.

We deliberately apply the same bar to human-written contributions.
There is no "AI-slop tax." If a hand-written PR violates the bar,
it is closed for the same reasons.

## Consequences

- **Easier:** review is fast. Reviewers can scan a PR against a
  checklist and reject without writing long explanations — the
  checklist *is* the explanation. Contributors (human or AI) know
  the bar before they push.
- **Easier:** rejecting low-quality PRs is no longer emotionally
  expensive. The reviewer points at a specific banned pattern or
  slop signature; the contributor knows what to fix.
- **Harder:** the bar excludes a meaningful class of "good enough"
  PRs that would have merged under a softer regime. We accept this
  trade. A project with one owner and dozens of AI-driven PRs per
  day cannot survive on "good enough."
- **Harder:** AI-assisted contributors must materially edit AI
  output before pushing — strip the defensive coding, delete the
  helper-used-once, rename `data` to the thing it actually is. This
  is *exactly* the work the bar exists to demand.
- **Given up:** raw contribution velocity. We are explicitly choosing
  fewer, better PRs over more, mediocre PRs. ADR-0002 already framed
  the principle ("one well-designed feature properly > ten rushed
  features"); ADR-0004 operationalizes it.
- **Migration:** PRs open at the time this ADR merges are not
  retroactively held to the bar. PRs opened after are.

## Alternatives considered

- **Soften ADR-0003 with examples instead of a separate bar.**
  Rejected — ADR-0003 is a process document; the bar is a code
  document. Mixing the two dilutes both.
- **CI-enforce every banned pattern via linters / semgrep rules.**
  Partial adoption (some patterns *are* in `.semgrep/buggy-rules.yml`),
  but rejected as a sole strategy: many slop signatures (vague test
  names, premature kwargs, single-use helpers, comments that
  translate the next line) are review-judgment calls. Pretending a
  linter can enforce them leads to false confidence.
- **Per-author quality tiers (e.g. "trusted human" gets a softer
  bar).** Rejected — the bar is on the **code**, not the **author**.
  An AI-generated PR that meets the bar is welcome; a human-written
  PR that doesn't is not. Per-author tiering creates a political
  surface this project does not need.
- **Reject all AI-assisted PRs.** Rejected as unenforceable and
  philosophically inconsistent with what Buggy *is*. The right
  move is to demand the assisting human do the work the assistant
  cannot.

## Operating note

This ADR will look, in retrospect, either obviously correct or
obviously over-tightened. If the latter, the response is to open
ADR-NNNN that relaxes specific clauses with evidence — not to drift
back to a softer norm in practice.
