# 0003. AI-assisted contribution self-review charter

- **Status:** Accepted
- **Date:** 2026-06-04
- **Deciders:** @PurpleCHOIms
- **Related:** [CONTRIBUTING_AGENT.md](../../CONTRIBUTING_AGENT.md), [docs/COWORK.md](../COWORK.md), [ADR-0002](0002-pr-tiering-and-blast-radius.md)

## Context

A non-trivial fraction of incoming contributions are produced with the
help of AI coding agents (Claude, Codex, Copilot, Cursor, Gemini,
in-house tools). This is fine — and on the offensive-AI mission this
project is built around, philosophically consistent — but it changes
the failure modes a reviewer has to defend against:

- **Volume.** A single contributor can credibly open more PRs in a day
  than the owner can review carefully in a week. "Passing tests" is no
  longer a sufficient quality signal at that ratio.
- **Confident-looking surface, shallow grounding.** AI-generated diffs
  read well and obey the project's lint config. They can still be wrong
  in ways that only surface in production: weakened RoE checks,
  silently-broadened public APIs, opportunistic refactors that survive
  CI but corrupt blame history.
- **Drive-by changes.** AI assistants reflexively "improve" adjacent
  code. The four Karpathy coding guidelines already on file
  (Think Before Coding / Simplicity First / Surgical Changes /
  Goal-Driven Execution) push against this; we want them visibly
  embedded in the contribution flow, not assumed.
- **Identity blur.** `Co-Authored-By: Claude` trailers are already
  rejected per `docs/COWORK.md §4.5`. That rejection only makes sense
  if there is also a positive statement of what the human author *is*
  responsible for when they used an AI tool.

The repo's automated layers (CI, basedpyright, Semgrep, gitleaks,
hadolint, shellcheck, the existing compose test, the new isolation
test) catch a large and growing class of mechanical mistakes. They do
not — and structurally cannot — catch architecture drift, OPSEC
softening in prompts, or scope inflation. Those are review-tier
concerns.

## Decision

We add a top-level `CONTRIBUTING_AGENT.md` charter that:

1. Restates that the human opening the PR is the author-of-record and
   the reviewer-of-record, regardless of which tool produced the diff.
2. Lists the **hard rules** — violations close the PR.
3. Provides a **self-review checklist** covering intent, scope and
   shape, blast-radius classification, verification, and honesty.
4. Catalogs common **AI-assistant anti-patterns** with their
   project-specific failure mode.
5. Names the escalation paths (ADR, SECURITY.md, issue first) for cases
   that do not fit the standard flow.

The charter is referenced from the PR template, from `CONTRIBUTING.md`,
and from ADR-0002. CODEOWNERS protects the charter itself
(`CONTRIBUTING_AGENT.md` is Tier-owner per ADR-0002): future changes
to the rules require maintainer review, not a drive-by edit.

We deliberately do **not** add a "was AI used?" checkbox to the PR
template. We tried that mentally and rejected it — false negatives are
free and undetectable, and a checkbox normalizes the question rather
than the conduct. The charter applies regardless of disclosure.

## Consequences

- **Easier:** maintainer review of AI-assisted PRs has a concrete
  document to cite. Contributors who have not run the checklist can be
  redirected without re-explaining the policy each time.
- **Harder:** AI-assisted contributors must do real self-review work
  before opening a PR — reading the diff, naming the anti-goal,
  attesting verification. That is the point.
- **Given up:** the implicit norm that "if CI is green, ship it."
  Replaced with "if CI is green AND the contributor has done the
  self-review AND the change matches the stated intent, ship it."
- **Migration:** existing PRs in flight are not retroactively held to
  the charter. New PRs opened after this ADR is merged are.

## Alternatives considered

- **Embed the charter inside `CONTRIBUTING.md`.** Rejected — dilutes
  the existing guide, which is read primarily by first-time human
  contributors. A separate, named document makes the AI-assisted case
  a first-class concern.
- **CI-enforce the charter (e.g. a workflow that requires checkboxes
  to be ticked).** Rejected for now — easy to game, easy to false-tick.
  The charter is a *trust contract*, not a *gate*. If a contributor
  cannot be trusted to self-review honestly, no checkbox-counting
  workflow will save the review.
- **Restrict AI-assisted contributions entirely.** Rejected as
  unenforceable and philosophically inconsistent with the project's
  own thesis. The right move is to raise the bar on what an
  AI-assisted PR must demonstrate before it merges, not to ban the
  practice.
