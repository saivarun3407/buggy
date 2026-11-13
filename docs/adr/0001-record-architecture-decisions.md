# 0001. Record architecture decisions

- **Status:** Accepted
- **Date:** 2026-06-04
- **Deciders:** @PurpleCHOIms
- **Related:** [docs/adr/README.md](README.md)

## Context

Buggy's architecture has evolved through several iterations
(Purple Team AI → RL → GAN → LLM agents; monolithic agent → planned
multi-agent decomposition; Docker-socket-exec sandbox → HTTP-daemon
sandbox; etc.). Each pivot was deliberate, but the *reasoning* for
those pivots lives in PR descriptions, issue threads, and the implicit
memory of the people who made them.

Several documents under `docs/` already serve a decision-record
purpose — `docs/security/sandbox-isolation.md`,
`docs/security/neo4j-hardening.md`, `docs/security/prompt-injection-defense.md`,
`docs/COWORK.md`. They are excellent narrative docs, but they are
edited in place when the system changes, which makes it hard to
distinguish "the current design" from "the history of how we got here."

With AI-assisted contributions arriving at a pace that exceeds single
maintainer review bandwidth, the cost of *implicit* architectural
knowledge has gone up. A reviewer (or contributing AI agent) needs to
be able to look up "why is the middleware order
SafeCommand → Skills → Filesystem → … and not the reverse?" in a place
that is stable, dated, and append-only — not in a doc that has been
silently rewritten since the decision was made.

## Decision

We adopt the [Michael Nygard ADR format](https://cognitect.com/blog/2011/11/15/documenting-architecture-decisions)
under `docs/adr/`. ADRs are numbered sequentially, append-only, and
CODEOWNERS-gated. Proposed ADRs may be opened by any contributor;
Accepted ADRs require maintainer review per the CODEOWNERS rule on
`docs/adr/**`.

Narrative docs under `docs/security/`, `docs/red-team/`, and elsewhere
continue to exist for current-state explanation and onboarding. ADRs
record the *decision events* that produced the current state. The two
formats are complementary, not competing.

## Consequences

- **Easier:** new contributors (human or AI) can find decision rationale
  in a known location. PRs that contradict an Accepted ADR are easy to
  flag. Reversals are explicit (`Superseded by ADR-NNNN`) rather than
  silent doc edits.
- **Harder:** non-obvious decisions now require a small amount of
  upfront writing. (We accept this; the cost is paid once, the benefit
  accrues forever.)
- **Given up:** the ability to silently change architecture by editing
  the narrative doc. This is intentional.
- **Migration:** existing decisions already documented in
  `docs/security/*.md` and `docs/COWORK.md` are not retroactively
  reformatted as ADRs. New decisions (and reversals of existing ones)
  use the ADR format from here forward. We may backfill specific
  high-value decisions as ADRs case-by-case, but we do not mass-convert.

## Alternatives considered

- **No ADRs, keep editing narrative docs in place.** Status quo. Loses
  the audit trail that matters for AI-assisted-contribution review.
- **RFC-style longer-form docs.** Rejected as too heavyweight for the
  decision velocity. RFCs work for cross-team projects; this is a
  small-team repo with a sole owner today.
- **Track decisions in GitHub issues/PRs only.** Rejected — issues drift,
  PRs get merged and become invisible in normal browsing, and neither
  surface has a stable URL scheme contributors can cite from skill or
  prompt files.
