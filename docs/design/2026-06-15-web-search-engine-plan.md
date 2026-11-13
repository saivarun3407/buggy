# Web Search/Fetch Engine — Design & Implementation Plan

> Branch: `feat/web-search-engine` (worktree). Supersedes #605 (ADR-0010) and
> #650 (`web_search`) — both rewritten from scratch per maintainer decision
> (2026-06-15). Precisely references `fivetaku/insane-search` for the engine,
> but **inverts its governance** to fit Buggy's RoE / network-isolation
> invariants.

## 0. Decisions locked

1. **All external web egress runs inside the sandbox** (not the management/
   langgraph process). The light-curl-agent-side option is rejected.
2. **From scratch**: rewrite ADR-0010 and the `web_search` tool; add `web_fetch`;
   build a new fetch engine. Close #605 and #650.

## 1. What we adopt from insane-search (engine intelligence)

Transferable, already site-agnostic — port with attribution:

- **Verdict model + 4-layer validation** (`validators.py`): challenge markers /
  size fingerprints / cookie sensor (`_abck=~-1~`) / `success_selectors`.
  Principle: **HTTP 200 is an inspection-start condition, not success.**
  Verdicts: `STRONG_OK | WEAK_OK | CHALLENGE | BLOCKED | UNKNOWN`.
- **WAF detection as a ranking** (`waf_detector.py` + `waf_profiles.yaml`):
  `(profile_id, confidence)` list, never a single verdict; graceful in-code
  default when YAML/PyYAML missing. = the ADR's "escalate-on-signal".
- **Grid planner + phases** (`fetch_chain.py`): probe → detect → grid
  (`url_transforms × tls_impersonate × referer`, exhaustive, no exit on first
  200) → browser fallback. `FetchResult.trace` records every attempt.
- **URL transforms** (`url_transforms.py`): domain-agnostic rules.
- **Capability-matched executor** (`executor.py`): which browser tier for which
  WAF capability tag.
- **No-Site-Name bias linter** (`bias_check.py`): CI gate forbidding hardcoded
  site domains/brands/selectors in the engine. Maps 1:1 to Buggy's
  generic-skill scoping rule.

## 2. What we invert (Buggy governance)

| insane-search | Buggy |
|---|---|
| anti-allowlist "try everything" | every hop gated by `evaluate_target`, **fail-closed** |
| in-process browser/curl | **runs inside the sandbox** (sandbox-net) |
| deps auto-installed at runtime | **declared in the sandbox image at build time**, CODEOWNERS-gated; never `pip install` at runtime |
| raw output to model | wrapped via `UntrustedOutput` / `PromptInjectionShield` |
| stealth/TLS-impersonation always on | **default-off, per-engagement opt-in** (mirrors `allow_sensitive_tlds`) |
| Phase-0 platform-API index hardcodes platforms | omit from engine; OSINT platform recipes (if any) live in skills/refs, never engine code |

## 3. Sandbox routing — how "all egress in sandbox" stays invariant-safe

CLAUDE.md invariant: *"Bash tool is the single execution surface — all commands
flow through `DockerSandbox.execute_tmux()`. Do not add side-channel exec paths."*

**Chosen mechanism: run the engine inside the sandbox via the existing bash
execution surface. No new HTTP route, no side channel.**

```
web_search(query) / web_fetch(url)   [management process — the @tool wrapper]
  │  1. RoE gate (management side): evaluate_target(host) — fail-closed
  │     (web_search: provider-allowlisted + OSINT target-exempt + audited;
  │      web_fetch: target-gated)
  │  2. dispatch into sandbox via the bash surface:
  │     execute_tmux("python3 -m buggy_web <verb> <args> --json")
  ▼
[sandbox container, sandbox-net]
  engine: probe → detect → grid → (browser fallback) → validate
  • physical egress happens HERE, behind the nftables/DNS allowlist
    (middleware/egress.py compiled from roe.json:machine_enforcement)
  • deps (curl_cffi, bs4, pyyaml, playwright) baked into the sandbox image
  • emits FetchResult JSON to stdout; full content → sandbox scratch file,
    path returned (mirrors bash >15K offload)
  ▼
  3. tool parses FetchResult JSON
  4. UntrustedOutput wrap
  5. return (trace summary shows which bypass path succeeded → OPSEC audit)
```

Double enforcement: tool-side `evaluate_target` (fast fail, scope+audit) **and**
the authoritative sandbox-edge nftables egress allowlist. Stealth/browser tiers
can only reach in-scope, allowlisted destinations.

Open question for the ADR: the engine ships as a sandbox-side package. Decide its
home — `containers/sandbox/` payload vs a `buggy` subpackage copied into the
image. Leaning: a self-contained `buggy/sandbox_web/` engine package
installed into the sandbox image (testable in-repo, shipped to sandbox).

## 4. Module layout (proposed)

```
packages/buggy/buggy/
  sandbox_web/                 # the engine — runs INSIDE the sandbox
    __init__.py                # fetch() public contract
    __main__.py                # `python3 -m buggy_web <verb> ...` CLI (JSON out)
    validators.py              # Verdict + 4-layer validate()  [port]
    waf_detector.py            # ranking detect() + profile loader  [port]
    waf_profiles.yaml          # WAF product profiles  [port, site-agnostic]
    url_transforms.py          # domain-agnostic transforms  [port]
    fetch_chain.py             # probe→detect→grid→fallback  [port + RoE hook]
    executor.py                # browser-tier selection (sandbox playwright)  [port, re-placed]
    providers.py               # web_search provider allowlist abstraction  [new]
    bias_check.py              # No-Site-Name CI linter  [port]
  tools/web/
    search.py                  # web_search @tool wrapper (management side)  [rewrite of #650]
    fetch.py                   # web_fetch @tool wrapper (management side)   [new]
  middleware/roe.py            # add web_search/web_fetch to GATED_TOOL_NAMES + extractors
  middleware/untrusted_output.py  # add web_search, web_fetch to UNTRUSTED_TOOL_NAMES
docs/adr/0010-open-web-acquisition.md   # rewritten ADR (insane-search-derived, all-sandbox)
containers/sandbox/...        # install engine deps + package into image
```

## 5. Implementation phases (TDD — test first each step)

- **P1 — ADR rewrite.** New ADR-0010: decision = insane-search-derived
  multi-phase engine, all egress in sandbox via bash surface, RoE fail-closed,
  no runtime install, UntrustedOutput wrap, No-Site-Name rule, `web_search` +
  `web_fetch`. Status Proposed → owner-accept.
- **P2 — Engine core (pure, no network).** Port `validators`, `waf_detector`,
  `waf_profiles`, `url_transforms`, `bias_check` with unit tests (these are
  pure/parse-only — fast, deterministic). Run `bias_check` as a new CI gate.
- **P3 — fetch_chain + executor.** Grid + browser-tier selection, with the RoE
  hook injected per attempt (every transformed URL re-validated against scope).
  Tests use `curl_cffi`/response mocks (no real egress), like #654/#656 used
  `httpx.MockTransport`.
- **P4 — `__main__` CLI + JSON contract.** Stdout schema (FetchResult +
  content-offload path). Tests on the CLI surface.
- **P5 — Tool wrappers (management side).** `web_search` (provider allowlist,
  OSINT exemption, audit) and `web_fetch` (target-gated, escalate-on-signal),
  both dispatching into the sandbox via the bash surface and `UntrustedOutput`-
  wrapped. Fix #650's two blockers by construction (state-based workspace, in
  `UNTRUSTED_TOOL_NAMES`). Tests through the real `@tool` entry + RoE middleware.
- **P6 — Sandbox image.** Bake engine + deps (curl_cffi/bs4/pyyaml; playwright
  optional tier) into `containers/sandbox`. Smoke via `make smoke`/dogfood.
- **P7 — Wire to agents.** Add to the appropriate agent tool lists by name
  (osint/recon), not just the RESEARCH/WEB bundle (the #654 orphan lesson).
- **P8 — Docs + CHANGELOG.** `docs/tools/web-search.md`, `web-fetch.md`.

## 6. Test strategy

- Pure modules (P2): exhaustive unit tests, deterministic.
- Network modules (P3-P5): mock transport; assert RoE fail-closed on
  out-of-scope hops, UntrustedOutput wrapping, audit emission through the real
  tool entrypoint (not just the library helper — #650's test gap).
- `bias_check` runs in CI (new gate) + locally.
- All under `packages/buggy/tests/unit/...` so `make ci-test` collects them
  (the #651 lesson).

## 7. Disposition of #605 / #650

- Close #605: ADR rewritten here as the new 0010.
- Close #650: `web_search` rebuilt on the engine here; its two blockers fixed by
  construction. Salvage from #650: the DDG redirect-unwrapper + provider idea →
  `providers.py`.
