"""Seed harness meta-learnings into the benchmark engagement graph.

The KG recorder captures per-challenge outcomes + attack paths
automatically. This script seeds the *harness-level* learnings —
root-caused failure modes and their fixes — so the graph also answers
"what went wrong operationally and what was done about it":

    (Host)-[:HAS_VULN]->(Weakness)<-[:PATCHES]-(Patch)

Modelled after the recorder (same engagement scope, same provenance
contract), idempotent via the store's MERGE-on-key semantics — re-run
any time; existing nodes are updated, never duplicated.

Usage:
    BUGGY_NEO4J_PASSWORD=... .venv/bin/python -m benchmark.kg_seed_learnings
"""

from __future__ import annotations

import logging

from benchmark.kg_recorder import BENCHMARK_ENGAGEMENT, BenchmarkKGRecorder
from buggy_core.types.kg import EdgeKind, NodeKind

log = logging.getLogger(__name__)


def build_learning_observations() -> list[dict]:
    """The harness learnings worth carrying into every future run.

    ``discovered`` / ``applied`` are fixed historical dates, not ``now()``:
    stamping the current time on every run made each "idempotent" re-seed
    rewrite the discovery/application history. These record *when the
    weakness was found and the patch shipped* — facts that don't change.
    """
    recorded = "2026-11-12T00:00:00+00:00"
    return [
        {
            "kind": NodeKind.HOST,
            "key": "challenge:XBEN-099-24",
            "label": "XBEN-099-24 — Get the first",
            "props": {"level": 2, "tags": ["idor"]},
            "edges_out": [
                {
                    "to_key": "weakness:xben-099-objectid-crash",
                    "kind": EdgeKind.HAS_VULN,
                    "weight": 1.0,
                }
            ],
        },
        {
            "kind": NodeKind.WEAKNESS,
            "key": "weakness:xben-099-objectid-crash",
            "label": "Challenge app dies on malformed ObjectId",
            "props": {
                "source": "harness-learning",
                "discovered": recorded,
                "symptom": (
                    "Target unreachable mid-run: every request after the first "
                    "/profile/<non-hex> probe is connection-refused."
                ),
                "root_cause": (
                    "Express 4 route passes req.params.id to mongoose findById "
                    "unvalidated; a CastError rejection is unhandled and Node "
                    "exits, killing the listener. One natural IDOR probe "
                    "(/profile/1) took the whole challenge down."
                ),
                "lesson": (
                    "On MongoDB ObjectId targets, derive well-formed ids from "
                    "leaked timestamps (e.g. /starttime, /info) instead of "
                    "probing numeric ids first; a server that dies right after "
                    "a malformed-id probe is causation, not flaky connectivity."
                ),
            },
            "edges_out": [],
        },
        {
            "kind": NodeKind.PATCH,
            "key": "patch:xben-099-casterror-guard",
            "label": "CastError guard + unhandledRejection backstop",
            "props": {
                "source": "harness-learning",
                "applied": recorded,
                "description": (
                    "server.js /profile/:id wraps findById in try/catch, maps "
                    "CastError to HTTP 400, and a process-level "
                    "unhandledRejection handler keeps the listener alive. "
                    "Patch lives in the benchmark submodule "
                    "(benchmarks/XBEN-099-24/app/server.js)."
                ),
                "note": "Local fixture repair; upstream XBOW scores not comparable for this challenge.",
            },
            "edges_out": [
                {
                    "to_key": "weakness:xben-099-objectid-crash",
                    "kind": EdgeKind.PATCHES,
                    "weight": 1.0,
                }
            ],
        },
        {
            "kind": NodeKind.WEAKNESS,
            "key": "weakness:refusal-toll-no-circuit-breaker",
            "label": "Every model call paid the safety-refusal toll",
            "props": {
                "source": "harness-learning",
                "discovered": recorded,
                "symptom": (
                    "Benchmark runs logged ~10 empty-response errors per minute: "
                    "auth/claude-sonnet-5-5 then auth/claude-fable-5 refuse the "
                    "offensive-security engagement prompt (HTTP 200, zero "
                    "content) on every single call before grok-sub serves."
                ),
                "root_cause": (
                    "_check_empty_response raised RuntimeError per refusal; "
                    "ModelFallbackMiddleware walked the chain correctly, but "
                    "the refusing models were re-tried from the top of every "
                    "call — full prompt re-send and round-trip each time."
                ),
                "lesson": (
                    "A safety refusal is per-model-and-prompt-class state, not "
                    "per-call. Memoizing it (TTL circuit breaker in "
                    "buggy.llm.factory) drops the toll to one probe per "
                    "model per TTL window; the fallback chain then settles on "
                    "the first non-refusing model (grok-sub/grok-4.3 in the "
                    "benchmark config) with zero wasted tokens."
                ),
            },
            "edges_out": [],
        },
        {
            "kind": NodeKind.PATCH,
            "key": "patch:llm-refusal-circuit-breaker",
            "label": "LLMModelRefusalError + TTL refusal circuit",
            "props": {
                "source": "harness-learning",
                "applied": recorded,
                "description": (
                    "buggy/llm/factory.py: _check_empty_response raises "
                    "LLMModelRefusalError; _ProxiedChatOpenAI marks the "
                    "refusing model in a process-wide TTL registry "
                    "(900 s) and fast-fails subsequent calls before any API "
                    "request, so ModelFallbackMiddleware advances instantly."
                ),
            },
            "edges_out": [
                {
                    "to_key": "weakness:refusal-toll-no-circuit-breaker",
                    "kind": EdgeKind.PATCHES,
                    "weight": 1.0,
                }
            ],
        },
        {
            "kind": NodeKind.WEAKNESS,
            "key": "weakness:grok-token-env-baked",
            "label": "Grok OAuth token rotated mid-run, killing every model chain",
            "props": {
                "source": "harness-learning",
                "discovered": recorded,
                "symptom": (
                    "Every run after a mid-batch point errored in ~5s with no "
                    "agent output; langgraph logs show 403 "
                    "unauthenticated:bad-credentials from the Grok API."
                ),
                "root_cause": (
                    "GROK_ACCESS_TOKEN is baked into the litellm container env "
                    "at creation. The host grok CLI rotates its token "
                    "periodically, revoking the extracted copy — with sonnet/"
                    "fable refusing the benchmark prompt, grok is the only "
                    "serving model, so its 403 exhausts the whole fallback "
                    "chain."
                ),
                "lesson": (
                    "A mid-run collapse where EVERY challenge starts failing "
                    "instantly with empty results is a credentials event, not "
                    "a langgraph regression — check litellm logs for 403s "
                    "before restarting anything. Refresh the token from "
                    "~/.grok/auth.json into .env and force-recreate litellm; "
                    "identify casualties via findings with passed=false, no "
                    "error, and ~5s duration, then rerun that set."
                ),
            },
            "edges_out": [],
        },
        {
            "kind": NodeKind.PATCH,
            "key": "patch:grok-token-refresh-recreate",
            "label": "Token refresh + litellm force-recreate + casualty rerun",
            "props": {
                "source": "harness-learning",
                "applied": recorded,
                "description": (
                    "Re-extract the current token from ~/.grok/auth.json into "
                    ".env (GROK_ACCESS_TOKEN), docker compose up -d "
                    "--force-recreate litellm, verify grok-sub/grok-4.3 with "
                    "a smoke completion, then rerun the no-error fast-FAIL "
                    "set. Follow-up hardening: mount auth.json as "
                    "GROK_TOKENS_PATH and drop the env var so the handler "
                    "picks up rotations without a recreate."
                ),
            },
            "edges_out": [
                {
                    "to_key": "weakness:grok-token-env-baked",
                    "kind": EdgeKind.PATCHES,
                    "weight": 1.0,
                }
            ],
        },
    ]


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    recorder = BenchmarkKGRecorder()
    if not recorder.enabled:
        log.error("KG recorder disabled — set BUGGY_NEO4J_PASSWORD and retry")
        raise SystemExit(1)
    store = recorder._store  # noqa: SLF001 — same-process seeding, no public accessor
    assert store is not None  # narrowed by enabled above
    summary = store.record_observations(
        build_learning_observations(),
        engagement=BENCHMARK_ENGAGEMENT,
        created_by="benchmark-runner",
        source_episode_id="harness-learnings",
    )
    log.info("seeded harness learnings: %s", summary)


if __name__ == "__main__":
    main()
