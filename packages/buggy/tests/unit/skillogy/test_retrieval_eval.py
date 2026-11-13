"""Offline defensive retrieval regression through the public graph-backed seam."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from buggy.skillogy.retrieval_eval import (
    RetrievalEvaluationError,
    evaluate_retrieval,
    main,
    run_retrieval_evaluation,
)
from buggy.skillogy.server.neo4j_backend import Neo4jBackend
from tests.unit.skillogy.conftest import SkillGraphDriver

SHARED = "/skills/shared/defensive-assessment/"
TLS = SHARED + "tls-inspection/SKILL.md"
CAPTURE = SHARED + "http-capture-review/SKILL.md"
SARIF = "/skills/standard/analyst/sarif-review/SKILL.md"
DNS = "/skills/standard/recon/dns-inventory/SKILL.md"
NETWORK = "/skills/standard/recon/network-inventory/SKILL.md"
DISTRACTOR = SHARED + "general-evidence/SKILL.md"
OUTSIDE = "/skills/standard/exploit/tls/SKILL.md"


@pytest.fixture
def defensive_graph() -> SkillGraphDriver:
    specifications = [
        ("general-evidence", DISTRACTOR, "General TLS evidence context", "analyst", [0.0, 1.0]),
        ("tls-inspection", TLS, "Review TLS certificates and protocols", "analyst", [1.0, 0.0]),
        ("http-capture-review", CAPTURE, "Review HTTP capture headers", "analyst", [0.8, 0.2]),
        ("sarif-review", SARIF, "Review SARIF static analysis artifacts", "analyst", [0.0, 1.0]),
        ("dns-inventory", DNS, "Bounded DNS record inventory", "reconnaissance", [0.0, 1.0]),
        ("network-inventory", NETWORK, "Bounded network inventory", "reconnaissance", [0.0, 1.0]),
        ("a-outside-tls", OUTSIDE, "TLS exploit playbook", "analyst", [1.0, 0.0]),
    ]
    return SkillGraphDriver(
        [
            {
                "name": name,
                "path": path,
                "description": description,
                "when_to_use": description,
                "subdomain": subdomain,
                "tags_raw": ["defensive-assessment"],
                "mitre_attack_raw": ["T1595"] if subdomain == "reconnaissance" else ["T1190"],
                "tactic_ids": ["TA0043"] if subdomain == "reconnaissance" else ["TA0001"],
                "embedding": vector,
            }
            for name, path, description, subdomain, vector in specifications
        ]
    )


def test_evaluation_scores_actual_ranked_paths_from_public_find_skill(
    defensive_graph: SkillGraphDriver,
    make_backend: Callable[[SkillGraphDriver], Neo4jBackend],
) -> None:
    queries: list[dict[str, Any]] = [
        {
            "id": "tls-review",
            "query": "TLS",
            "subdomain": "analyst",
            "tag": "defensive-assessment",
            "allowed_path_prefixes": ["/skills/shared/"],
            "expected_paths": [TLS],
        }
    ]
    report = run_retrieval_evaluation(queries, make_backend(defensive_graph).find_skill, k=2)
    assert report["query_count"] == 1
    assert report["no_result_count"] == 0
    assert report["unavailable_count"] == 0
    assert report["precision_at_k"] == 0.5
    assert report["recall_at_k"] == 1.0
    assert report["mrr"] == 0.5
    assert report["queries"][0]["ranked_paths"] == [DISTRACTOR, TLS]
    assert report["queries"][0]["reciprocal_rank"] == 0.5
    assert report["queries"][0]["status"] == "ok"
    assert OUTSIDE not in report["queries"][0]["ranked_paths"]


def test_graph_failure_is_unavailable_not_an_empty_success(
    defensive_graph: SkillGraphDriver,
    make_backend: Callable[[SkillGraphDriver], Neo4jBackend],
) -> None:
    defensive_graph.failure = ConnectionError("synthetic-private-error-details")
    queries = [{"id": "unavailable", "query": "TLS", "expected_paths": [TLS]}]
    report = run_retrieval_evaluation(queries, make_backend(defensive_graph).find_skill, k=2)
    assert report["unavailable_count"] == 1
    assert report["no_result_count"] == 0
    assert report["mrr"] == report["precision_at_k"] == report["recall_at_k"] == 0.0
    assert report["queries"][0]["status"] == "unavailable"
    assert report["queries"][0]["ranked_paths"] == []
    assert report["queries"][0]["error_type"] == "ConnectionError"
    assert "synthetic-private-error-details" not in str(report)


def test_missing_rankings_and_duplicates_never_inflate_aggregate_metrics() -> None:
    queries = [
        {"id": "partial", "query": "TLS", "expected_paths": [TLS, CAPTURE]},
        {"id": "short", "query": "SARIF", "expected_paths": [SARIF]},
        {"id": "empty", "query": "unknown", "expected_paths": []},
        {"id": "down", "query": "TLS", "expected_paths": [TLS]},
        {"id": "missing", "query": "SARIF", "expected_paths": [SARIF]},
    ]
    rankings = {
        "partial": [DISTRACTOR, TLS, TLS, CAPTURE],
        "short": [SARIF],
        "empty": [],
        "down": None,
    }
    report = evaluate_retrieval(queries, rankings, k=3)
    assert report["query_count"] == 5
    assert report["unavailable_count"] == 2
    assert report["no_result_count"] == 1
    assert report["precision_at_k"] == pytest.approx(2 / 15)
    assert report["recall_at_k"] == 0.3
    assert report["mrr"] == 0.3
    assert report["queries"][0]["ranked_paths"] == rankings["partial"]
    assert report["queries"][0]["precision_at_k"] == pytest.approx(1 / 3)
    assert report["queries"][0]["recall_at_k"] == 0.5
    assert report["queries"][2]["recall_at_k"] == 0.0
    assert [row["status"] for row in report["queries"]] == [
        "ok",
        "ok",
        "no_results",
        "unavailable",
        "unavailable",
    ]


@pytest.mark.parametrize("k", [0, -1, 101, True, 1.5, "2"])
def test_metric_cutoff_must_match_the_bounded_retrieval_limit(k: Any) -> None:
    with pytest.raises(RetrievalEvaluationError):
        evaluate_retrieval(
            [{"id": "q", "query": "TLS", "expected_paths": [TLS]}], {"q": [TLS]}, k=k
        )


@pytest.mark.parametrize(
    "changes",
    [
        {"id": True},
        {"expected_paths": None},
        {"expected_paths": TLS},
        {"expected_paths": [True]},
        {"expected_paths": ["tls-inspection"]},
        {"query": None},
        {"query": "\nTLS"},
        {"allowed_path_prefixes": "/skills/shared/"},
        {"available_capabilities": ["tls-inspection"]},
    ],
)
def test_invalid_labels_and_invented_filters_raise_a_named_error(changes: dict[str, Any]) -> None:
    query = {"id": "q", "query": "TLS", "expected_paths": [TLS]} | changes
    with pytest.raises(RetrievalEvaluationError):
        evaluate_retrieval([query], {"q": [TLS]}, k=2)


@pytest.mark.parametrize("rankings", [[], {"typo": [TLS]}, {"q": TLS}, {"q": {}}, {"q": [None]}])
def test_malformed_recorded_rankings_are_not_scored_as_success(rankings: Any) -> None:
    with pytest.raises(RetrievalEvaluationError):
        evaluate_retrieval([{"id": "q", "query": "TLS", "expected_paths": [TLS]}], rankings, k=2)


@pytest.mark.parametrize(
    "queries", [[], [{"id": "q", "query": "TLS", "expected_paths": [TLS]}] * 2]
)
def test_empty_or_duplicate_query_sets_do_not_create_misleading_averages(queries: Any) -> None:
    with pytest.raises(RetrievalEvaluationError):
        evaluate_retrieval(queries, {}, k=2)


@pytest.mark.parametrize("path", [None, "tls-inspection", 42])
def test_invalid_paths_from_graph_results_are_retrieval_unavailable(
    make_backend: Callable[[SkillGraphDriver], Neo4jBackend], path: object
) -> None:
    driver = SkillGraphDriver([{"name": "TLS review", "path": path}])
    report = run_retrieval_evaluation(
        [{"id": "tls", "query": "TLS", "expected_paths": [TLS]}],
        make_backend(driver).find_skill,
        k=2,
    )
    assert report["unavailable_count"] == 1
    assert report["no_result_count"] == 0
    assert report["queries"][0]["ranked_paths"] == []
    assert report["mrr"] == 0.0


@pytest.mark.parametrize("state", ["matched", "empty", "missing"])
def test_offline_cli_scores_recorded_public_retrieval_and_flags_missing_observations(
    tmp_path: Path,
    defensive_graph: SkillGraphDriver,
    make_backend: Callable[[SkillGraphDriver], Neo4jBackend],
    state: str,
) -> None:
    query = "network inventory" if state != "empty" else "unmatchable audit query"
    queries = [{"id": "inventory", "query": query, "expected_paths": [NETWORK]}]
    hits = make_backend(defensive_graph).find_skill(query=query, limit=2)
    rankings = {"inventory": [hit["path"] for hit in hits]} if state != "missing" else {}
    labels_path, rankings_path = tmp_path / "queries.json", tmp_path / "rankings.json"
    labels_path.write_text(json.dumps(queries), encoding="utf-8")
    rankings_path.write_text(json.dumps(rankings), encoding="utf-8")
    completed = subprocess.run(
        [
            sys.executable,
            "-B",
            "-m",
            "buggy.skillogy.retrieval_eval",
            str(labels_path),
            str(rankings_path),
            "--k",
            "2",
        ],
        cwd=Path(__file__).resolve().parents[5],
        capture_output=True,
        text=True,
        check=False,
        env={
            "PATH": os.defpath,
            "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1",
            "PYTHON_DOTENV_DISABLED": "1",
            "PYTHONDONTWRITEBYTECODE": "1",
            "BUGGY_SKIP_BOOT": "1",
            "BUGGY_TELEMETRY": "off",
            "DO_NOT_TRACK": "1",
        },
    )
    assert completed.returncode == (2 if state == "missing" else 0), completed.stderr
    report = json.loads(completed.stdout)
    assert report["unavailable_count"] == (state == "missing")
    assert report["no_result_count"] == (state == "empty")
    assert report["queries"][0]["ranked_paths"] == ([NETWORK] if state == "matched" else [])
    assert report["precision_at_k"] == (0.5 if state == "matched" else 0.0)
    assert report["mrr"] == (1.0 if state == "matched" else 0.0)
    assert json.loads(labels_path.read_text(encoding="utf-8")) == queries
    assert json.loads(rankings_path.read_text(encoding="utf-8")) == rankings


@pytest.mark.parametrize(
    "contents",
    [None, "{", "[]", "{}" + " " * 1_048_577, '{"q": null, "q": [' + json.dumps(TLS) + "]}"],
    ids=["missing-file", "invalid-json", "invalid-schema", "oversized", "duplicate-observation"],
)
def test_cli_rejects_unreadable_ambiguous_or_oversized_input_without_emitting_metrics(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], contents: str | None
) -> None:
    labels, rankings = tmp_path / "labels.json", tmp_path / "rankings.json"
    labels.write_text(
        json.dumps([{"id": "q", "query": "TLS", "expected_paths": [TLS]}]), encoding="utf-8"
    )
    if contents is not None:
        rankings.write_text(contents, encoding="utf-8")
    assert main([str(labels), str(rankings), "--k", "2"]) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "retrieval evaluation failed" in captured.err


@pytest.mark.parametrize(
    ("filters", "expected", "ranked"),
    [
        (
            {
                "query": "network inventory",
                "subdomain": "reconnaissance",
                "mitre_id": "T1595",
                "tactic_id": "TA0043",
            },
            [NETWORK],
            [NETWORK],
        ),
        ({"query": "DNS", "tag": "defensive-assessment"}, [DNS], [DNS]),
        ({"query": "HTTP capture", "subdomain": "analyst"}, [CAPTURE], [CAPTURE]),
        (
            {
                "query": "SARIF",
                "subdomain": "analyst",
                "allowed_path_prefixes": ["/skills/standard/analyst/"],
            },
            [SARIF],
            [SARIF],
        ),
        (
            {
                "subdomain": "reconnaissance",
                "tag": "defensive-assessment",
                "mitre_id": "T1595",
                "tactic_id": "TA0043",
            },
            [DNS, NETWORK],
            [DNS, NETWORK],
        ),
        ({"query": "TLS", "subdomain": "reconnaissance"}, [], []),
        ({"query": "TLS", "tag": "nonexistent-tag"}, [], []),
        ({"query": "DNS", "mitre_id": "T1190"}, [], []),
        ({"query": "DNS", "tactic_id": "TA0001"}, [], []),
        (
            {
                "query": "SARIF",
                "allowed_path_prefixes": ["/skills/standard/recon/", "/skills/shared/"],
            },
            [SARIF],
            [],
        ),
        ({"query": "find likely CVEs in static-analysis reports"}, [SARIF], []),
    ],
    ids=[
        "network",
        "dns",
        "http-artifact",
        "sarif-artifact",
        "facets-only",
        "phase-filter",
        "tag-filter",
        "technique-filter",
        "tactic-filter",
        "role-acl",
        "lexical-paraphrase-miss",
    ],
)
def test_defensive_queries_preserve_filters_and_measure_misses_honestly(
    defensive_graph: SkillGraphDriver,
    make_backend: Callable[[SkillGraphDriver], Neo4jBackend],
    filters: dict[str, Any],
    expected: list[str],
    ranked: list[str],
) -> None:
    report = run_retrieval_evaluation(
        [{"id": "defensive", "expected_paths": expected} | filters],
        make_backend(defensive_graph).find_skill,
        k=3,
    )
    assert report["queries"][0]["ranked_paths"] == ranked
    assert report["no_result_count"] == (not ranked)
    assert report["unavailable_count"] == 0
    assert report["precision_at_k"] == len(ranked) / 3
    assert report["recall_at_k"] == (1.0 if ranked else 0.0)
    assert report["mrr"] == (1.0 if ranked else 0.0)


def test_public_hybrid_ranking_changes_measured_rr_without_leaking_outside_acl(
    defensive_graph: SkillGraphDriver, make_backend: Callable[[SkillGraphDriver], Neo4jBackend]
) -> None:
    backend = make_backend(defensive_graph)
    queries = [
        {
            "id": "tls",
            "query": "TLS",
            "expected_paths": [TLS],
            "allowed_path_prefixes": ["/skills/shared/"],
        }
    ]
    lexical = run_retrieval_evaluation(queries, backend.find_skill, k=2)
    defensive_graph.query_vectors["TLS"] = [1.0, 0.0]
    hybrid = run_retrieval_evaluation(queries, backend.find_skill, k=2)
    assert lexical["queries"][0]["ranked_paths"] == [DISTRACTOR, TLS]
    assert hybrid["queries"][0]["ranked_paths"] == [TLS, DISTRACTOR]
    assert lexical["mrr"] == 0.5 and hybrid["mrr"] == 1.0
    assert OUTSIDE not in hybrid["queries"][0]["ranked_paths"]
    assert hybrid["unavailable_count"] == 0
