"""Score labeled Skillogy rankings offline without inferring retrieval success."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Annotated, Any

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, TypeAdapter, ValidationError

_Text = Annotated[
    str, StringConstraints(min_length=1, max_length=2048, pattern=r"^[^\x00-\x1f\x7f-\x9f]+$")
]
_SkillPath = Annotated[
    str,
    StringConstraints(
        max_length=1024, pattern=r"^/skills/(?:[A-Za-z0-9_-][A-Za-z0-9._-]*/)+SKILL\.md$"
    ),
]
_Paths = Annotated[list[_SkillPath], Field(max_length=1000)]
_FILTERS = ("query", "subdomain", "mitre_id", "tag", "tactic_id")
_MAX_INPUT_BYTES = 1_048_576


class _Query(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    id: Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")]
    expected_paths: _Paths
    query: _Text | None = None
    subdomain: _Text | None = None
    mitre_id: _Text | None = None
    tag: _Text | None = None
    tactic_id: _Text | None = None
    allowed_path_prefixes: Annotated[list[_Text], Field(max_length=64)] | None = None


_QUERIES = TypeAdapter(Annotated[list[_Query], Field(min_length=1, max_length=1000)])
_RANKINGS = TypeAdapter(dict[str, _Paths | None])


class RetrievalEvaluationError(ValueError):
    """The labeled queries or recorded rankings cannot be evaluated."""


def _validate_queries(queries: object, k: int) -> list[dict[str, Any]]:
    if type(k) is not int or not 1 <= k <= 100:
        raise RetrievalEvaluationError("k must be an integer from 1 to 100")
    try:
        parsed = _QUERIES.validate_python(queries, strict=True)
    except ValidationError as exc:
        raise RetrievalEvaluationError("invalid labeled queries") from exc
    if len({query.id for query in parsed}) != len(parsed):
        raise RetrievalEvaluationError("query ids must be unique")
    if any(not any(getattr(query, field) for field in _FILTERS) for query in parsed):
        raise RetrievalEvaluationError("each query requires a retrieval filter")
    return [query.model_dump(exclude_none=True) for query in parsed]


def evaluate_retrieval(
    queries: list[dict[str, Any]],
    ranked_results: dict[str, list[str] | None],
    *,
    k: int = 5,
) -> dict[str, Any]:
    queries = _validate_queries(queries, k)
    try:
        ranked_results = _RANKINGS.validate_python(ranked_results, strict=True)
    except ValidationError as exc:
        raise RetrievalEvaluationError("invalid recorded rankings") from exc
    if set(ranked_results) - {query["id"] for query in queries}:
        raise RetrievalEvaluationError("rankings contain unknown query ids")
    evaluations: list[dict[str, Any]] = []
    for query in queries:
        observed = ranked_results.get(query["id"])
        paths = observed if observed is not None else []
        status = "unavailable" if observed is None else ("ok" if paths else "no_results")
        expected = set(query["expected_paths"])
        relevant = len(set(paths[:k]) & expected)
        evaluations.append(
            query
            | {
                "status": status,
                "ranked_paths": paths,
                "precision_at_k": relevant / k,
                "recall_at_k": relevant / len(expected) if expected else 0.0,
                "reciprocal_rank": next(
                    (1 / rank for rank, path in enumerate(paths, 1) if path in expected), 0.0
                ),
            }
        )
    return {
        "k": k,
        "query_count": len(evaluations),
        "no_result_count": sum(row["status"] == "no_results" for row in evaluations),
        "unavailable_count": sum(row["status"] == "unavailable" for row in evaluations),
        "precision_at_k": sum(row["precision_at_k"] for row in evaluations) / len(evaluations),
        "recall_at_k": sum(row["recall_at_k"] for row in evaluations) / len(evaluations),
        "mrr": sum(row["reciprocal_rank"] for row in evaluations) / len(evaluations),
        "queries": evaluations,
    }


def run_retrieval_evaluation(
    queries: list[dict[str, Any]],
    find_skill: Callable[..., list[dict[str, Any]]],
    *,
    k: int = 5,
) -> dict[str, Any]:
    queries = _validate_queries(queries, k)
    rankings: dict[str, list[str] | None] = {}
    errors: dict[str, str] = {}
    for query in queries:
        filters = {
            key: value for key, value in query.items() if key not in {"id", "expected_paths"}
        }
        try:
            hits = find_skill(**filters, limit=k)
            if not isinstance(hits, list):
                raise RetrievalEvaluationError("find_skill must return a ranked list")
            rankings.update(
                _RANKINGS.validate_python({query["id"]: [hit["path"] for hit in hits]}, strict=True)
            )
        except Exception as exc:
            rankings[query["id"]] = None
            errors[query["id"]] = type(exc).__name__
    report = evaluate_retrieval(queries, rankings, k=k)
    for evaluation in report["queries"]:
        if evaluation["id"] in errors:
            evaluation["error_type"] = errors[evaluation["id"]]
    return report


def _unique_fields(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    if len(dict(pairs)) != len(pairs):
        raise RetrievalEvaluationError("duplicate fields in evaluation input")
    return dict(pairs)


def _read_json(path: Path) -> Any:
    with path.open("rb") as stream:
        payload = stream.read(_MAX_INPUT_BYTES + 1)
    if len(payload) > _MAX_INPUT_BYTES:
        raise RetrievalEvaluationError("evaluation input exceeds 1 MiB")
    return json.loads(payload, object_pairs_hook=_unique_fields)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Offline Skillogy retrieval evaluation")
    parser.add_argument(
        "queries", type=Path, help="JSON labeled queries with id and expected_paths"
    )
    parser.add_argument(
        "rankings", type=Path, help="JSON map of query id to ranked paths; null means unavailable"
    )
    parser.add_argument("--k", type=int, default=5)
    args = parser.parse_args(argv)
    try:
        report = evaluate_retrieval(_read_json(args.queries), _read_json(args.rankings), k=args.k)
    except (
        OSError,
        UnicodeError,
        json.JSONDecodeError,
        RecursionError,
        RetrievalEvaluationError,
    ) as exc:
        sys.stderr.write(f"retrieval evaluation failed ({type(exc).__name__})\n")
        return 2
    sys.stdout.write(json.dumps(report, indent=2, sort_keys=True) + "\n")
    return 2 if report["unavailable_count"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
