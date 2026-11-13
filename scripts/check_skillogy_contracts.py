from __future__ import annotations

import argparse
import json
import os
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from fastapi.testclient import TestClient

from buggy.skillogy.builder.emit import emit_cypher
from buggy.skillogy.builder.model import Node
from buggy.skillogy.builder.skills import emit_skill_records
from buggy.skillogy.retrieval_eval import run_retrieval_evaluation
from buggy.skillogy.server.app import build_app
from buggy.skillogy.server.neo4j_backend import Neo4jBackend


class SkillogySmokeError(RuntimeError):
    pass


def verify(skills_root: Path, uri: str) -> dict[str, Any]:
    endpoint = urlsplit(uri)
    if endpoint.scheme != "bolt" or endpoint.hostname != "neo4j-fixture" or endpoint.port != 7687:
        raise SkillogySmokeError("Only the isolated neo4j-fixture endpoint is supported")
    if os.environ.get("BUGGY_LLM__PROXY_URL") or os.environ.get("BUGGY_LLM__PROXY_API_KEY"):
        raise SkillogySmokeError("Live model providers must be disabled for this fixture")
    prefix = "/skills/shared/defensive-assessment/"
    nodes, edges = emit_skill_records(
        skills_root,
        commit_sha="container-smoke",
        built_at=datetime(2025, 1, 1, tzinfo=timezone.utc),
    )
    selected = [
        node
        for node in nodes
        if node.label == "Skill" and node.properties["path"].startswith(prefix)
    ]
    names = {node.key for node in selected}
    if len(selected) != 8:
        raise SkillogySmokeError("The defensive fixture must contain exactly eight skills")
    selected_edges = [
        edge
        for edge in edges
        if edge.from_label == "Skill"
        and edge.from_key in names
        and edge.edge_type in {"IN_PHASE", "TAGGED"}
    ]
    tag_names = {edge.to_key for edge in selected_edges if edge.to_label == "Tag"}
    selected += [node for node in nodes if node.label == "Tag" and node.key in tag_names]
    selected.append(Node(label="Phase", key_field="name", properties={"name": "analyst"}))
    with closing(
        Neo4jBackend(uri=uri, user="neo4j", password="isolated-fixture", database="neo4j")
    ) as backend:
        if backend.run_cypher_read("MATCH (n) RETURN count(n) AS total") != [{"total": 0}]:
            raise SkillogySmokeError("Refusing to modify a nonempty database")
        statements = backend.bulk_ingest_cypher(emit_cypher(selected, selected_edges))
        if backend.health()["skill_count"] != 8:
            raise SkillogySmokeError("The compiled skills did not round-trip into Neo4j")
        with TestClient(build_app(backend, api_key="fixture-token")) as client:
            request = {
                "query": "authenticated",
                "subdomain": "analyst",
                "allowed_path_prefixes": [prefix],
            }
            if client.post("/v1/skills:find", json=request).status_code != 401:
                raise SkillogySmokeError("Skillogy accepted an unauthenticated request")
            response = client.post(
                "/v1/skills:find", json=request, headers={"Authorization": "Bearer fixture-token"}
            )
            response.raise_for_status()
            hits = response.json()["hits"]
            if not hits or any(
                hit["assessment_contract"]["version"] != 1 or hit["commit_sha"] != "container-smoke"
                for hit in hits
            ):
                raise SkillogySmokeError("Skillogy omitted compiled contracts or provenance")
            denied = client.post(
                "/v1/skills:find",
                json=request | {"allowed_path_prefixes": ["/skills/unavailable/"]},
                headers={"Authorization": "Bearer fixture-token"},
            )
            denied.raise_for_status()
            if denied.json()["hits"]:
                raise SkillogySmokeError("Skillogy did not enforce the requested path boundary")
        cases = [
            {
                "id": slug,
                "query": f"defensive-{slug}",
                "expected_paths": [f"{prefix}{slug}/SKILL.md"],
            }
            for slug in (
                "authenticated-surface-review",
                "oauth-consent-review",
                "remediation-retest",
            )
        ]
        evaluation = run_retrieval_evaluation(cases, backend.find_skill, k=3)
        if evaluation["mrr"] != 1 or evaluation["unavailable_count"]:
            raise SkillogySmokeError("Native graph retrieval missed an exact defensive skill")
        return {
            "skills": 8,
            "ingested_statements": statements,
            "retrieval_queries": len(cases),
            "mrr": evaluation["mrr"],
            "auth_and_acl": "verified",
        }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Check compiled defensive skills against a fresh isolated Neo4j fixture"
    )
    parser.add_argument("--skills-root", required=True, type=Path)
    parser.add_argument("--uri", default="bolt://neo4j-fixture:7687")
    args = parser.parse_args(argv)
    print(json.dumps(verify(args.skills_root, args.uri), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
