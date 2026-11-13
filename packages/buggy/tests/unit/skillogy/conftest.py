"""Offline graph-driver boundary for real Skillogy retrieval and ranking tests."""

from __future__ import annotations

import math
import re
import socket
import sys
from collections.abc import Callable
from dataclasses import dataclass
from importlib import import_module
from types import ModuleType
from typing import Any, NoReturn, Self, cast

import pytest

from buggy.skillogy import embeddings
from buggy.skillogy.server.neo4j_backend import Neo4jBackend, assert_read_only


@dataclass
class DriverQuery:
    text: str
    timeout: float | None = None

    def __str__(self) -> str:
        return self.text


@pytest.fixture(autouse=True)
def neo4j_query_api(monkeypatch: pytest.MonkeyPatch) -> None:
    try:
        module = import_module("neo4j")
    except ImportError:
        module = ModuleType("neo4j")
        monkeypatch.setitem(sys.modules, "neo4j", module)
    monkeypatch.setattr(module, "Query", DriverQuery, raising=False)


class Records(list[dict[str, Any]]):
    def fetch(self, count: int) -> list[dict[str, Any]]:
        return self[:count]

    def single(self) -> dict[str, Any] | None:
        return self[0] if self else None


class SkillGraphDriver:
    def __init__(self, skills: list[dict[str, Any]]) -> None:
        self.skills = skills
        self.query_vectors: dict[str, list[float]] = {}
        self.failure: Exception | None = None
        self.requests: list[tuple[str, dict[str, Any]]] = []

    def session(self, *, database: str, default_access_mode: str) -> Self:
        assert database == "offline"
        assert default_access_mode == "READ"
        return self

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *args: Any) -> None:
        return None

    def run(
        self, cypher: str | DriverQuery, parameters: dict[str, Any] | None = None, **kwargs: Any
    ) -> Records:
        cypher = str(cypher)
        assert_read_only(cypher)
        params = parameters if parameters is not None else kwargs
        self.requests.append((cypher, params))
        if self.failure is not None:
            raise self.failure
        if "RETURN properties(s) AS props" in cypher:
            matches = [
                skill for skill in self.skills if params["arg"] in (skill["path"], skill["name"])
            ]
            matches.sort(key=lambda skill: skill["path"] != params["arg"])
            return Records([{"props": skill} for skill in matches[:1]])
        semantic = "db.index.vector.queryNodes" in cypher
        skills = [dict(skill) for skill in self.skills]
        if semantic:
            skills = [skill for skill in skills if skill.get("embedding")]
            for skill in skills:
                vector, query = skill["embedding"], params["qvec"]
                skill["score"] = sum(a * b for a, b in zip(vector, query, strict=True)) / (
                    math.sqrt(sum(a * a for a in vector)) * math.sqrt(sum(b * b for b in query))
                )
            skills.sort(key=lambda skill: -skill["score"])
            skills = skills[: params["k"]]
        else:
            skills.sort(key=lambda skill: skill["name"])
        if "toLower($query)" in cypher:
            skills = [
                skill
                for skill in skills
                if any(
                    params["query"].lower() in skill.get(field, "").lower()
                    for field in ("name", "description", "when_to_use")
                )
            ]
        for parameter, field, predicate in (
            ("subdomain", "subdomain", "(:Phase {name: $subdomain})"),
            ("tag", "tags_raw", "(:Tag {name: $tag})"),
            ("mitre_id", "mitre_attack_raw", "(:Technique {id: $mitre_id})"),
            ("tactic_id", "tactic_ids", "(:Tactic {id: $tactic_id})"),
        ):
            if predicate in cypher:
                skills = [
                    skill
                    for skill in skills
                    if params[parameter]
                    in ([skill.get(field)] if parameter == "subdomain" else skill.get(field, []))
                ]
        if "ANY(p IN $allowed_path_prefixes WHERE s.path STARTS WITH p)" in cypher:
            skills = [
                skill
                for skill in skills
                if any(
                    skill["path"].startswith(prefix) for prefix in params["allowed_path_prefixes"]
                )
            ]
        projection = re.findall(r"s\.(\w+) AS (\w+)", cypher.split("RETURN ", 1)[1])
        rows = Records()
        for skill in skills[: params["cand_n"]]:
            row = {alias: skill.get(field) for field, alias in projection}
            row["matched_mitre"] = skill.get("mitre_attack_raw", [])
            row["matched_tags"] = skill.get("tags_raw", [])
            if semantic:
                row["score"] = skill["score"]
            rows.append(row)
        return rows


@pytest.fixture
def make_backend(monkeypatch: pytest.MonkeyPatch) -> Callable[[SkillGraphDriver], Neo4jBackend]:
    def no_network(*args: Any, **kwargs: Any) -> NoReturn:
        raise AssertionError("Offline retrieval must not use the network")

    monkeypatch.setattr(socket.socket, "connect", no_network)
    monkeypatch.setattr(socket, "getaddrinfo", no_network)

    def make(driver: SkillGraphDriver) -> Neo4jBackend:
        backend = Neo4jBackend.__new__(Neo4jBackend)
        backend._driver = cast(Any, driver)
        backend._database = "offline"
        backend._max_rows = 200
        monkeypatch.setattr(embeddings, "embed_text", driver.query_vectors.get)
        return backend

    return make
