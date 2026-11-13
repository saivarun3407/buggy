"""Agent reads must stop when a graph-driver transaction deadline expires."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any, Self, cast

import pytest

from buggy.skillogy.server.neo4j_backend import Neo4jBackend

from .conftest import DriverQuery, Records


class _DriverDeadlineExceeded(TimeoutError):
    pass


class _SlowGraphDriver:
    """A graph-driver boundary simulating a six-second read."""

    def session(self, *, database: str, default_access_mode: str) -> Self:
        assert (database, default_access_mode) == ("offline", "READ")
        return self

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *args: Any) -> None:
        return None

    def run(
        self, query: str | DriverQuery, parameters: dict[str, Any] | None = None, **kwargs: Any
    ) -> Records:
        if isinstance(query, DriverQuery) and query.timeout is not None and 0 < query.timeout < 6:
            raise _DriverDeadlineExceeded(f"transaction exceeded {query.timeout:g}s")
        return Records()


@pytest.mark.parametrize(
    "read",
    [
        lambda backend: backend.load_skill("/skills/shared/demo/SKILL.md"),
        lambda backend: backend.health(),
        lambda backend: backend.query_moc_summary("reconnaissance"),
        lambda backend: backend.traverse("/skills/shared/demo/SKILL.md"),
        lambda backend: backend.run_cypher_read("MATCH (s:Skill) RETURN s"),
        lambda backend: backend._find_lexical("demo", [], None, {}, 10),
        lambda backend: backend._find_semantic([0.1, 0.2], [], None, {}, 10),
    ],
    ids=["load", "health", "moc", "traverse", "cypher", "lexical", "semantic"],
)
def test_runtime_reads_stop_when_the_driver_deadline_expires(
    read: Callable[[Neo4jBackend], Any],
) -> None:
    backend = Neo4jBackend.__new__(Neo4jBackend)
    backend._database = "offline"
    backend._driver = cast(Any, _SlowGraphDriver())
    backend._max_rows = 20

    with pytest.raises(_DriverDeadlineExceeded, match="transaction exceeded 5s"):
        read(backend)
