from __future__ import annotations

import builtins
import hashlib
import importlib.util
import inspect
import io
import json
import os
import re
import socket
import subprocess
import sys
import traceback
from collections import Counter
from collections.abc import Callable
from copy import deepcopy
from functools import partial
from pathlib import Path
from types import ModuleType
from typing import Any, NoReturn, get_type_hints

import pytest

from buggy.sandbox_kernel.asvs_catalog import (
    CATALOG_SHA256,
    CATALOG_VERSION,
    ASVSCatalogError,
    catalog,
    requirements,
)

RELEASE_PATH = (
    Path(__file__).parents[3]
    / "buggy"
    / "sandbox_kernel"
    / "OWASP_Application_Security_Verification_Standard_5.0.0_en.json"
)
RELEASE_SIZE = 149_407
RELEASE_SHA256 = "bcdbec214d70abcfad9284a31d4f9e5134305831d628aad3aa85d7e26626cb35"
CUMULATIVE_COUNTS = {"1": 70, "2": 253, "3": 345}
SECRET = "synthetic-private-marker-do-not-echo"
CHAPTERS = {
    "V1": "Encoding and Sanitization",
    "V2": "Validation and Business Logic",
    "V3": "Web Frontend Security",
    "V4": "API and Web Service",
    "V5": "File Handling",
    "V6": "Authentication",
    "V7": "Session Management",
    "V8": "Authorization",
    "V9": "Self-contained Tokens",
    "V10": "OAuth and OIDC",
    "V11": "Cryptography",
    "V12": "Secure Communication",
    "V13": "Configuration",
    "V14": "Data Protection",
    "V15": "Secure Coding and Architecture",
    "V16": "Security Logging and Error Handling",
    "V17": "WebRTC",
}


@pytest.fixture(autouse=True)
def forbid_network_and_processes(monkeypatch: pytest.MonkeyPatch) -> None:
    def forbidden(*args: Any, **kwargs: Any) -> NoReturn:
        raise AssertionError("The ASVS catalog must not use network or process operations")

    for owner, attribute in (
        (socket, "socket"),
        (socket, "create_connection"),
        (socket, "getaddrinfo"),
        (subprocess, "Popen"),
        (subprocess, "run"),
        (os, "system"),
        (os, "popen"),
    ):
        monkeypatch.setattr(owner, attribute, forbidden)


@pytest.fixture
def release_bytes() -> bytes:
    with RELEASE_PATH.open("rb") as stream:
        raw = stream.read(RELEASE_SIZE + 1)
    assert len(raw) == RELEASE_SIZE
    assert hashlib.sha256(raw).hexdigest() == RELEASE_SHA256
    return raw


def test_default_catalog_public_interface() -> None:
    assert issubclass(ASVSCatalogError, ValueError)
    assert CATALOG_VERSION == "5.0.0"
    assert CATALOG_SHA256 == RELEASE_SHA256
    result = catalog()
    assert result["standard"] == "ASVS"
    assert result["version"] == CATALOG_VERSION
    assert result["level"] == 2
    assert result["sha256"] == CATALOG_SHA256
    assert result["offset"] == 0
    assert result["limit"] == 50
    assert result["requirements"] == requirements()[:50]
    assert result["total"] == len(requirements()) == 253


def test_public_signatures_and_annotations() -> None:
    required = inspect.signature(requirements).parameters
    assert list(required) == ["level"]
    assert required["level"].default == 2
    paged = inspect.signature(catalog).parameters
    assert list(paged) == ["level", "offset", "limit"]
    assert paged["level"].default == 2
    assert paged["offset"].default == 0
    assert paged["limit"].default == 50
    for parameter in (paged["offset"], paged["limit"]):
        assert parameter.kind is inspect.Parameter.KEYWORD_ONLY
    assert get_type_hints(requirements) == {"level": int, "return": list[dict[str, Any]]}
    assert get_type_hints(catalog) == {
        "level": int,
        "offset": int,
        "limit": int,
        "return": dict[str, Any],
    }


def test_release_hash_and_exact_discovered_counts(release_bytes: bytes) -> None:
    assert hashlib.sha256(release_bytes).hexdigest() == CATALOG_SHA256 == RELEASE_SHA256
    document = json.loads(release_bytes)
    assert document["ShortName"] == "ASVS"
    assert document["Version"] == "5.0.0"
    leaves = [
        item
        for chapter in document["Requirements"]
        for section in chapter["Items"]
        for item in section["Items"]
    ]
    assert len(leaves) == 345
    assert Counter(int(item["L"]) for item in leaves) == {1: 70, 2: 183, 3: 92}


def test_verbatim_requirements_qualified_unique_ids_and_official_order(
    release_bytes: bytes,
) -> None:
    document = json.loads(release_bytes)
    expected = [
        (chapter, section, item)
        for chapter in document["Requirements"]
        for section in chapter["Items"]
        for item in section["Items"]
    ]
    result = requirements(3)
    assert len(result) == len(expected) == 345
    assert len({item["requirement_id"] for item in result}) == 345
    assert len({item["shortcode"] for item in result}) == 345
    assert result[0]["requirement_id"] == "v5.0.0-1.1.1"
    assert result[-1]["requirement_id"] == "v5.0.0-17.3.2"
    for requirement, (chapter, section, item) in zip(result, expected, strict=True):
        assert requirement == {
            "requirement_id": f"v5.0.0-{item['Shortcode'].removeprefix('V')}",
            "shortcode": item["Shortcode"],
            "chapter_id": chapter["Shortcode"],
            "chapter": chapter["Name"],
            "section_id": section["Shortcode"],
            "section": section["Name"],
            "level": int(item["L"]),
            "description": item["Description"],
        }
        assert type(requirement["level"]) is int
        assert re.fullmatch(r"v5\.0\.0-\d+\.\d+\.\d+", requirement["requirement_id"])
    chapters = {item["chapter_id"]: item["chapter"] for item in result}
    assert chapters == CHAPTERS
    assert list(chapters) == [f"V{number}" for number in range(1, 18)]


@pytest.mark.parametrize(("level", "count"), [(1, 70), (2, 253), (3, 345)])
def test_levels_are_complete_cumulative_and_not_internally_paginated(
    level: int, count: int
) -> None:
    result = requirements(level)
    assert len(result) == count
    assert result == [item for item in requirements(3) if item["level"] <= level]
    assert {item["level"] for item in result} == set(range(1, level + 1))
    page = catalog(level, limit=1000)
    assert page["requirements"] == result
    assert page["total"] == count
    assert page["catalog_total"] == 345
    assert page["cumulative_level_counts"] == CUMULATIVE_COUNTS


def test_release_attribution_license_notice_and_deterministic_json_metadata() -> None:
    result = catalog()
    metadata = {
        "standard": "ASVS",
        "version": "5.0.0",
        "level": 2,
        "sha256": RELEASE_SHA256,
        "source_commit": "5cf9b032440be53ce345ab3c130fda46ba1ce7a2",
        "source_url": "https://github.com/OWASP/ASVS/releases/tag/v5.0.0_release",
        "attribution": "OWASP ASVS project and contributors",
        "license": "CC-BY-SA-4.0",
        "license_url": "https://creativecommons.org/licenses/by-sa/4.0/",
        "catalog_total": 345,
        "total": 253,
        "cumulative_level_counts": CUMULATIVE_COUNTS,
        "offset": 0,
        "limit": 50,
        "next_offset": 50,
        "has_more": True,
        "notice": (
            "Catalog membership or plan completion does not constitute "
            "automatic control verification or OWASP certification."
        ),
    }
    assert set(result) == set(metadata) | {"requirements"}
    assert {key: result[key] for key in metadata} == metadata
    assert json.loads(json.dumps(result)) == result == catalog()


@pytest.mark.parametrize("level", [1, 2, 3])
def test_pagination_reassembles_every_requirement_in_order(level: int) -> None:
    expected = requirements(level)
    collected: list[dict[str, Any]] = []
    offset = 0
    while True:
        page = catalog(level, offset=offset, limit=37)
        assert page["offset"] == offset
        assert page["limit"] == 37
        assert page["total"] == len(expected)
        assert page["catalog_total"] == 345
        assert page["cumulative_level_counts"] == CUMULATIVE_COUNTS
        assert page["requirements"] == expected[offset : offset + 37]
        collected.extend(page["requirements"])
        if offset + 37 >= len(expected):
            assert page["next_offset"] is None
            assert page["has_more"] is False
            break
        assert page["has_more"] is True
        assert page["next_offset"] == offset + 37
        offset = page["next_offset"]
    assert collected == expected


@pytest.mark.parametrize(
    ("offset", "limit"),
    [(0, 1), (1, 1), (0, 1000), (344, 1), (344, 2), (345, 50), (346, 1000), (10**100, 1)],
)
def test_page_boundaries_and_exhausted_offsets(offset: int, limit: int) -> None:
    result = catalog(3, offset=offset, limit=limit)
    assert result["requirements"] == requirements(3)[offset : offset + limit]
    assert result["offset"] == offset
    assert result["limit"] == limit
    assert result["total"] == result["catalog_total"] == 345
    assert result["has_more"] is (offset + limit < 345)
    assert result["next_offset"] == (offset + limit if offset + limit < 345 else None)


@pytest.fixture
def forbid_resource_read(monkeypatch: pytest.MonkeyPatch) -> None:
    def forbidden(*args: Any, **kwargs: Any) -> NoReturn:
        raise AssertionError("Invalid arguments must be rejected before opening any file")

    monkeypatch.setattr(Path, "open", forbidden)


@pytest.mark.usefixtures("forbid_resource_read")
@pytest.mark.parametrize("api", [requirements, catalog])
@pytest.mark.parametrize(
    "level", [True, False, None, -1, 0, 4, 2.0, "2", b"2", [], {}, 10**100, SECRET]
)
def test_level_requires_a_strict_integer_in_range(api: Callable[..., Any], level: Any) -> None:
    with pytest.raises(ASVSCatalogError, match="^level must be") as caught:
        api(level)
    assert SECRET not in str(caught.value)


@pytest.mark.usefixtures("forbid_resource_read")
@pytest.mark.parametrize("offset", [-1, True, False, None, 0.0, "0", b"0", [], {}, SECRET])
def test_offset_requires_a_nonnegative_strict_integer(offset: Any) -> None:
    with pytest.raises(ASVSCatalogError, match="^offset must be") as caught:
        catalog(offset=offset)
    assert SECRET not in str(caught.value)


@pytest.mark.usefixtures("forbid_resource_read")
@pytest.mark.parametrize(
    "limit", [0, -1, 1001, 10**100, True, False, None, 1.0, "50", b"50", [], {}, SECRET]
)
def test_limit_requires_a_strict_integer_from_one_to_one_thousand(limit: Any) -> None:
    with pytest.raises(ASVSCatalogError, match="^limit must be") as caught:
        catalog(limit=limit)
    assert SECRET not in str(caught.value)


@pytest.mark.usefixtures("forbid_resource_read")
@pytest.mark.parametrize("api", [requirements, catalog])
@pytest.mark.parametrize("keyword", ["path", "sha256", "digest"])
def test_callers_cannot_supply_a_replacement_resource_or_digest(
    api: Callable[..., Any], keyword: str
) -> None:
    with pytest.raises(TypeError):
        api(**{keyword: SECRET})


def test_mutating_any_returned_structure_cannot_affect_other_calls() -> None:
    first = catalog(3, limit=1000)
    second = catalog(3, limit=1000)
    full = requirements(3)
    baseline = deepcopy(second)
    assert first is not second
    assert first["requirements"] is not second["requirements"]
    assert first["requirements"][0] is not second["requirements"][0]
    assert first["cumulative_level_counts"] is not second["cumulative_level_counts"]
    first["requirements"][0]["description"] = SECRET
    first["requirements"][1].clear()
    first["requirements"].clear()
    first["cumulative_level_counts"]["1"] = -1
    first["cumulative_level_counts"].clear()
    first["attribution"] = SECRET
    full[0].clear()
    full.clear()
    assert second == baseline == catalog(3, limit=1000)
    assert requirements(3) == baseline["requirements"]


def substitute_bundle(
    monkeypatch: pytest.MonkeyPatch, raw: bytes
) -> tuple[list[int], list[io.BytesIO]]:
    read_sizes: list[int] = []
    streams: list[io.BytesIO] = []

    class BoundedReader(io.BytesIO):
        def read(self, size: int | None = -1) -> bytes:
            assert size is not None and 0 < size <= RELEASE_SIZE + 1
            read_sizes.append(size)
            assert sum(read_sizes) <= RELEASE_SIZE + 1
            return super().read(size)

    def open_bundle(path: Path, mode: str = "r", *args: Any, **kwargs: Any) -> io.BytesIO:
        assert path == RELEASE_PATH
        assert mode == "rb"
        stream = BoundedReader(raw)
        streams.append(stream)
        return stream

    monkeypatch.setattr(Path, "open", open_bundle)
    return read_sizes, streams


@pytest.mark.parametrize("api", [requirements, catalog])
def test_the_fixed_bundle_is_read_in_binary_mode_with_a_finite_bound(
    api: Callable[..., Any], monkeypatch: pytest.MonkeyPatch, release_bytes: bytes
) -> None:
    expected = api()
    with monkeypatch.context() as scope:
        read_sizes, streams = substitute_bundle(scope, release_bytes)
        assert api() == expected
    assert read_sizes
    assert streams and all(stream.closed for stream in streams)


@pytest.mark.parametrize(
    "api",
    [requirements, catalog, pytest.param(partial(catalog, 3, offset=345), id="exhausted_catalog")],
)
@pytest.mark.parametrize(
    "corruption",
    [
        "empty",
        "truncated",
        "changed_json",
        "changed_whitespace",
        "invalid_json",
        "invalid_utf8",
        "appended",
        "oversized",
    ],
)
def test_modified_bundle_fails_safely_even_after_a_successful_call(
    api: Callable[..., Any],
    corruption: str,
    monkeypatch: pytest.MonkeyPatch,
    release_bytes: bytes,
) -> None:
    expected = api()
    damaged = {
        "empty": b"",
        "truncated": release_bytes[:-1],
        "changed_json": release_bytes.replace(b'"ASVS"', b'"ASVZ"', 1),
        "changed_whitespace": release_bytes.replace(b"  ", b"\t ", 1),
        "invalid_json": SECRET.encode().ljust(RELEASE_SIZE, b" "),
        "invalid_utf8": b"\xff" + release_bytes[1:],
        "appended": release_bytes + b"\n",
        "oversized": release_bytes + b" " * RELEASE_SIZE,
    }[corruption]
    assert damaged != release_bytes
    if corruption in {"changed_json", "changed_whitespace"}:
        assert len(damaged) == RELEASE_SIZE
        assert isinstance(json.loads(damaged), dict)
    with monkeypatch.context() as scope:
        read_sizes, streams = substitute_bundle(scope, damaged)
        with pytest.raises(ASVSCatalogError) as caught:
            api()
    assert str(caught.value) == "Bundled ASVS catalog failed integrity verification"
    assert SECRET not in "".join(traceback.format_exception(caught.value))
    assert read_sizes
    assert streams and all(stream.closed for stream in streams)
    assert api() == expected


@pytest.mark.parametrize("api", [requirements, catalog])
@pytest.mark.parametrize(
    "error_type", [FileNotFoundError, PermissionError, IsADirectoryError, OSError]
)
def test_unavailable_bundle_has_no_cached_fallback_and_suppresses_io_details(
    api: Callable[..., Any], error_type: type[OSError], monkeypatch: pytest.MonkeyPatch
) -> None:
    expected = api()

    def open_failure(path: Path, mode: str = "r", *args: Any, **kwargs: Any) -> NoReturn:
        assert path == RELEASE_PATH
        assert mode == "rb"
        raise error_type(SECRET)

    with monkeypatch.context() as scope:
        scope.setattr(Path, "open", open_failure)
        with pytest.raises(ASVSCatalogError) as caught:
            api()
    assert str(caught.value) == "Bundled ASVS catalog is unavailable"
    assert SECRET not in "".join(traceback.format_exception(caught.value))
    assert api() == expected


@pytest.mark.parametrize("api", [requirements, catalog])
def test_read_failure_is_safe_and_closes_the_resource(
    api: Callable[..., Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    class BrokenReader(io.BytesIO):
        def read(self, size: int | None = -1) -> bytes:
            raise OSError(SECRET)

    stream = BrokenReader()

    def open_bundle(path: Path, mode: str = "r", *args: Any, **kwargs: Any) -> io.BytesIO:
        assert path == RELEASE_PATH
        assert mode == "rb"
        return stream

    with monkeypatch.context() as scope:
        scope.setattr(Path, "open", open_bundle)
        with pytest.raises(ASVSCatalogError) as caught:
            api()
    assert str(caught.value) == "Bundled ASVS catalog is unavailable"
    assert SECRET not in "".join(traceback.format_exception(caught.value))
    assert stream.closed


def test_standalone_public_interface_uses_only_stdlib_with_network_and_processes_blocked(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    spec = importlib.util.spec_from_file_location(
        "standalone_asvs_catalog", RELEASE_PATH.with_name("asvs_catalog.py")
    )
    assert spec is not None and spec.loader is not None
    standalone = importlib.util.module_from_spec(spec)
    original_import = builtins.__import__
    imports: set[str] = set()

    def stdlib_only(name: str, *args: Any, **kwargs: Any) -> ModuleType:
        root = name.partition(".")[0]
        assert root in sys.stdlib_module_names, f"Non-stdlib catalog dependency: {name}"
        imports.add(root)
        return original_import(name, *args, **kwargs)

    with monkeypatch.context() as scope:
        scope.setattr(builtins, "__import__", stdlib_only)
        spec.loader.exec_module(standalone)
        full = standalone.requirements(3)
        page = standalone.catalog(3, limit=1000)
    assert imports
    assert len(full) == 345
    assert page["requirements"] == full == requirements(3)
    assert page == catalog(3, limit=1000)
