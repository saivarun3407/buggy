"""Inspect defensive capability contracts without contacting a target."""

from __future__ import annotations

import builtins
import json
import os
import platform
import shutil
import socket
import ssl
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

import pytest

from buggy.sandbox_kernel import capabilities
from buggy.sandbox_kernel.bounded_process import CommandResult, run_bounded
from buggy.sandbox_kernel.capabilities import capability_catalog

IDS = (
    "network-inventory",
    "dns-inventory",
    "tls-inspection",
    "http-capture-review",
    "sarif-review",
)


@pytest.fixture(autouse=True)
def isolated_runtime(monkeypatch: pytest.MonkeyPatch) -> None:
    def no_network(*args: Any, **kwargs: Any) -> Any:
        pytest.fail("Capability inspection must not connect to a target")

    monkeypatch.setattr(shutil, "which", lambda name: None)
    monkeypatch.setattr(socket, "create_connection", no_network)
    monkeypatch.setattr(platform, "system", lambda: "Linux")
    monkeypatch.setattr(platform, "machine", lambda: "x86_64")

    def isolated_probe(argv: list[str], **kwargs: Any) -> CommandResult:
        if argv[0] == sys.executable:
            return CommandResult("completed", 0, b"workflow-runtime-ready\n", b"")
        return run_bounded(argv, **kwargs)

    monkeypatch.setattr(capabilities, "run_bounded", isolated_probe)


def synthetic_tools(monkeypatch: pytest.MonkeyPatch, programs: dict[str, str]) -> None:
    """Replace the OS tool boundary with Python, retaining the real bounded runner."""
    popen = subprocess.Popen[bytes]

    def launch(argv: list[str], **kwargs: Any) -> subprocess.Popen[bytes]:
        tool = Path(argv[0]).name
        expected = {"nmap": ["--version"], "dig": ["-v"]}
        assert argv == [f"/fixture-secret/{tool}", *expected[tool]]
        return popen([sys.executable, "-B", "-c", programs[tool]], **kwargs)

    monkeypatch.setattr(
        shutil, "which", lambda name: f"/fixture-secret/{name}" if name in programs else None
    )
    monkeypatch.setattr(subprocess, "Popen", launch)


def test_catalog_is_versioned_deterministic_fresh_and_defensively_bounded() -> None:
    catalog = capability_catalog()
    assert catalog == capability_catalog()
    assert catalog["schema_version"] == 1
    assert catalog["catalog_version"] == "defensive-v1"
    assert tuple(entry["id"] for entry in catalog["capabilities"]) == IDS
    assert "not authorization" in catalog["limitations"]
    assert "successful assessment" in catalog["limitations"]
    for entry, tool, network in zip(
        catalog["capabilities"],
        ("nmap", "dig", "python-ssl", "builtin-json", "builtin-json"),
        (True, True, True, False, False),
        strict=True,
    ):
        assert entry["tool"] == tool
        assert entry["execution_location"] == "sandbox"
        assert entry["requires_network"] is network
        assert entry["input_kinds"] and entry["output_kinds"] and entry["approved_mode"]
        limits = entry["limits"]
        assert type(limits["timeout_seconds"]) is int and 0 < limits["timeout_seconds"] <= 30
        assert limits["max_output_bytes"] == 2 * 1024 * 1024
        assert type(limits["max_targets"]) is int and 0 <= limits["max_targets"] <= 16
        assert (limits["max_targets"] > 0) is network
    assert catalog["capabilities"][0]["approved_mode"] == "tcp-connect-only"
    pristine = json.dumps(catalog, sort_keys=True)
    catalog["capabilities"][0]["limits"]["max_targets"] = 999
    catalog["capabilities"][0]["input_kinds"].append("shell")
    catalog["capabilities"].clear()
    assert json.dumps(capability_catalog(), sort_keys=True) == pristine


def test_network_capability_distinguishes_host_and_port_budgets() -> None:
    network = capability_catalog()["capabilities"][0]
    assert network["limits"]["max_targets"] == 1
    assert network["limits"]["max_ports"] == 16
    assert capabilities.inspect_capabilities()["inspection_location"] == "current_process"


@pytest.mark.parametrize("present", [False, True])
def test_static_inspection_distinguishes_presence_from_validation_without_executing(
    monkeypatch: pytest.MonkeyPatch, present: bool
) -> None:
    def no_execution(*args: Any, **kwargs: Any) -> Any:
        pytest.fail("Static inspection must not launch a command")

    monkeypatch.setattr(subprocess, "Popen", no_execution)
    monkeypatch.setattr(
        shutil, "which", lambda name: f"/fixture-secret/{name}" if present else None
    )
    inspection = capabilities.inspect_capabilities()
    assert inspection["schema_version"] == 1
    assert inspection["platform"] == {"system": "Linux", "machine": "x86_64"}
    assert inspection["probe"] is False
    assert inspection["end_to_end_validation"] == "not_performed"
    for definition, entry in zip(capability_catalog()["capabilities"], inspection["capabilities"]):
        assert all(entry[key] == value for key, value in definition.items())
        assert entry["check"] == "not_performed"
        if entry["tool"] in ("nmap", "dig"):
            assert entry["status"] == ("installed" if present else "unavailable")
            assert entry["reason"] == ("binary_resolved" if present else "binary_missing")
            assert entry["version"] is None
        else:
            assert entry["status"] == "installed"
    assert "fixture-secret" not in json.dumps(inspection)


@pytest.mark.parametrize("probe", [False, True])
def test_builtin_readiness_reports_actual_runtime_versions_and_labels_self_checks(
    probe: bool,
) -> None:
    inspection = capabilities.inspect_capabilities(probe=probe)
    assert inspection["end_to_end_validation"] == "not_performed"
    tls, http, sarif = inspection["capabilities"][2:]
    assert tls["version"] == " ".join(ssl.OPENSSL_VERSION.split()[:2])
    assert tls["check"] == ("runtime_self_check" if probe else "not_performed")
    for entry in (http, sarif):
        assert (
            entry["version"]
            == f"Python {sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
        )
        assert entry["check"] == ("parser_self_check" if probe else "not_performed")
    assert all(
        entry["status"] == ("available" if probe else "installed") for entry in (tls, http, sarif)
    )
    assert all(entry["status"] == "unavailable" for entry in inspection["capabilities"][:2])
    assert "self-checks are not end-to-end validation" in inspection["limitations"]


def test_builtin_parser_self_check_rejects_unexpected_results(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(json, "loads", lambda raw: None)
    inspection = capabilities.inspect_capabilities(probe=True)
    for entry in inspection["capabilities"][3:]:
        assert entry["status"] == "error"
        assert entry["check"] == "parser_self_check"
        assert entry["reason"] == "parser_check_failed"


@pytest.mark.parametrize("stream", [1, 2])
@pytest.mark.parametrize(
    "nmap_output,dig_output,versions",
    [
        (
            b"Nmap version 7.95 ( https://nmap.org )\nPlatform: x86_64-pc-linux-gnu\n",
            b"DiG 9.10.6\n",
            ["7.95", "9.10.6"],
        ),
        (
            b"Nmap version 7.94SVN ( https://nmap.org )\n",
            b"DiG 9.18.33-1~deb12u1-Debian\n",
            ["7.94SVN", "9.18.33"],
        ),
    ],
)
def test_fixed_version_probes_parse_allowlisted_versions_without_claiming_assessment(
    monkeypatch: pytest.MonkeyPatch,
    stream: int,
    nmap_output: bytes,
    dig_output: bytes,
    versions: list[str],
) -> None:
    synthetic_tools(
        monkeypatch,
        {
            tool: f"import os; os.write({stream}, {output!r})"
            for tool, output in (("nmap", nmap_output), ("dig", dig_output))
        },
    )
    inspection = capabilities.inspect_capabilities(probe=True)
    for entry, version in zip(inspection["capabilities"][:2], versions, strict=True):
        assert entry["status"] == "available"
        assert entry["version"] == version
        assert entry["reason"] == "version_verified"
        assert entry["check"] == "version_probe"
    assert inspection["end_to_end_validation"] == "not_performed"
    assert "fixture-secret" not in json.dumps(inspection)
    assert "Platform:" not in json.dumps(inspection)


@pytest.mark.parametrize(
    "output",
    [
        b"",
        b"fixture-secret /private/arbitrary/path",
        b"7.95",
        b"Nmap version 7.95 fixture-secret",
        b"DiG 9.18.33/fixture-secret",
        b"\xff\x00\x1b[31mNmap version 7.95",
    ],
)
def test_exit_zero_with_unexpected_version_output_is_error_not_available(
    monkeypatch: pytest.MonkeyPatch, output: bytes
) -> None:
    program = f"import os; os.write(1, {output!r})"
    synthetic_tools(monkeypatch, {"nmap": program, "dig": program})
    inspection = capabilities.inspect_capabilities(probe=True)
    for entry in inspection["capabilities"][:2]:
        assert entry["status"] == "error"
        assert entry["reason"] == "unexpected_version_output"
        assert entry["version"] is None
    serialized = json.dumps(inspection)
    assert "fixture-secret" not in serialized and "/private/" not in serialized
    assert len(serialized) < 8192


@pytest.mark.parametrize(
    "tail,reason",
    [
        ("os.write(2, b'x' * 65536)", "version_probe_output_limit"),
        ("time.sleep(2)", "version_probe_timeout"),
        ("sys.exit(7)", "version_probe_failed"),
        ("os.write(2, b'fixture-secret')", "unexpected_version_output"),
    ],
)
def test_bounded_or_failed_version_probes_never_become_available(
    monkeypatch: pytest.MonkeyPatch, tail: str, reason: str
) -> None:
    synthetic_tools(
        monkeypatch,
        {
            tool: f"import os,sys,time; os.write(1, {header!r}); {tail}"
            for tool, header in (("nmap", b"Nmap version 7.95\n"), ("dig", b"DiG 9.18.33\n"))
        },
    )
    started = time.monotonic()
    inspection = capabilities.inspect_capabilities(probe=True)
    assert time.monotonic() - started < 3.5
    for entry in inspection["capabilities"][:2]:
        assert entry["status"] == "error"
        assert entry["reason"] == reason
        assert entry["check"] == "version_probe"
        assert entry["version"] is None
    assert "fixture-secret" not in json.dumps(inspection)


@pytest.mark.parametrize("missing", [False, True])
def test_probe_launch_failure_is_sanitized_and_disappearance_is_unavailable(
    monkeypatch: pytest.MonkeyPatch, missing: bool
) -> None:
    def launch(argv: list[str], **kwargs: Any) -> Any:
        if missing:
            raise FileNotFoundError(2, "fixture-secret", argv[0])
        raise OSError("fixture-secret /private/arbitrary/path")

    monkeypatch.setattr(shutil, "which", lambda name: f"/fixture-secret/{name}")
    monkeypatch.setattr(subprocess, "Popen", launch)
    inspection = capabilities.inspect_capabilities(probe=True)
    for entry in inspection["capabilities"][:2]:
        assert entry["status"] == ("unavailable" if missing else "error")
        assert entry["reason"] == (
            "version_probe_unavailable" if missing else "version_probe_error"
        )
    assert "fixture-secret" not in json.dumps(inspection)


@pytest.mark.parametrize("probe", [None, 0, 1, "fixture-secret", [], {}])
def test_probe_flag_requires_a_boolean_without_reflecting_input(probe: Any) -> None:
    with pytest.raises(capabilities.CapabilityInputError, match="^probe must be a boolean$"):
        capabilities.inspect_capabilities(probe=probe)


@pytest.mark.parametrize("boundary,failed", [("resolver", [0, 1]), ("ssl", [2]), ("json", [3, 4])])
def test_runtime_errors_are_isolated_per_capability_and_never_reflect_exceptions(
    monkeypatch: pytest.MonkeyPatch, boundary: str, failed: list[int]
) -> None:
    def broken_runtime(*args: Any, **kwargs: Any) -> Any:
        raise OSError("fixture-secret /private/arbitrary/path")

    owner, attribute = {
        "resolver": (shutil, "which"),
        "ssl": (ssl, "SSLContext"),
        "json": (json, "loads"),
    }[boundary]
    monkeypatch.setattr(owner, attribute, broken_runtime)
    inspection = capabilities.inspect_capabilities(probe=True)
    for index in failed:
        entry = inspection["capabilities"][index]
        assert entry["status"] == "error"
        assert entry["version"] is None
        assert entry["reason"] == "inspection_error"
    assert any(entry["status"] == "available" for entry in inspection["capabilities"])
    assert "fixture-secret" not in json.dumps(inspection)
    assert "/private/" not in json.dumps(inspection)


@pytest.mark.parametrize("raises", [False, True])
def test_platform_metadata_is_allowlisted_and_errors_are_not_reflected(
    monkeypatch: pytest.MonkeyPatch, raises: bool
) -> None:
    def metadata() -> str:
        if raises:
            raise OSError("fixture-secret /private/arbitrary/path")
        return "fixture-secret /private/arbitrary/path" * 1000

    monkeypatch.setattr(platform, "system", metadata)
    monkeypatch.setattr(platform, "machine", metadata)
    inspection = capabilities.inspect_capabilities()
    assert inspection["platform"] == {"system": "unknown", "machine": "unknown"}
    assert "fixture-secret" not in json.dumps(inspection)


@pytest.mark.parametrize("probe", [False, True])
@pytest.mark.parametrize(
    "version",
    [
        "fixture-secret /private/arbitrary/path",
        "OpenSSL 3.5.6 fixture-secret",
        "OpenSSL 3.5.6\x00fixture-secret",
        "OpenSSL 3.5.6 " + "x" * 5000,
    ],
    ids=["path", "suffix", "control-character", "huge"],
)
def test_tls_runtime_version_is_strictly_parsed_without_reflection(
    monkeypatch: pytest.MonkeyPatch, probe: bool, version: str
) -> None:
    monkeypatch.setattr(ssl, "OPENSSL_VERSION", version)
    inspection = capabilities.inspect_capabilities(probe=probe)
    tls = inspection["capabilities"][2]
    assert tls["status"] == "error"
    assert tls["reason"] == "unexpected_runtime_version"
    assert tls["version"] is None
    assert "fixture-secret" not in json.dumps(inspection)


def test_missing_ssl_runtime_is_unavailable_not_a_success(monkeypatch: pytest.MonkeyPatch) -> None:
    import_module = builtins.__import__

    def unavailable_ssl(name: str, *args: Any, **kwargs: Any) -> Any:
        if name == "ssl":
            raise ImportError("fixture-secret")
        return import_module(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", unavailable_ssl)
    inspection = capabilities.inspect_capabilities(probe=True)
    tls = inspection["capabilities"][2]
    assert tls["status"] == "unavailable"
    assert tls["reason"] == "runtime_unavailable"
    assert tls["version"] is None
    assert "fixture-secret" not in json.dumps(inspection)


@pytest.mark.parametrize("probe", [False, True])
def test_unsupported_process_cleanup_is_explicit_without_launching(
    monkeypatch: pytest.MonkeyPatch, probe: bool
) -> None:
    def no_execution(*args: Any, **kwargs: Any) -> Any:
        pytest.fail("Unsupported process groups must prevent command launch")

    with monkeypatch.context() as unsupported:
        unsupported.setattr(os, "name", "nt")
        unsupported.setattr(shutil, "which", lambda name: f"/fixture-secret/{name}")
        unsupported.setattr(subprocess, "Popen", no_execution)
        inspection = capabilities.inspect_capabilities(probe=probe)
    for entry in inspection["capabilities"][:2]:
        assert entry["status"] == "unsupported"
        assert entry["check"] == "not_performed"
        assert entry["reason"] == "process_groups_unsupported"


def test_version_probes_reject_unexpected_trailing_output(monkeypatch: pytest.MonkeyPatch) -> None:
    synthetic_tools(
        monkeypatch,
        {
            tool: f"import os; os.write(1, {header + b'fixture-secret /private/path'!r})"
            for tool, header in (("nmap", b"Nmap version 7.95\n"), ("dig", b"DiG 9.18.33\n"))
        },
    )
    inspection = capabilities.inspect_capabilities(probe=True)
    for entry in inspection["capabilities"][:2]:
        assert entry["status"] == "error"
        assert entry["reason"] == "unexpected_version_output"
        assert entry["version"] is None
    assert "fixture-secret" not in json.dumps(inspection)


def test_binary_lookup_is_resolved_before_changing_the_probe_working_directory(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    popen = subprocess.Popen[bytes]
    binary = "fixture-secret/nmap"

    def launch(argv: list[str], **kwargs: Any) -> subprocess.Popen[bytes]:
        assert argv == [os.path.abspath(binary), "--version"]
        return popen([sys.executable, "-B", "-c", "print('Nmap version 7.95')"], **kwargs)

    monkeypatch.setattr(shutil, "which", lambda name: binary if name == "nmap" else None)
    monkeypatch.setattr(subprocess, "Popen", launch)
    inspection = capabilities.inspect_capabilities(probe=True)
    assert inspection["capabilities"][0]["status"] == "available"
    assert inspection["capabilities"][0]["version"] == "7.95"
    assert "fixture-secret" not in json.dumps(inspection)


@pytest.mark.parametrize(
    ("outcome", "status", "reason"),
    [
        (
            CommandResult("completed", 2, b"", b"fixture-secret defusedxml"),
            "unavailable",
            "import_missing",
        ),
        (CommandResult("timeout", None, b"fixture-secret", b""), "error", "import_check_timeout"),
        (
            CommandResult("output_limit", None, b"fixture-secret", b""),
            "error",
            "import_check_output_limit",
        ),
        (CommandResult("completed", 1, b"", b"fixture-secret"), "error", "import_check_failed"),
        (
            CommandResult("completed", 0, b"fixture-secret", b""),
            "error",
            "unexpected_import_output",
        ),
        (
            CommandResult("completed", 0, b"workflow-runtime-ready\n", b"fixture-secret"),
            "error",
            "unexpected_import_output",
        ),
    ],
)
def test_workflow_runtime_failure_cannot_leave_capabilities_available(
    monkeypatch: pytest.MonkeyPatch, outcome: CommandResult, status: str, reason: str
) -> None:
    calls = []

    def command(argv: list[str], **kwargs: Any) -> CommandResult:
        if argv[0] == sys.executable:
            calls.append((argv, kwargs))
            return outcome
        output = b"Nmap version 7.99\n" if Path(argv[0]).name == "nmap" else b"DiG 9.20.23\n"
        return CommandResult("completed", 0, output, b"")

    monkeypatch.setattr(shutil, "which", lambda name: f"/fixture-secret/{name}")
    monkeypatch.setattr(capabilities, "run_bounded", command)
    inspection = capabilities.inspect_capabilities(probe=True)
    assert all(entry["status"] == status for entry in inspection["capabilities"])
    assert inspection["workflow_runtime"]["status"] == status
    assert inspection["workflow_runtime"]["reason"] == reason
    assert inspection["workflow_runtime"]["check"] == "bounded_import_check"
    assert inspection["end_to_end_validation"] == "not_performed"
    assert [entry["version"] for entry in inspection["capabilities"][:2]] == ["7.99", "9.20.23"]
    assert [entry["check"] for entry in inspection["capabilities"][:2]] == ["version_probe"] * 2
    assert "fixture-secret" not in json.dumps(inspection)
    assert len(calls) == 1
    argv, options = calls[0]
    assert argv[1:4] == ["-I", "-B", "-c"]
    assert options["cwd"] == "/"
    assert 0 < options["timeout"] <= 2
    assert options["max_output_bytes"] <= 4096


def test_static_inspection_does_not_claim_workflow_import_readiness() -> None:
    inspection = capabilities.inspect_capabilities()
    assert inspection["workflow_runtime"]["status"] == "not_checked"
    assert inspection["workflow_runtime"]["check"] == "not_performed"
    assert inspection["end_to_end_validation"] == "not_performed"


@pytest.mark.parametrize(
    "boundary", ["missing", "socket.connect", "socket.getaddrinfo", "subprocess.Popen"]
)
def test_actual_workflow_import_check_refuses_missing_dependencies_and_network_actions(
    monkeypatch: pytest.MonkeyPatch, boundary: str
) -> None:
    popen = subprocess.Popen[bytes]
    calls = []
    action = (
        'raise ModuleNotFoundError("fixture-secret /private/defusedxml")'
        if boundary == "missing"
        else f"sys.audit({boundary!r}, 'fixture-secret')"
    )
    prefix = (
        "import sys\n"
        "class DependencyBoundary:\n"
        "    def find_spec(self, fullname, path=None, target=None):\n"
        "        if fullname == 'defusedxml':\n"
        f"            {action}\n"
        "        return None\n"
        "sys.meta_path.insert(0, DependencyBoundary())\n"
    )

    def launch(argv: list[str], **kwargs: Any) -> subprocess.Popen[bytes]:
        calls.append(argv)
        assert argv[:4] == [sys.executable, "-I", "-B", "-c"]
        assert kwargs["cwd"] == "/"
        assert kwargs["env"] == {"PATH": os.defpath, "LANG": "C", "LC_ALL": "C"}
        assert kwargs["start_new_session"] is True
        return popen([*argv[:4], prefix + argv[4], *argv[5:]], **kwargs)

    monkeypatch.setattr(capabilities, "run_bounded", run_bounded)
    monkeypatch.setattr(subprocess, "Popen", launch)
    inspection = capabilities.inspect_capabilities(probe=True)
    runtime = inspection["workflow_runtime"]
    assert runtime["status"] == ("unavailable" if boundary == "missing" else "error")
    assert runtime["reason"] == (
        "import_missing" if boundary == "missing" else "import_check_failed"
    )
    assert not any(entry["status"] == "available" for entry in inspection["capabilities"])
    assert len(calls) == 1
    assert "fixture-secret" not in json.dumps(inspection)
    assert "/private/" not in json.dumps(inspection)


@pytest.mark.parametrize(
    ("program", "reason"),
    [
        ("import time; time.sleep(4)", "import_check_timeout"),
        ("import os; os.write(1, b'fixture-secret' * 65536)", "import_check_output_limit"),
    ],
)
def test_workflow_import_process_is_actually_time_and_output_bounded(
    monkeypatch: pytest.MonkeyPatch, program: str, reason: str
) -> None:
    popen = subprocess.Popen[bytes]

    def launch(argv: list[str], **kwargs: Any) -> subprocess.Popen[bytes]:
        assert argv[:4] == [sys.executable, "-I", "-B", "-c"]
        return popen([*argv[:4], program, *argv[5:]], **kwargs)

    monkeypatch.setattr(capabilities, "run_bounded", run_bounded)
    monkeypatch.setattr(subprocess, "Popen", launch)
    started = time.monotonic()
    inspection = capabilities.inspect_capabilities(probe=True)
    assert time.monotonic() - started < 3.5
    assert inspection["workflow_runtime"]["reason"] == reason
    assert inspection["workflow_runtime"]["status"] == "error"
    assert not any(entry["status"] == "available" for entry in inspection["capabilities"])
    assert "fixture-secret" not in json.dumps(inspection)
