"""Describe bounded defensive modes and inspect local runtime prerequisites."""

from __future__ import annotations

import json
import os
import platform
import re
import shutil
import sys
from pathlib import Path
from typing import Any

from buggy.sandbox_kernel.bounded_process import MAX_OUTPUT_BYTES, run_bounded

_PROBE_TIMEOUT_SECONDS = 1.0
_PROBE_OUTPUT_BYTES = 4096
_IMPORT_TIMEOUT_SECONDS = 2.0
_WORKFLOW_IMPORT_CHECK = """
import os
import sys
os.environ["BUGGY_SKIP_BOOT"] = "1"
sys.path.insert(0, sys.argv[1])

def deny_network(event: str, args: tuple[object, ...]) -> None:
    if event.startswith("socket.") or event in {"subprocess.Popen", "os.system", "os.posix_spawn"}:
        raise RuntimeError("Workflow import checks cannot perform network or process actions")

sys.addaudithook(deny_network)
try:
    from buggy.sandbox_kernel.defensive_workflows import DefensiveWorkflowRunner
    if not callable(DefensiveWorkflowRunner):
        sys.exit(1)
except ImportError:
    sys.exit(2)
except Exception:
    sys.exit(1)
sys.stdout.write("workflow-runtime-ready\\n")
"""
_VERSION_ARGS = {"nmap": "--version", "dig": "-v"}
_VERSION_PATTERNS = {
    "nmap": rb"Nmap version ([0-9]{1,2}\.[0-9]{1,3}(?:SVN)?)(?: \( https://nmap\.org \))?"
    rb"(?:\r?\n(?:Platform|Compiled with|Compiled without|Available nsock engines):[ -~]*)*\r?\n?",
    "dig": rb"DiG ([0-9]{1,2}\.[0-9]{1,3}\.[0-9]{1,3}(?:-P[0-9]{1,2})?)"
    rb"(?:-[0-9][0-9.+~a-z-]{0,48})?(?:-(?:Debian|Ubuntu))?\r?\n?",
}

_DEFINITIONS = (
    ("network-inventory", "nmap", "ip-addresses", "nmap-xml", "tcp-connect-only", 30, 1),
    ("dns-inventory", "dig", "dns-name", "dns-records", "bounded-record-query-no-axfr", 10, 1),
    (
        "tls-inspection",
        "python-ssl",
        "tls-endpoint",
        "tls-metadata",
        "verified-tls-handshake",
        10,
        1,
    ),
    (
        "http-capture-review",
        "builtin-json",
        "http-capture-json",
        "header-review",
        "artifact-only",
        5,
        0,
    ),
    ("sarif-review", "builtin-json", "sarif-json", "sarif-summary", "artifact-only", 5, 0),
)
_LIMITATIONS = (
    "Availability is not authorization or a successful assessment. "
    "Version probes, workflow import checks, and builtin parser/runtime self-checks are not end-to-end validation."
)


class CapabilityInputError(ValueError):
    """A capability inspection request has an invalid option."""


def capability_catalog() -> dict[str, Any]:
    return {
        "schema_version": 1,
        "catalog_version": "defensive-v1",
        "limitations": _LIMITATIONS,
        "capabilities": [
            {
                "id": identifier,
                "tool": tool,
                "execution_location": "sandbox",
                "input_kinds": [input_kind],
                "output_kinds": [output_kind],
                "requires_network": targets > 0,
                "approved_mode": mode,
                "limits": {
                    "timeout_seconds": timeout,
                    "max_output_bytes": MAX_OUTPUT_BYTES,
                    "max_targets": targets,
                    **({"max_ports": 16} if identifier == "network-inventory" else {}),
                },
            }
            for identifier, tool, input_kind, output_kind, mode, timeout, targets in _DEFINITIONS
        ],
    }


def _inspect_builtin(entry: dict[str, Any], probe: bool) -> None:
    if entry["tool"] == "python-ssl":
        import ssl

        version = re.fullmatch(
            r"((?:OpenSSL|LibreSSL) [0-9]{1,2}\.[0-9]{1,2}\.[0-9]{1,3}[a-z]?)"
            r"(?: [0-9]{1,2} (?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) [0-9]{4})?",
            ssl.OPENSSL_VERSION,
        )
        if not version:
            entry.update(status="error", reason="unexpected_runtime_version")
            return
        entry["version"] = version[1]
        if probe:
            entry["check"] = "runtime_self_check"
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            valid = context.verify_mode == ssl.CERT_REQUIRED and context.check_hostname
            entry.update(
                status="available" if valid else "error",
                reason="runtime_check_passed" if valid else "runtime_check_failed",
            )
    else:
        entry["version"] = (
            f"Python {sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
        )
        if probe:
            entry["check"] = "parser_self_check"
            expected = (
                {"log": {"entries": []}}
                if entry["id"] == "http-capture-review"
                else {"version": "2.1.0", "runs": []}
            )
            fixture = (
                '{"log":{"entries":[]}}'
                if entry["id"] == "http-capture-review"
                else '{"version":"2.1.0","runs":[]}'
            )
            valid = json.loads(fixture) == expected
            entry.update(
                status="available" if valid else "error",
                reason="parser_check_passed" if valid else "parser_check_failed",
            )


def _inspect_binary(entry: dict[str, Any], probe: bool) -> None:
    tool = entry["tool"]
    binary = shutil.which(tool)
    entry.update(
        status="installed" if binary else "unavailable",
        reason="binary_resolved" if binary else "binary_missing",
    )
    if not binary:
        return
    if os.name != "posix" or not callable(getattr(os, "killpg", None)):
        entry.update(status="unsupported", reason="process_groups_unsupported")
        return
    if not probe:
        return
    entry["check"] = "version_probe"
    command = run_bounded(
        [os.path.abspath(binary), _VERSION_ARGS[tool]],
        cwd="/",
        timeout=_PROBE_TIMEOUT_SECONDS,
        max_output_bytes=_PROBE_OUTPUT_BYTES,
    )
    if command.status != "completed":
        entry.update(
            status="unavailable" if command.status == "unavailable" else "error",
            reason=f"version_probe_{command.status}",
        )
        return
    if command.exit_code != 0:
        entry.update(status="error", reason="version_probe_failed")
        return
    output = command.stdout or command.stderr
    matched = (
        None if command.stdout and command.stderr else re.fullmatch(_VERSION_PATTERNS[tool], output)
    )
    entry.update(
        status="available" if matched else "error",
        reason="version_verified" if matched else "unexpected_version_output",
        version=matched[1].decode("ascii") if matched else None,
    )


def _inspect_workflow_runtime(probe: bool) -> dict[str, Any]:
    result = {
        "status": "not_checked",
        "check": "not_performed",
        "reason": "probe_required",
        "timeout_seconds": _IMPORT_TIMEOUT_SECONDS,
        "max_output_bytes": _PROBE_OUTPUT_BYTES,
    }
    if not probe:
        return result
    if os.name != "posix" or not callable(getattr(os, "killpg", None)):
        return result | {"status": "unsupported", "reason": "process_groups_unsupported"}
    result["check"] = "bounded_import_check"
    try:
        command = run_bounded(
            [
                sys.executable,
                "-I",
                "-B",
                "-c",
                _WORKFLOW_IMPORT_CHECK,
                str(Path(__file__).resolve().parents[2]),
            ],
            cwd="/",
            timeout=_IMPORT_TIMEOUT_SECONDS,
            max_output_bytes=_PROBE_OUTPUT_BYTES,
        )
    except (OSError, ValueError, RuntimeError):
        return result | {"status": "error", "reason": "import_check_error"}
    if command.status != "completed":
        return result | {
            "status": "unavailable" if command.status == "unavailable" else "error",
            "reason": "import_check_" + command.status,
        }
    if command.exit_code == 2:
        return result | {"status": "unavailable", "reason": "import_missing"}
    if command.exit_code != 0:
        return result | {"status": "error", "reason": "import_check_failed"}
    if command.stdout != b"workflow-runtime-ready\n" or command.stderr:
        return result | {"status": "error", "reason": "unexpected_import_output"}
    return result | {"status": "available", "reason": "import_verified"}


def _platform_details() -> dict[str, str]:
    details = {}
    for field, read, allowed in (
        ("system", platform.system, ("Linux", "Darwin", "Windows", "FreeBSD", "OpenBSD", "NetBSD")),
        (
            "machine",
            platform.machine,
            (
                "x86_64",
                "AMD64",
                "aarch64",
                "arm64",
                "i386",
                "i686",
                "armv7l",
                "ppc64le",
                "s390x",
                "riscv64",
            ),
        ),
    ):
        try:
            value = read()
        except OSError:
            value = "unknown"
        details[field] = value if value in allowed else "unknown"
    return details


def inspect_capabilities(*, probe: bool = False) -> dict[str, Any]:
    """Inspect the current runtime; production callers must run inside the sandbox."""
    if type(probe) is not bool:
        raise CapabilityInputError("probe must be a boolean")
    inspection = capability_catalog()
    inspection.update(
        platform=_platform_details(),
        inspection_location="current_process",
        probe=probe,
        end_to_end_validation="not_performed",
    )
    for entry in inspection["capabilities"]:
        entry.update(
            status="installed", check="not_performed", version=None, reason="builtin_runtime"
        )
        try:
            if entry["tool"] in _VERSION_ARGS:
                _inspect_binary(entry, probe)
            else:
                _inspect_builtin(entry, probe)
        except ImportError:
            entry.update(status="unavailable", version=None, reason="runtime_unavailable")
        except (OSError, ValueError, RuntimeError):
            entry.update(status="error", version=None, reason="inspection_error")
    runtime = _inspect_workflow_runtime(probe)
    inspection["workflow_runtime"] = runtime
    if probe and runtime["status"] != "available":
        for entry in inspection["capabilities"]:
            if entry["status"] == "available":
                entry.update(
                    status=runtime["status"], reason="workflow_runtime_" + runtime["status"]
                )
    return inspection
