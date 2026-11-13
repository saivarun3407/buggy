r"""Opt-in Linux smoke against disposable loopback fixtures, never live targets.

Run from the repository root with an already available sandbox image:

    docker run --rm --pull never --network none --dns 127.0.0.1 \
      --memory 512m --pids-limit 64 --cap-drop ALL --cap-add NET_BIND_SERVICE \
      --security-opt no-new-privileges --read-only \
      --tmpfs /tmp:rw,nosuid,nodev,size=128m --env PYTHONDONTWRITEBYTECODE=1 \
      --mount "type=bind,src=$PWD/packages/buggy/buggy/sandbox_kernel,dst=/opt/buggy/sandbox_kernel,readonly" \
      --mount "type=bind,src=$PWD/packages/buggy-core/buggy_core,dst=/opt/buggy_core,readonly" \
      --mount "type=bind,src=$PWD/scripts/check_defensive_workflows.py,dst=/opt/check_defensive_workflows.py,readonly" \
      --entrypoint python3 ghcr.io/purpleailab/buggy-sandbox:dev \
      /opt/check_defensive_workflows.py --run

The certificate, private key, assessment, and evidence exist only in /tmp.
JSON lines report each check, with native stdout/stderr on unexpected outcomes.
A successful smoke establishes fixture behavior, not independent assurance.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import socket
import ssl
import struct
import sys
import threading
import time
from collections.abc import Callable, Iterator, Sequence
from contextlib import ExitStack, contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from buggy.sandbox_kernel.defensive_workflows import DefensiveWorkflowRunner

HOST = "fixture.test"
IP = "127.0.0.1"
WORKFLOWS = (
    "network-inventory",
    "dns-inventory",
    "tls-inspection",
    "http-capture-review",
    "sarif-review",
)


class SmokeError(RuntimeError):
    """The explicit native verification did not satisfy its contract."""


class SmokeIsolationError(SmokeError):
    """The process is not in the required loopback-only Linux environment."""


class SmokePrerequisiteError(SmokeError):
    """The sandbox image lacks an actual workflow runtime prerequisite."""


class FixtureServiceError(SmokeError):
    """A disposable fixture failed or received an unexpected request."""


class WorkflowVerificationError(SmokeError):
    """A workflow result, persisted evidence, or safety check differed from expectations."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise WorkflowVerificationError(message)


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _json_file(path: Path, value: dict[str, Any]) -> str:
    path.write_text(json.dumps(value, sort_keys=True), encoding="utf-8")
    return path.name


def verify_isolation() -> None:
    """Refuse execution outside Linux with only loopback up and loopback DNS."""
    if sys.platform != "linux":
        raise SmokeIsolationError("Use a new Linux container with --network none --dns 127.0.0.1")
    active = {
        interface.name
        for interface in Path("/sys/class/net").iterdir()
        if interface.is_dir()
        and int((interface / "flags").read_text(encoding="ascii").strip(), 16) & 1
    }
    resolvers = [
        parts[1]
        for line in Path("/etc/resolv.conf").read_text(encoding="ascii").splitlines()
        if (parts := line.split()) and parts[0] == "nameserver" and len(parts) == 2
    ]
    if active != {"lo"} or resolvers != [IP]:
        raise SmokeIsolationError(f"Expected only lo and DNS {IP}; got {active}, {resolvers}")


class FixtureServices:
    """Real, bounded UDP DNS, TCP, and TLS servers in the current network namespace."""

    def __init__(self, directory: Path) -> None:
        self.directory = directory
        self.certificate = directory / "fixture.crt"
        self.private_key = directory / "fixture.key"
        self.lock = threading.Lock()
        self.stop = threading.Event()
        self.queries: list[tuple[str, int]] = []
        self.tcp_connections = 0
        self.tls_connections = 0
        self.tls_handshakes = 0
        self.tls_rejections = 0
        self.server_names: list[str | None] = []
        self.errors: list[str] = []
        self.abort_on_query: Path | None = None
        self.tcp_port = 0
        self.closed_port = 0
        self.tls_port = 0
        self.certificate_sha256 = ""

    def snapshot(self) -> tuple[int, int, int, int, int]:
        with self.lock:
            return (
                len(self.queries),
                self.tcp_connections,
                self.tls_connections,
                self.tls_handshakes,
                self.tls_rejections,
            )

    def _dns_response(self, packet: bytes) -> bytes:
        if len(packet) < 12:
            raise FixtureServiceError("Truncated fixture DNS request")
        identifier, flags, questions, _, _, _ = struct.unpack_from("!6H", packet)
        if flags & 0xF800 or questions != 1:
            raise FixtureServiceError("Only ordinary, single-question DNS requests are supported")
        offset = 12
        labels: list[str] = []
        while offset < len(packet) and packet[offset]:
            size = packet[offset]
            if size > 63 or offset + size + 1 >= len(packet):
                raise FixtureServiceError("Invalid fixture DNS label")
            labels.append(packet[offset + 1 : offset + size + 1].decode("ascii"))
            offset += size + 1
        offset += 1
        if offset + 4 > len(packet):
            raise FixtureServiceError("Missing fixture DNS question")
        kind, category = struct.unpack_from("!HH", packet, offset)
        question = packet[12 : offset + 4]
        name = ".".join(labels)
        with self.lock:
            self.queries.append((name, kind))
            abort, self.abort_on_query = self.abort_on_query, None
        if abort is not None:
            abort.touch(mode=0o600)
        if name != HOST or kind not in (1, 28) or category != 1:
            raise FixtureServiceError(f"Unexpected DNS question: {name}, {kind}, {category}")
        answer = (
            b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + socket.inet_aton(IP)
            if kind == 1
            else b""
        )
        return (
            struct.pack("!6H", identifier, 0x8580, 1, int(bool(answer)), 0, 0) + question + answer
        )

    def _serve_dns(self, transport: socket.socket) -> None:
        while not self.stop.is_set():
            try:
                packet, peer = transport.recvfrom(4096)
                if peer[0] != IP:
                    raise FixtureServiceError(f"Non-fixture DNS client: {peer[0]}")
                transport.sendto(self._dns_response(packet), peer)
            except TimeoutError:
                continue
            except Exception as exc:
                with self.lock:
                    self.errors.append(f"DNS: {type(exc).__name__}: {exc}")

    def _serve_tcp(self, listener: socket.socket, context: ssl.SSLContext | None) -> None:
        while not self.stop.is_set():
            try:
                connection, peer = listener.accept()
            except TimeoutError:
                continue
            try:
                with connection:
                    connection.settimeout(2)
                    if peer[0] != IP:
                        raise FixtureServiceError(f"Non-fixture TCP client: {peer[0]}")
                    with self.lock:
                        if context is None:
                            self.tcp_connections += 1
                        else:
                            self.tls_connections += 1
                    if context is None:
                        try:
                            data = connection.recv(1)
                        except ConnectionResetError:
                            data = b""
                    else:
                        try:
                            with context.wrap_socket(connection, server_side=True) as secured:
                                with self.lock:
                                    self.tls_handshakes += 1
                                try:
                                    data = secured.recv(1)
                                except (BrokenPipeError, ConnectionResetError):
                                    data = b""
                        except ssl.SSLError:
                            with self.lock:
                                self.tls_rejections += 1
                            continue
                    if data:
                        raise FixtureServiceError("Observation sent unexpected application data")
            except Exception as exc:
                with self.lock:
                    self.errors.append(f"TCP/TLS: {type(exc).__name__}: {exc}")

    def _server_name(
        self, transport: ssl.SSLSocket | ssl.SSLObject, name: str | None, context: ssl.SSLContext
    ) -> None:
        with self.lock:
            self.server_names.append(name)

    @contextmanager
    def running(self) -> Iterator[FixtureServices]:
        verify_isolation()
        from buggy.sandbox_kernel.bounded_process import run_bounded

        self.directory.mkdir(mode=0o700)
        generated = run_bounded(
            [
                "openssl",
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-noenc",
                "-sha256",
                "-days",
                "1",
                "-subj",
                f"/CN={HOST}",
                "-addext",
                f"subjectAltName=DNS:{HOST},IP:{IP}",
                "-addext",
                "basicConstraints=critical,CA:TRUE",
                "-addext",
                "keyUsage=critical,digitalSignature,keyCertSign",
                "-addext",
                "extendedKeyUsage=serverAuth",
                "-keyout",
                str(self.private_key),
                "-out",
                str(self.certificate),
            ],
            cwd=self.directory,
            timeout=10,
            max_output_bytes=8192,
        )
        if generated.status != "completed" or generated.exit_code != 0:
            raise FixtureServiceError(f"Certificate generation failed: {generated}")
        self.private_key.chmod(0o600)
        self.certificate_sha256 = _sha(
            ssl.PEM_cert_to_DER_cert(self.certificate.read_text(encoding="ascii"))
        )
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.num_tickets = 0
        context.load_cert_chain(self.certificate, self.private_key)
        context.sni_callback = self._server_name
        with ExitStack() as resources:
            sockets = [
                resources.enter_context(socket.socket(socket.AF_INET, kind))
                for kind in (
                    socket.SOCK_DGRAM,
                    socket.SOCK_STREAM,
                    socket.SOCK_STREAM,
                    socket.SOCK_STREAM,
                )
            ]
            dns, tcp, tls, closed = sockets
            for transport, port in zip(sockets, (53, 0, 0, 0), strict=True):
                transport.bind((IP, port))
                transport.settimeout(0.1)
            tcp.listen(4)
            tls.listen(4)
            self.tcp_port = tcp.getsockname()[1]
            self.tls_port = tls.getsockname()[1]
            self.closed_port = closed.getsockname()[1]
            threads = [
                threading.Thread(target=self._serve_dns, args=(dns,), daemon=True),
                threading.Thread(target=self._serve_tcp, args=(tcp, None), daemon=True),
                threading.Thread(target=self._serve_tcp, args=(tls, context), daemon=True),
            ]
            for thread in threads:
                thread.start()
            try:
                yield self
            finally:
                self.stop.set()
                for thread in threads:
                    thread.join(timeout=3)
                if any(thread.is_alive() for thread in threads):
                    raise FixtureServiceError("A fixture thread did not stop within its bound")


@contextmanager
def _trust(certificate: Path, empty_directory: Path) -> Iterator[None]:
    values = {"SSL_CERT_FILE": str(certificate), "SSL_CERT_DIR": str(empty_directory)}
    previous = {key: os.environ.get(key) for key in values}
    os.environ.update(values)
    try:
        yield
    finally:
        for key, value in previous.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


def initialize_assessment(workspace: Path, fixtures: FixtureServices) -> dict[str, Any]:
    """Seed nonempty baseline coverage and explicit port-limited enforcing authorization."""
    from buggy.sandbox_kernel.assessment import AssessmentStore

    store = AssessmentStore(workspace)
    store.dispatch(
        "initialize",
        {
            "engagement_name": "isolated-defensive-smoke",
            "profile": "external",
            "allowed_hosts": [HOST, IP],
            "denied_hosts": [],
        },
    )
    store.dispatch(
        "import",
        {
            "source": {"id": "fixture-operation", "kind": "manual", "status": "ok"},
            "operations": [{"url": f"https://{HOST}:{fixtures.tls_port}/", "method": "GET"}],
        },
    )
    scope = [
        f"https://{host}:{port}/"
        for host in (HOST, IP)
        for port in (fixtures.tcp_port, fixtures.closed_port, fixtures.tls_port)
    ]
    now = datetime.now(timezone.utc)
    roe = {
        "in_scope": scope,
        "machine_enforcement": {
            "mode": "enforce",
            "in_scope": scope,
            "out_of_scope": [],
            "allow_cloud_metadata": False,
            "allow_sensitive_tlds": False,
            "max_concurrent_connections": 1,
            "min_inter_request_delay_ms": 100,
            "authorized_windows": [
                [
                    (now - timedelta(minutes=1)).isoformat(),
                    (now + timedelta(minutes=10)).isoformat(),
                ]
            ],
            "forbidden_command_patterns": [r"(?:^|\s)(?:-sS|-sU|-sV|-sC|-A|-O|--script)(?:\s|$)"],
        },
    }
    (workspace / "plan").mkdir(mode=0o700)
    _json_file(workspace / "plan/roe.json", roe)
    return roe


def write_artifacts(workspace: Path, fixtures: FixtureServices) -> dict[str, str]:
    """Create synthetic inputs matching the five public supplied-artifact contracts."""
    asset = f"https://{HOST}:{fixtures.tls_port}/"
    now = datetime.now(timezone.utc)
    stamp = now.isoformat()
    network = (
        '<?xml version="1.0"?><!DOCTYPE nmaprun><nmaprun scanner="nmap" version="synthetic-fixture">'
        '<host><status state="up"/>'
        f'<address addr="{IP}" addrtype="ipv4"/>'
        f'<hostnames><hostname name="{HOST}" type="user"/></hostnames>'
        f'<ports><port protocol="tcp" portid="{fixtures.tcp_port}">'
        '<state state="open"/><service name="unknown"/></port></ports></host>'
        '<runstats><finished exit="success"/><hosts up="1" down="0" total="1"/></runstats></nmaprun>'
    )
    (workspace / "network.xml").write_text(network, encoding="utf-8")
    values: dict[str, dict[str, Any]] = {
        "dns-inventory": {
            "schema_version": 1,
            "kind": "dns-observation",
            "asset": asset,
            "observed_at": stamp,
            "queries": [
                {
                    "name": HOST,
                    "type": "A",
                    "status": "NOERROR",
                    "answers": [
                        {"name": HOST, "type": "A", "value": IP, "ttl": 60},
                    ],
                },
                {"name": HOST, "type": "AAAA", "status": "NOERROR", "answers": []},
            ],
        },
        "tls-inspection": {
            "schema_version": 1,
            "kind": "tls-observation",
            "asset": asset,
            "observed_at": stamp,
            "peer_ip": IP,
            "server_name": HOST,
            "port": fixtures.tls_port,
            "handshake": "completed",
            "certificate_validation": "valid",
            "protocol": "TLSv1.3",
            "cipher": "TLS_AES_256_GCM_SHA384",
            "certificate_sha256": fixtures.certificate_sha256,
            "not_before": (now - timedelta(minutes=1)).isoformat(),
            "not_after": (now + timedelta(days=1)).isoformat(),
        },
        "http-capture-review": {
            "source": "capture",
            "url": asset,
            "method": "GET",
            "captured_at": stamp,
            "status_code": 200,
            "headers": {
                "X-Content-Type-Options": "nosniff",
                "Strict-Transport-Security": "max-age=31536000",
                "Set-Cookie": "session=fixture-private-cookie",
            },
            "body": "fixture-private-body",
        },
        "sarif-review": {
            "version": "2.1.0",
            "properties": {"asset": asset},
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "synthetic-scanner",
                            "version": "1",
                            "rules": [{"id": "FIXTURE001"}],
                        }
                    },
                    "invocations": [{"executionSuccessful": True, "exitCode": 0}],
                    "results": [
                        {
                            "ruleId": "FIXTURE001",
                            "ruleIndex": 0,
                            "level": "warning",
                            "message": {"text": "Synthetic finding, not independently reproduced"},
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": "src/fixture.py"},
                                        "region": {"startLine": 7},
                                    }
                                }
                            ],
                        }
                    ],
                }
            ],
        },
    }
    return {"network-inventory": "network.xml"} | {
        workflow: _json_file(workspace / f"{workflow}.json", value)
        for workflow, value in values.items()
    }


class SmokeChecks:
    def __init__(
        self,
        workspace: Path,
        fixtures: FixtureServices,
        runner_type: type[DefensiveWorkflowRunner],
    ) -> None:
        from buggy.sandbox_kernel.assessment import AssessmentStore

        self.workspace = workspace
        self.fixtures = fixtures
        self.runner_type = runner_type
        self.store_type = AssessmentStore
        self.results: list[dict[str, Any]] = []
        self.reports: dict[str, dict[str, Any]] = {}
        self.baseline = AssessmentStore(workspace).dispatch("report", {})
        self.ledger_digest = _sha((workspace / "assessment/coverage.sqlite3").read_bytes())
        _require(
            self.baseline["totals"]["cases"] > 0, "Baseline must contain real unassessed cases"
        )

    def _reference(self, reference: dict[str, Any]) -> bytes:
        relative = Path(reference["path"])
        _require(not relative.is_absolute() and ".." not in relative.parts, "Unsafe evidence path")
        path = self.workspace / relative
        _require(path.resolve().is_relative_to(self.workspace), "Evidence escaped the workspace")
        raw = path.read_bytes()
        _require(_sha(raw) == reference["sha256"], f"Evidence hash mismatch: {relative}")
        _require(len(raw) == reference["size_bytes"], f"Evidence size mismatch: {relative}")
        return raw

    def verify_report(self, result: dict[str, Any]) -> None:
        run_id = result["run_id"]
        _require(
            re.fullmatch(r"[0-9a-f]{32}\.[0-9a-f]{64}", run_id) is not None, "Malformed run ID"
        )
        _require(
            result["manifest"]["sha256"] == run_id.split(".")[1], "Run ID does not anchor manifest"
        )
        manifest = json.loads(self._reference(result["manifest"]))
        _require(manifest["run_nonce"] == run_id.split(".")[0], "Run ID nonce mismatch")
        _require(result["assurance"] == "none", "Observation was promoted to assurance")
        _require(
            result["independent_verification"] is False,
            "Observation became independent verification",
        )
        _require(
            result["baseline_coverage_updated"] is False, "Observation claimed baseline promotion"
        )
        _require(result["evidence_integrity"] == "verified", "Untrusted workflow evidence")
        _require(result["integrity_errors"] == [], "Unexpected evidence integrity errors")
        for reference in [result["manifest"], *result["evidence"]]:
            self._reference(reference)
            _require(
                (self.workspace / reference["path"]).stat().st_mode & 0o222 == 0,
                "Evidence is writable",
            )
        if result["source_artifact"] is not None:
            self._reference(result["source_artifact"])
            _require(
                result["source_artifact"]["sha256"] == result["artifact"]["sha256"],
                "Source copy changed",
            )
            _require(result["mode"] == "supplied_artifact", "Artifact mode changed")
            _require(
                result["process"] == {"status": "not_run", "exit_code": None},
                "Artifact executed a command",
            )
        if result["artifact"] is not None:
            _require(result["artifact"] in result["evidence"], "Artifact is absent from evidence")
        _require(self.runner_type(self.workspace).report(run_id) == result, "Fresh report differs")

    def check(
        self,
        name: str,
        workflow: str,
        payload: dict[str, Any],
        *,
        status: str = "observed",
        code: str | None = None,
        quiet: bool = False,
        validate: Callable[[dict[str, Any]], None] | None = None,
    ) -> None:
        before = self.fixtures.snapshot()
        started = time.monotonic()
        record: dict[str, Any] = {"check": name, "ok": False}
        result: dict[str, Any] | None = None
        try:
            result = self.runner_type(self.workspace).run(workflow, payload)
            record.update(
                status=result.get("status"),
                run_id=result.get("run_id"),
                process=result.get("process"),
                evidence_count=len(result.get("evidence", [])),
                observations=result.get("observations"),
                workflow_error=result.get("error"),
                tool=result.get("tool"),
                commands=[
                    process["argv"] for process in result.get("processes", []) if "argv" in process
                ],
            )
            self.verify_report(result)
            record["native_stderr"] = [
                self._reference(process["stderr"]).decode("utf-8", errors="replace")[:8192]
                for process in result.get("processes", [])
                if process.get("stderr", {}).get("size_bytes", 0)
            ]
            _require(result["run_id"] not in self.reports, "A run ID was reused")
            self.reports[result["run_id"]] = result
            if quiet:
                time.sleep(0.15)
                _require(
                    self.fixtures.snapshot() == before, "A no-request case contacted a fixture"
                )
                _require(
                    result["process"]["status"] == "not_run",
                    "Blocked/artifact case executed a command",
                )
                _require(not result.get("processes"), "Unexpected process/transport history")
            _require(result["status"] == status, f"Expected {status}, got {result['status']}")
            if code is not None:
                _require(result["error"]["code"] == code, f"Expected error code {code}")
            if status == "blocked":
                _require(result["observations"] == [], "Blocked action retained observations")
            if validate is not None:
                validate(result)
            _require(
                self.store_type(self.workspace).dispatch("report", {}) == self.baseline,
                "Baseline changed",
            )
            record["ok"] = True
        except Exception as exc:
            record["error"] = {"type": type(exc).__name__, "message": str(exc)}
            if result is not None:
                record["native_output"] = [
                    {
                        "argv": process.get("argv"),
                        **{
                            stream: self._reference(process[stream]).decode(
                                "utf-8", errors="replace"
                            )[:8192]
                            for stream in ("stdout", "stderr")
                            if stream in process
                        },
                    }
                    for process in result.get("processes", [])
                ]
        record["elapsed_seconds"] = round(time.monotonic() - started, 3)
        self.results.append(record)
        print(json.dumps(record, sort_keys=True), flush=True)

    def finish(self) -> None:
        for report in self.reports.values():
            self.verify_report(report)
        _require(
            self.store_type(self.workspace).dispatch("report", {}) == self.baseline,
            "Final baseline changed",
        )
        _require(
            _sha((self.workspace / "assessment/coverage.sqlite3").read_bytes())
            == self.ledger_digest,
            "Baseline ledger bytes changed",
        )
        _require(not self.fixtures.errors, f"Fixture errors: {self.fixtures.errors}")


def _check_dns(result: dict[str, Any]) -> None:
    _require(
        result["observations"] == [{"name": HOST, "type": "A", "value": IP, "ttl": 60}],
        "Unexpected DNS answers",
    )
    _require(
        result["query_statuses"] == {"A": "NOERROR", "AAAA": "NOERROR"}, "Incomplete A/AAAA results"
    )
    _require(result["resolved_ips"] == [IP], "DNS escaped the fixture IP")
    processes = result["processes"]
    _require(len(processes) == 2, "DNS retried or expanded its questions")
    for process, kind in zip(processes, ("A", "AAAA"), strict=True):
        argv = process["argv"]
        _require(argv[:6] == ["dig", "-r", "-q", HOST + ".", "-t", kind], "Unexpected DNS command")
        _require(
            {"+time=2", "+tries=1", "+nosearch", "+ignore"} <= set(argv),
            "DNS command lost its bounds",
        )
        _require(
            process["status"] == "completed" and process["exit_code"] == 0, "Native dig failed"
        )


def _check_network(result: dict[str, Any], fixtures: FixtureServices) -> None:
    _require(
        result["pinned_ip"] == IP and result["resolved_ips"] == [IP], "Nmap target was not pinned"
    )
    ports = sorted([fixtures.tcp_port, fixtures.closed_port])
    _require(len(result["processes"]) == len(ports), "Nmap must run one process per port")
    _require(len(result["artifacts"]) == len(ports), "Per-port native XML was not retained")
    _require(result["artifact"] == result["artifacts"][0], "Primary artifact is not the first XML")
    previous_start: datetime | None = None
    for process, port, artifact in zip(
        result["processes"], ports, result["artifacts"], strict=True
    ):
        argv = process["argv"]
        _require(argv[0] == "nmap" and argv[-1] == IP, "Nmap target was not the fixture")
        _require(
            {"-sT", "-Pn", "-n", "--unprivileged", "--disable-arp-ping", "--no-stylesheet"}
            <= set(argv),
            "Nmap lost connect-only flags",
        )
        _require(
            not {"-sS", "-sU", "-sV", "-sC", "--script", "-A", "-O"} & set(argv),
            "Nmap broadened its mode",
        )
        _require(
            not {"--scan-delay", "--max-parallelism"} & set(argv),
            "Nmap returned to conflicting rate/concurrency flags",
        )
        for flag, value in (("--max-rate", "1"), ("--max-retries", "0"), ("--host-timeout", "18s")):
            _require(argv[argv.index(flag) + 1] == value, f"Nmap lost its {flag} bound")
        _require(argv[argv.index("-p") + 1] == str(port), "Nmap scanned more than one port")
        _require(artifact in result["evidence"], "Per-port XML is absent from evidence")
        _require(
            process["status"] == "completed" and process["exit_code"] == 0, "Native Nmap failed"
        )
        _require(process["stderr"]["size_bytes"] == 0, "Native Nmap emitted a warning or error")
        started = datetime.fromisoformat(process["started_at"])
        if previous_start is not None:
            _require(
                (started - previous_start).total_seconds() >= 1,
                "Nmap exceeded one start per second",
            )
        previous_start = started
    _require(result["unobserved_ports"] == [], "Nmap lost requested port observations")
    _require(
        {item["port"]: item["state"] for item in result["observations"]}
        == {fixtures.tcp_port: "open", fixtures.closed_port: "closed"},
        "Native Nmap disagrees with fixture listeners",
    )
    _require(
        all(item["ip"] == IP and item["protocol"] == "tcp" for item in result["observations"]),
        "Unexpected Nmap target or protocol",
    )


def _check_tls(result: dict[str, Any], fixtures: FixtureServices, name: str) -> None:
    _require(result["pinned_ip"] == IP, "TLS did not pin the fixture IP")
    _require(
        result["process"] == {"status": "completed", "exit_code": None},
        "TLS transport did not complete",
    )
    _require(
        len(result["processes"]) == (3 if name == HOST else 1), "TLS retried or made extra requests"
    )
    observation = result["observations"][0]
    expected = {
        "peer_ip": IP,
        "port": fixtures.tls_port,
        "server_name": name,
        "handshake": "completed",
        "certificate_validation": "valid",
        "certificate_sha256": fixtures.certificate_sha256,
    }
    _require(
        all(observation[key] == value for key, value in expected.items()),
        "TLS metadata does not match the generated certificate",
    )
    _require(
        observation["protocol"] in {"TLSv1.2", "TLSv1.3"} and observation["cipher"] != "unknown",
        "Missing native TLS negotiation",
    )
    _require(
        bool(observation["not_before"] and observation["not_after"]), "Missing certificate validity"
    )
    _require(fixtures.server_names[-1] == (name if name == HOST else None), "TLS SNI mismatch")


def run_smoke() -> dict[str, Any]:
    """Run fixture-only verification; return a machine-readable final summary."""
    verify_isolation()
    from buggy.sandbox_kernel.capabilities import inspect_capabilities

    inspection = inspect_capabilities(probe=True)
    _require(
        {entry["id"] for entry in inspection["capabilities"]} == set(WORKFLOWS),
        "Capability catalog differs",
    )
    _require(
        all(entry["status"] == "available" for entry in inspection["capabilities"]),
        f"Native prerequisites unavailable: {inspection}",
    )
    _require(
        inspection["workflow_runtime"]["status"] == "available"
        and inspection["workflow_runtime"]["check"] == "bounded_import_check",
        "Workflow imports were not explicitly verified",
    )
    _require(inspection["end_to_end_validation"] == "not_performed", "A probe claimed assessment")
    print(json.dumps({"capabilities": inspection}, sort_keys=True), flush=True)
    try:
        from buggy.sandbox_kernel import (
            _workflow_storage,
            bounded_process,
            defensive_workflows,
        )
        from buggy.sandbox_kernel.defensive_workflows import DefensiveWorkflowRunner
    except ModuleNotFoundError as exc:
        raise SmokePrerequisiteError(
            f"Workflow runtime dependency missing: {exc.name}. Prepare an approved sandbox image; "
            "this smoke never installs dependencies."
        ) from exc
    with TemporaryDirectory(prefix="defensive-workflows-smoke-") as temporary:
        root = Path(temporary)
        workspace = root / "workspace"
        workspace.mkdir(mode=0o700)
        empty_trust = root / "empty-trust"
        empty_trust.mkdir(mode=0o700)
        with FixtureServices(root / "fixtures").running() as fixtures:
            roe = initialize_assessment(workspace, fixtures)
            checks = SmokeChecks(workspace, fixtures, DefensiveWorkflowRunner)
            asset = f"https://{HOST}:{fixtures.tls_port}/"
            literal = f"https://{IP}:{fixtures.tls_port}/"
            ports = [fixtures.tcp_port, fixtures.closed_port]
            for workflow, path in write_artifacts(workspace, fixtures).items():

                def validate_artifact(result: dict[str, Any]) -> None:
                    _require(
                        bool(result["observations"]), "Supplied fixture produced no observations"
                    )
                    _require(
                        "fixture-private-cookie" not in json.dumps(result),
                        "HTTP cookie leaked into report",
                    )
                    _require(
                        "fixture-private-body" not in json.dumps(result),
                        "HTTP body leaked into report",
                    )
                    if result["workflow_id"] == "sarif-review":
                        _require(result["source_executed"] is False, "SARIF executed source")

                checks.check(
                    f"artifact:{workflow}",
                    workflow,
                    {"url": asset, "artifact_path": path},
                    quiet=True,
                    validate=validate_artifact,
                )
            checks.check(
                "native:nmap-ip",
                "network-inventory",
                {"url": literal, "observe": True, "ports": ports},
                validate=lambda result: _check_network(result, fixtures),
            )
            checks.check(
                "native:dns", "dns-inventory", {"url": asset, "observe": True}, validate=_check_dns
            )
            with _trust(fixtures.certificate, empty_trust):
                for name, url in ((IP, literal), (HOST, asset)):
                    checks.check(
                        f"native:tls-{name}",
                        "tls-inspection",
                        {"url": url, "observe": True},
                        validate=lambda result, name=name: _check_tls(result, fixtures, name),
                    )
            before_invalid = fixtures.snapshot()
            with _trust(empty_trust / "absent.pem", empty_trust):
                _require(
                    ssl.create_default_context().cert_store_stats()["x509_ca"] == 0,
                    "Negative TLS fixture still has trusted CAs",
                )

                def invalid_tls(result: dict[str, Any]) -> None:
                    time.sleep(0.15)
                    after = fixtures.snapshot()
                    _require(
                        after[2] - before_invalid[2] == 1 and after[3] == before_invalid[3],
                        "Invalid TLS retried or completed an unverified handshake",
                    )
                    _require(
                        after[4] - before_invalid[4] == 1,
                        "TLS server did not see one rejected handshake",
                    )
                    _require(
                        result["observations"][0]["certificate_validation"] == "invalid",
                        "Invalid certificate was credited",
                    )

                checks.check(
                    "safety:tls-untrusted-no-retry",
                    "tls-inspection",
                    {"url": literal, "observe": True},
                    status="inconclusive",
                    code="TLS_CERTIFICATE_INVALID",
                    validate=invalid_tls,
                )
            modes = [
                (
                    workflow,
                    {"url": asset, "observe": True}
                    | ({"ports": ports} if workflow == "network-inventory" else {}),
                )
                for workflow in WORKFLOWS[:3]
            ]
            roe_path = workspace / "plan/roe.json"
            for label, changes, code in (
                ("enforcement-required", {"mode": "audit"}, "ENFORCEMENT_REQUIRED"),
                ("roe-out-of-scope", {"out_of_scope": [HOST, IP]}, "OUT_OF_SCOPE"),
                (
                    "command-forbidden",
                    {"forbidden_command_patterns": [r"\b(?:dig|nmap|ssl)\b"]},
                    "FORBIDDEN_COMMAND",
                ),
            ):
                _json_file(
                    roe_path, roe | {"machine_enforcement": roe["machine_enforcement"] | changes}
                )
                try:
                    for workflow, payload in modes:
                        checks.check(
                            f"safety:{label}:{workflow}",
                            workflow,
                            payload,
                            status="blocked",
                            code=code,
                            quiet=True,
                        )
                finally:
                    _json_file(roe_path, roe)
            for workflow, payload in modes:
                checks.check(
                    f"safety:assessment-out-of-scope:{workflow}",
                    workflow,
                    payload | {"url": f"https://outside.fixture.test:{fixtures.tls_port}/"},
                    status="blocked",
                    code="ASSESSMENT_SCOPE",
                    quiet=True,
                )
            abort = workspace / ".abort"
            abort.touch(mode=0o600)
            try:
                for workflow, payload in modes:
                    checks.check(
                        f"safety:abort:{workflow}",
                        workflow,
                        payload,
                        status="blocked",
                        code="EMERGENCY_ABORT",
                        quiet=True,
                    )
            finally:
                abort.unlink()
            before_abort = fixtures.snapshot()
            with fixtures.lock:
                fixtures.abort_on_query = abort
            try:

                def inflight_abort(result: dict[str, Any]) -> None:
                    after = fixtures.snapshot()
                    _require(
                        after[0] - before_abort[0] == 1 and after[1:] == before_abort[1:],
                        "Abort allowed another query or target connection",
                    )
                    _require(
                        len(result["processes"]) == 1
                        and result["processes"][0]["argv"][0] == "dig",
                        "Abort did not stop after the first bounded action",
                    )

                checks.check(
                    "safety:abort-during-native-dns",
                    "network-inventory",
                    {"url": asset, "observe": True, "ports": ports},
                    status="blocked",
                    code="EMERGENCY_ABORT",
                    validate=inflight_abort,
                )
            finally:
                with fixtures.lock:
                    fixtures.abort_on_query = None
                abort.unlink(missing_ok=True)
            checks.finish()
            passed = sum(record["ok"] for record in checks.results)
            summary = {
                "status": "passed" if passed == len(checks.results) else "failed",
                "checks_passed": passed,
                "checks_total": len(checks.results),
                "persisted_runs_verified": len(checks.reports),
                "baseline_unchanged": True,
                "baseline_revision": checks.baseline["revision"],
                "baseline_cases": checks.baseline["totals"]["cases"],
                "fixture_requests": {
                    "dns": fixtures.queries,
                    "tcp": fixtures.tcp_connections,
                    "tls": fixtures.tls_connections,
                    "tls_verified": fixtures.tls_handshakes,
                    "tls_rejected": fixtures.tls_rejections,
                    "sni": fixtures.server_names,
                },
                "fixture_ports": {
                    "open": fixtures.tcp_port,
                    "closed": fixtures.closed_port,
                    "tls": fixtures.tls_port,
                },
                "runtime_sources": {
                    module.__name__: _sha(Path(module.__file__).read_bytes())
                    for module in (defensive_workflows, _workflow_storage, bounded_process)
                    if module.__file__ is not None
                },
                "workspace_cleanup": "TemporaryDirectory; no retained keys or evidence",
            }
    return summary


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "--run", action="store_true", help="Explicitly run fixture-only native verification"
    )
    args = parser.parse_args(argv)
    if not args.run:
        parser.error("Pass --run inside a new --network none container; this is not a default test")
    try:
        summary = run_smoke()
    except Exception as exc:
        print(
            json.dumps(
                {"status": "failed", "error": {"type": type(exc).__name__, "message": str(exc)}}
            ),
            flush=True,
        )
        return 1
    print(json.dumps(summary, sort_keys=True), flush=True)
    return 0 if summary["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
