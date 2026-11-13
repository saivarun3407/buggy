"""Bounded defensive observations, never baseline dispositions or independent assurance."""

from __future__ import annotations

import ipaddress
import re
import shlex
import socket
import ssl
import time
from contextlib import closing
from copy import deepcopy
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from defusedxml import ElementTree
from defusedxml.common import DefusedXmlException

from buggy.sandbox_kernel._workflow_storage import (
    LIMIT,
    NON_ASSURANCE,
    DefensiveWorkflowError,
    WorkflowInputError,
    WorkflowStorage,
    WorkflowStorageError,
)
from buggy.sandbox_kernel.assessment import (
    AssessmentError,
    AssessmentStore,
    _boolean,
    _dump,
    _header_result,
    _host,
    _in_scope,
    _integer,
    _json_object,
    _method,
    _now,
    _sha,
    _text,
    _timestamp,
    _url,
)
from buggy.sandbox_kernel.bounded_process import run_bounded
from buggy_core.types.roe import (
    MachineEnforcement,
    ScopeRule,
    evaluate_command,
    evaluate_target,
    evaluate_time_window,
)

__all__ = [
    "DefensiveWorkflowError",
    "DefensiveWorkflowRunner",
    "WorkflowInputError",
    "WorkflowStorageError",
    "workflow_catalog",
]

_VERSION = "1"
_WORKFLOWS = {
    "network-inventory": "Bounded Nmap XML, one selected host",
    "dns-inventory": "Normalized DNS observation JSON v1, A/AAAA only",
    "tls-inspection": "Normalized TLS observation JSON v1",
    "http-capture-review": "Normalized source=capture HTTP response JSON",
    "sarif-review": "SARIF 2.1.0 report, without executing source",
}
_LIMITATIONS = [
    "Observations are not security passes, independent verification, or complete inventory.",
    "Supplied artifact authenticity is not established; hashes detect changes, not authorship.",
    "Baseline and ASVS coverage are unchanged.",
    "Observation never follows redirects, expands DNS aliases, or retries with weaker verification.",
    "Domain observation requires bounded dig resolution; one authorized IP is selected for Nmap/TLS.",
    "In-flight actions are bounded; abort and authorization are checked before and after each action.",
    "Network observation is serial, one TCP port per process; artifacts lists all XML and artifact aliases the first.",
]
_ARTIFACT_CONTRACTS: dict[str, dict[str, Any]] = {
    "network-inventory": {
        "format": "Nmap XML (UTF-8)",
        "required": "scanner=nmap; explicit runstats/finished exit and consistent runstats/hosts counts",
        "binding": "One IP and at most one host; selected IP or exact supplied hostname must match URL",
        "limits": "2 MiB; 10000 XML nodes; depth 20; 256 explicit ports; no DTD references/entities/stylesheets",
    },
    "dns-inventory": {
        "schema_version": 1,
        "kind": "dns-observation",
        "asset": "Selected HTTP(S) URL",
        "observed_at": "ISO-8601 timestamp with timezone",
        "queries": [
            {
                "name": "Selected hostname",
                "type": "A|AAAA",
                "status": "NOERROR|NXDOMAIN|SERVFAIL|REFUSED|TIMEOUT",
                "answers": [
                    {
                        "name": "Same hostname",
                        "type": "Same record type",
                        "value": "Exact matching-family IP",
                        "ttl": "Integer 0..2147483647",
                    }
                ],
            }
        ],
        "tool": {"name": "Optional tool name", "version": "Optional version, otherwise unknown"},
    },
    "tls-inspection": {
        "schema_version": 1,
        "kind": "tls-observation",
        "asset": "Selected HTTPS URL",
        "observed_at": "ISO-8601 timestamp with timezone",
        "peer_ip": "Exact IP",
        "server_name": "Selected hostname or IP",
        "port": "Selected URL port (default 443)",
        "handshake": "completed|failed",
        "certificate_validation": "valid|invalid|unknown",
        "protocol": "TLS protocol or unknown",
        "cipher": "Cipher name or unknown",
        "certificate_sha256": "Lowercase SHA-256 or null",
        "not_before": "ISO-8601 timestamp or null",
        "not_after": "ISO-8601 timestamp or null",
        "tool": {"name": "Optional tool name", "version": "Optional version, otherwise unknown"},
    },
    "http-capture-review": {
        "source": "capture",
        "url": "Selected operation URL",
        "method": "Selected method (default GET)",
        "captured_at": "ISO-8601 timestamp with timezone",
        "status_code": "Integer 100..599",
        "headers": {"Header-Name": "String or nonempty list of strings"},
        "semantics": "AssessmentStore._check_headers; challenges/errors/non-2xx are inconclusive; no body is evaluated",
    },
    "sarif-review": {
        "version": "2.1.0",
        "runs": "At most 16 runs, each with tool.driver.name and optional results",
        "results": "At most 1000 results total; object messages, valid levels, bounded locations and rule indexes",
        "binding": "Optional log/run properties.asset must match URL; absent binding is caller_asserted",
        "validation": "Bounded core structure, not full optional SARIF semantics; external properties are rejected; no URI is loaded or source executed",
    },
}


def workflow_catalog() -> dict[str, Any]:
    return NON_ASSURANCE | {
        "schema_version": 1,
        "workflows": [
            {
                "workflow_id": key,
                "capability_id": key,
                "version": _VERSION,
                "description": description,
                "artifact_mode": True,
                "observation_mode": key in {"network-inventory", "dns-inventory", "tls-inspection"},
                "observe_default": False,
                "required_parameters": ["url", "artifact_path"],
                "max_artifact_bytes": LIMIT,
                "artifact_contract": deepcopy(_ARTIFACT_CONTRACTS[key]),
                "observation_parameters": (
                    {"observe": True, "url": "Exact HTTP(S) origin URL"}
                    | (
                        {"ports": "1..16 unique integers, 1..65535"}
                        if key == "network-inventory"
                        else {}
                    )
                )
                if key in {"network-inventory", "dns-inventory", "tls-inspection"}
                else None,
                "observation_requirements": "Initialized assessment; enforced RoE; scoped asset; no abort; supported timing/rate policy"
                if key in {"network-inventory", "dns-inventory", "tls-inspection"}
                else None,
            }
            for key, description in _WORKFLOWS.items()
        ],
    }


def _ip(value: Any) -> str:
    try:
        return ipaddress.ip_address(_host(value)).compressed
    except ValueError as exc:
        raise AssessmentError("An exact IP address is required") from exc


def _xml_integer(value: Any, field: str, minimum: int, maximum: int) -> int:
    if not isinstance(value, str) or not re.fullmatch(r"[0-9]{1,10}", value):
        raise AssessmentError("Invalid Nmap numeric field")
    return _integer(int(value), field, minimum, maximum)


def _network(raw: bytes, asset: str, pinned_ip: str | None = None) -> dict[str, Any]:
    try:
        text = raw.decode("utf-8")
        if re.search(r"<\?(?!xml\s)", text):
            raise AssessmentError(
                "XML processing instructions and external stylesheets are forbidden"
            )
        text = re.sub(r"<!DOCTYPE\s+nmaprun\s*>", "", text, count=1)
        root = ElementTree.fromstring(
            text, forbid_dtd=True, forbid_entities=True, forbid_external=True
        )
    except (UnicodeError, ElementTree.ParseError, DefusedXmlException) as exc:
        raise AssessmentError("Malformed or external-reference Nmap XML is forbidden") from exc
    nodes = list(root.iter())
    if root.tag != "nmaprun" or root.get("scanner") != "nmap" or len(nodes) > 10000:
        raise AssessmentError("A bounded Nmap run is required")
    if any(
        not isinstance(node.tag, str)
        or "{" in node.tag
        or any("{" in key or key == "href" for key in node.attrib)
        for node in nodes
    ):
        raise AssessmentError("Namespaced or external-reference XML is forbidden")
    pending = [(root, 0)]
    while pending:
        element, depth = pending.pop()
        if depth > 20:
            raise AssessmentError("Nmap XML nesting exceeds its bound")
        pending.extend((child, depth + 1) for child in element)
    finished = root.findall("runstats/finished")
    if len(finished) != 1 or finished[0].get("exit") not in {"success", "error"}:
        raise AssessmentError("Nmap run is incomplete or lacks an explicit completion status")
    hosts = root.findall("host")
    if len(hosts) > 1 or len(root.findall(".//host")) != len(hosts):
        raise AssessmentError("Network inventory accepts only one selected host")
    summaries = root.findall("runstats/hosts")
    if len(summaries) != 1:
        raise AssessmentError("Nmap run must include complete host counts")
    counts = {
        key: _xml_integer(summaries[0].get(key), key, 0, 1) for key in ("up", "down", "total")
    }
    if counts["up"] + counts["down"] != counts["total"] or len(hosts) > counts["total"]:
        raise AssessmentError("Nmap host counts disagree with the supplied observations")
    observations = []
    selected = _host(urlsplit(asset).hostname)
    for host in hosts:
        addresses = []
        for address in host.findall("address"):
            family = address.get("addrtype")
            if family not in {"ipv4", "ipv6"}:
                continue
            parsed = _ip(address.get("addr"))
            if (":" in parsed) != (family == "ipv6"):
                raise AssessmentError("Nmap address family does not match its value")
            addresses.append(parsed)
        names = [_host(item.get("name")) for item in host.findall("hostnames/hostname")]
        if len(addresses) != 1:
            raise AssessmentError("Nmap host must have one concrete selected address")
        if pinned_ip is not None:
            matches = set(addresses) == {pinned_ip}
        else:
            matches = selected in addresses or bool(names) and set(names) == {selected}
        if not matches:
            raise AssessmentError("Nmap host does not match the selected asset")
        statuses = host.findall("status")
        if len(statuses) != 1 or statuses[0].get("state") not in {"up", "down", "unknown"}:
            raise AssessmentError("Nmap host status is missing or invalid")
        host_state = statuses[0].get("state", "unknown")
        ports = host.findall("ports/port")
        if ports and host_state != "up":
            raise AssessmentError("Nmap port observations require an up host")
        if host_state in {"up", "down"} and not counts[host_state]:
            raise AssessmentError("Nmap status contradicts its host counts")
        if len(ports) > 256:
            raise AssessmentError("Nmap inventory exceeds 256 supplied ports")
        seen = set()
        for port in ports:
            number = _xml_integer(port.get("portid"), "port", 1, 65535)
            protocol = port.get("protocol")
            state = port.find("state")
            if (
                protocol not in {"tcp", "udp"}
                or len(port.findall("state")) != 1
                or state is None
                or state.get("state")
                not in {
                    "open",
                    "closed",
                    "filtered",
                    "unfiltered",
                    "open|filtered",
                    "closed|filtered",
                    "unknown",
                }
                or (protocol, number) in seen
            ):
                raise AssessmentError("Nmap port observation is malformed or duplicated")
            seen.add((protocol, number))
            service = port.find("service")
            observations.append(
                {
                    "ip": addresses[0],
                    "port": number,
                    "protocol": protocol,
                    "state": state.get("state"),
                    "service": _text(service.get("name", "unknown"), "service", 128)
                    if service is not None
                    else "unknown",
                }
            )
    return {
        "status": "observed"
        if observations and finished[0].get("exit") == "success"
        else "inconclusive",
        "observations": observations,
        "tool": {
            "name": "nmap",
            "version": _text(root.get("version", "unknown"), "nmap version", 128),
        },
    }


def _object(value: Any, field: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise AssessmentError(f"{field} must be an object")
    return value


def _items(value: Any, field: str, maximum: int) -> list[Any]:
    if not isinstance(value, list) or len(value) > maximum:
        raise AssessmentError(f"{field} must be a bounded list")
    return value


def _normalized(raw: bytes, asset: str, kind: str) -> dict[str, Any]:
    value = _json_object(raw)
    if (
        _integer(value.get("schema_version"), "schema_version", 1, 1) != 1
        or value.get("kind") != kind
    ):
        raise AssessmentError("Unknown normalized observation schema")
    if _url(value.get("asset")) != asset:
        raise AssessmentError("Observation does not match the selected asset")
    _timestamp(value.get("observed_at"), "observed_at")
    return value


def _tool(value: dict[str, Any], name: str) -> dict[str, str]:
    tool = _object(value.get("tool", {}), "tool")
    return {
        "name": _text(tool.get("name", name), "tool name", 128),
        "version": _text(tool.get("version", "unknown"), "tool version", 128),
    }


def _dns(raw: bytes, asset: str) -> dict[str, Any]:
    value = _normalized(raw, asset, "dns-observation")
    host = _host(urlsplit(asset).hostname)
    observations = []
    statuses: dict[str, str] = {}
    for query_value in _items(value.get("queries"), "queries", 2):
        query = _object(query_value, "query")
        kind = _text(query.get("type"), "query type", 4)
        status = _text(query.get("status"), "query status", 16)
        if _host(query.get("name")) != host or kind not in {"A", "AAAA"} or kind in statuses:
            raise AssessmentError(
                "DNS questions must be unique A/AAAA questions for the selected host"
            )
        if status not in {"NOERROR", "NXDOMAIN", "SERVFAIL", "REFUSED", "TIMEOUT"}:
            raise AssessmentError("Unknown DNS query status")
        statuses[kind] = status
        answers = _items(query.get("answers"), "answers", 64)
        if status != "NOERROR" and answers:
            raise AssessmentError("Failed DNS questions cannot contain answers")
        seen = set()
        for answer_value in answers:
            answer = _object(answer_value, "answer")
            address = _ip(answer.get("value"))
            if _host(answer.get("name")) != host or answer.get("type") != kind:
                raise AssessmentError("DNS answers must match the exact selected question")
            if (":" in address) != (kind == "AAAA") or address in seen:
                raise AssessmentError("DNS answer family is incorrect or duplicated")
            seen.add(address)
            observations.append(
                {
                    "name": host,
                    "type": kind,
                    "value": address,
                    "ttl": _integer(answer.get("ttl"), "ttl", 0, 2147483647),
                }
            )
    return {
        "status": "observed"
        if observations and set(statuses.values()) == {"NOERROR"}
        else "inconclusive",
        "observations": observations,
        "query_statuses": statuses,
        "tool": _tool(value, "normalized-dns"),
    }


def _tls(raw: bytes, asset: str) -> dict[str, Any]:
    value = _normalized(raw, asset, "tls-observation")
    target = urlsplit(asset)
    if target.scheme != "https" or _host(value.get("server_name")) != target.hostname:
        raise AssessmentError("TLS observations require the selected HTTPS authority")
    port = _integer(value.get("port"), "port", 1, 65535)
    if port != (target.port or 443):
        raise AssessmentError("TLS port does not match the selected asset")
    peer = _ip(value.get("peer_ip"))
    try:
        literal = str(ipaddress.ip_address(target.hostname or ""))
    except ValueError:
        literal = None
    if literal is not None and peer != literal:
        raise AssessmentError("TLS peer does not match the selected IP")
    handshake = _text(value.get("handshake"), "handshake", 16)
    validation = _text(value.get("certificate_validation"), "certificate_validation", 16)
    if handshake not in {"completed", "failed"} or validation not in {
        "valid",
        "invalid",
        "unknown",
    }:
        raise AssessmentError("Invalid TLS handshake or certificate validation state")
    if handshake == "failed" and validation == "valid":
        raise AssessmentError("Failed TLS handshakes cannot establish certificate validation")
    certificate = value.get("certificate_sha256")
    if certificate is not None and (
        not isinstance(certificate, str) or not re.fullmatch(r"[0-9a-f]{64}", certificate)
    ):
        raise AssessmentError("Invalid TLS certificate digest")
    observation = {
        "peer_ip": peer,
        "port": port,
        "server_name": target.hostname,
        "handshake": handshake,
        "certificate_validation": validation,
        "protocol": _text(value.get("protocol", "unknown"), "protocol", 32),
        "cipher": _text(value.get("cipher", "unknown"), "cipher", 128),
        "certificate_sha256": certificate,
        "not_before": _timestamp(value["not_before"], "not_before", allow_future=True)
        if value.get("not_before") is not None
        else None,
        "not_after": _timestamp(value["not_after"], "not_after", allow_future=True)
        if value.get("not_after") is not None
        else None,
    }
    return {
        "status": "observed"
        if handshake == "completed" and validation == "valid" and certificate
        else "inconclusive",
        "observations": [observation],
        "tool": _tool(value, "normalized-tls"),
    }


def _capture(raw: bytes, asset: str, method: str) -> dict[str, Any]:
    value = _json_object(raw)
    if value.get("source") != "capture":
        raise AssessmentError("Only source=capture response artifacts are accepted")
    _timestamp(value.get("captured_at"), "captured_at")
    if _url(value.get("url")) != asset or _method(value.get("method")) != method:
        raise AssessmentError("Captured URL and method must match the selected operation")
    observations = []
    for control in ("http.nosniff", "http.hsts"):
        status, reason = _header_result(control, asset, value)
        observations.append(
            {
                "control_id": control,
                "result": {"pass": "present", "fail": "missing_or_ambiguous"}.get(status, status),
                "reason": reason,
            }
        )
    return {
        "status": "inconclusive"
        if all(item["result"] == "inconclusive" for item in observations)
        else "observed",
        "observations": observations,
        "tool": {"name": "captured-http-response", "version": "unknown"},
    }


def _sarif_asset(value: dict[str, Any], asset: str) -> bool:
    properties = _object(value.get("properties", {}), "SARIF properties")
    if "asset" in properties and _url(properties["asset"]) != asset:
        raise AssessmentError("SARIF asset does not match the selected asset")
    return "asset" in properties


def _sarif(raw: bytes, asset: str) -> dict[str, Any]:
    value = _json_object(raw)
    if value.get("version") != "2.1.0":
        raise AssessmentError("Only SARIF 2.1.0 reports are accepted")
    bound = _sarif_asset(value, asset)
    observations = []
    tools = []
    completed = True
    for index, run_value in enumerate(_items(value.get("runs"), "SARIF runs", 16)):
        run = _object(run_value, "SARIF run")
        bound = _sarif_asset(run, asset) or bound
        if "externalPropertyFileReferences" in run or "inlineExternalProperties" in value:
            raise AssessmentError("External SARIF properties are unsupported and never loaded")
        driver = _object(_object(run.get("tool"), "SARIF tool").get("driver"), "SARIF driver")
        tools.append(
            {
                "name": _text(driver.get("name"), "SARIF driver name", 128),
                "version": _text(driver.get("version", "unknown"), "SARIF driver version", 128),
            }
        )
        rules = _items(driver.get("rules", []), "SARIF rules", 1000)
        rule_ids = [
            _text(_object(rule, "SARIF rule").get("id"), "SARIF rule id", 512) for rule in rules
        ]
        if len(set(rule_ids)) != len(rule_ids):
            raise AssessmentError("Duplicate SARIF rule IDs")
        artifacts = _items(run.get("artifacts", []), "SARIF artifacts", 1000)
        for item in artifacts:
            _object(item, "SARIF artifact")
        for invocation_value in _items(run.get("invocations", []), "SARIF invocations", 32):
            invocation = _object(invocation_value, "SARIF invocation")
            success = _boolean(invocation.get("executionSuccessful"), "executionSuccessful")
            code = _integer(
                invocation.get("exitCode", 0), "SARIF exitCode", -2147483648, 2147483647
            )
            completed = completed and success and code == 0
        for result_value in _items(run.get("results", []), "SARIF results", 1000):
            result = _object(result_value, "SARIF result")
            message = _object(result.get("message"), "SARIF result message")
            if not any(key in message for key in ("text", "markdown", "id")):
                raise AssessmentError("SARIF messages must contain text, markdown, or an ID")
            for key in ("text", "markdown", "id"):
                if key in message:
                    _text(message[key], "SARIF message", 32768, multiline=True)
            rule_id = _text(result.get("ruleId", "unknown"), "SARIF result ruleId", 512)
            if "ruleIndex" in result:
                rule_index = _integer(result["ruleIndex"], "ruleIndex", 0, len(rule_ids) - 1)
                if rule_id not in {"unknown", rule_ids[rule_index]}:
                    raise AssessmentError("SARIF ruleId and ruleIndex disagree")
                rule_id = rule_ids[rule_index]
            level = _text(result.get("level", "warning"), "SARIF level", 16)
            if level not in {"none", "note", "warning", "error"}:
                raise AssessmentError("Invalid SARIF level")
            locations = _items(result.get("locations", []), "SARIF locations", 32)
            for location_value in locations:
                location = _object(location_value, "SARIF location")
                if "physicalLocation" not in location:
                    if "logicalLocations" not in location:
                        raise AssessmentError("SARIF location lacks a physical or logical location")
                    _items(location["logicalLocations"], "logicalLocations", 32)
                    continue
                physical = _object(location["physicalLocation"], "physicalLocation")
                target = _object(physical.get("artifactLocation"), "artifactLocation")
                if "uri" in target:
                    _text(target["uri"], "SARIF location URI", 4096)
                elif "index" not in target:
                    raise AssessmentError("SARIF artifact location requires a URI or index")
                if "index" in target:
                    _integer(target["index"], "artifact index", 0, len(artifacts) - 1)
                region = _object(physical.get("region", {}), "SARIF region")
                for key in ("startLine", "endLine", "startColumn", "endColumn"):
                    if key in region:
                        _integer(region[key], key, 1, 2147483647)
                if (
                    "startLine" in region
                    and region.get("endLine", region["startLine"]) < region["startLine"]
                ):
                    raise AssessmentError("Invalid SARIF region ordering")
            observations.append(
                {
                    "run_index": index,
                    "rule_id": rule_id,
                    "level": level,
                    "locations_count": len(locations),
                }
            )
            if len(observations) > 1000:
                raise AssessmentError("SARIF report exceeds 1000 total results")
    return {
        "status": "observed" if completed and observations else "inconclusive",
        "observations": observations,
        "tool": tools[0]
        if len(tools) == 1
        else {"name": "multiple" if tools else "unknown", "version": "unknown"},
        "tools": tools,
        "asset_binding": "artifact_declared" if bound else "caller_asserted",
        "source_executed": False,
        "validation_profile": "bounded-sarif-2.1.0-core",
    }


class _ObservationStopped(Exception):
    def __init__(self, status: str, code: str, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.code = code


def _scope_entries(
    value: Any, asset: str, port: int, *, deny: bool = False
) -> tuple[ScopeRule, ...]:
    result = []
    for entry in _items(value, "RoE scope", 128):
        kind = "auto"
        if isinstance(entry, dict):
            if set(entry) - {"target", "type"}:
                raise AssessmentError("Unsupported RoE scope fields")
            kind = _text(entry.get("type", "auto"), "scope type", 16)
            entry = entry.get("target")
        pattern = _text(entry, "scope pattern", 1024)
        if kind not in {"auto", "host", "ip", "cidr", "domain-glob"}:
            raise AssessmentError("Unsupported RoE scope kind")
        if "://" in pattern:
            target = urlsplit(_url(pattern))
            if not deny and (target.path != "/" or target.query):
                raise AssessmentError("Path-restricted RoE cannot authorize host observation")
            target_port = target.port or (443 if target.scheme == "https" else 80)
            if not deny and (target.scheme != urlsplit(asset).scheme or target_port != port):
                continue
            pattern, kind = _host(target.hostname), "host"
        elif "/" in pattern:
            if kind not in {"auto", "cidr"} or "%" in pattern:
                raise AssessmentError("Invalid RoE network scope")
            try:
                pattern, kind = str(ipaddress.ip_network(pattern, strict=False)), "cidr"
            except ValueError as exc:
                raise AssessmentError("Invalid RoE CIDR") from exc
        elif pattern.startswith("*."):
            if kind not in {"auto", "domain-glob"}:
                raise AssessmentError("Invalid RoE wildcard kind")
            pattern, kind = "*." + _host(pattern[2:]), "domain-glob"
        else:
            pattern = _ip(pattern) if kind in {"ip", "cidr"} else _host(pattern)
        result.append(ScopeRule(pattern, kind))
    return tuple(result)


def _machine(roe: dict[str, Any], asset: str, ports: list[int]) -> MachineEnforcement:
    data = dict(_object(roe.get("machine_enforcement"), "machine_enforcement"))
    if data.get("mode") != "enforce":
        raise _ObservationStopped(
            "blocked", "ENFORCEMENT_REQUIRED", "machine_enforcement.mode must be enforce"
        )
    fields = {
        "mode",
        "in_scope",
        "out_of_scope",
        "forbidden_destinations",
        "forbidden_command_patterns",
        "allow_cloud_metadata",
        "allow_sensitive_tlds",
        "max_concurrent_connections",
        "min_inter_request_delay_ms",
        "authorized_windows",
        "blackout_windows",
    }
    if set(data) - fields:
        raise AssessmentError("Unsupported machine-enforcement fields")
    for field in ("allow_cloud_metadata", "allow_sensitive_tlds"):
        data[field] = _boolean(data.get(field, False), field)
    if data.get("max_concurrent_connections") is not None:
        _integer(data["max_concurrent_connections"], "max_concurrent_connections", 1, 1024)
    data["min_inter_request_delay_ms"] = _integer(
        data.get("min_inter_request_delay_ms", 0), "min_inter_request_delay_ms", 0, 1000
    )
    for field in ("authorized_windows", "blackout_windows"):
        windows = []
        for window in _items(data.get(field, []), field, 64):
            pair = (
                [window.get("start"), window.get("end")]
                if isinstance(window, dict) and set(window) == {"start", "end"}
                else window
            )
            if not isinstance(pair, list) or len(pair) != 2:
                raise AssessmentError("Invalid RoE time window")
            start, end = [_timestamp(item, field, allow_future=True) for item in pair]
            if datetime.fromisoformat(start) >= datetime.fromisoformat(end):
                raise AssessmentError("Invalid RoE time window ordering")
            windows.append([start, end])
        data[field] = windows
    patterns = [
        _text(pattern, "forbidden command pattern", 256)
        for pattern in _items(
            data.get("forbidden_command_patterns", []), "forbidden_command_patterns", 64
        )
    ]
    try:
        for pattern in patterns:
            re.compile(pattern)
    except re.error as exc:
        raise AssessmentError("Invalid forbidden-command regex") from exc
    data["forbidden_command_patterns"] = patterns
    target = urlsplit(asset)
    ports = ports or [target.port or (443 if target.scheme == "https" else 80)]
    denies = list(_items(data.get("out_of_scope", []), "out_of_scope", 128)) + list(
        _items(roe.get("out_of_scope", []), "out_of_scope", 128)
    )
    out_scope = _scope_entries(denies, asset, ports[0], deny=True)
    forbidden = _scope_entries(data.get("forbidden_destinations", []), asset, ports[0], deny=True)
    data.update(
        in_scope=[], out_of_scope=[], forbidden_destinations=[item.pattern for item in forbidden]
    )
    rules = replace(MachineEnforcement.from_dict(data), out_of_scope=out_scope)
    machine = roe["machine_enforcement"]
    for port in ports:
        allowed = _scope_entries(machine.get("in_scope", roe.get("in_scope", [])), asset, port)
        if not allowed:
            raise _ObservationStopped(
                "blocked", "SCOPE_REQUIRED", "Every observed port requires explicit RoE scope"
            )
        rules = replace(rules, in_scope=allowed)
        decision = evaluate_target(_host(target.hostname), rules)
        if not decision.allow:
            raise _ObservationStopped(
                "blocked", decision.reason_code, "The selected asset is refused by RoE"
            )
        if roe.get("in_scope"):
            human_allowed = _scope_entries(roe["in_scope"], asset, port)
            if (
                not human_allowed
                or not evaluate_target(
                    _host(target.hostname), replace(rules, in_scope=human_allowed)
                ).allow
            ):
                raise _ObservationStopped(
                    "blocked", "OUT_OF_SCOPE", "The selected asset is outside top-level RoE scope"
                )
    return rules


def _dig_query(raw: bytes, host: str, kind: str) -> dict[str, Any]:
    try:
        text = raw.decode("ascii")
    except UnicodeError as exc:
        raise AssessmentError("Invalid dig output encoding") from exc
    statuses = re.findall(r"->>HEADER<<- opcode: QUERY, status: ([A-Z]+),", text)
    flags = re.findall(r";; flags: ([^;]*); QUERY: 1, ANSWER: ([0-9]+),", text)
    questions = re.findall(r"^;([^;\s]+)\s+IN\s+(A|AAAA)\s*$", text, re.MULTILINE)
    if (
        len(statuses) != 1
        or len(flags) != 1
        or questions != [(host + ".", kind)]
        or ";; MSG SIZE  rcvd:" not in text
        and ";; MSG SIZE rcvd:" not in text
    ):
        raise AssessmentError("dig output is incomplete or mismatches the selected question")
    if "tc" in flags[0][0].split() or "qr" not in flags[0][0].split():
        raise AssessmentError("Truncated or non-response DNS output is forbidden")
    answers = []
    for line in text.splitlines():
        if not line.strip() or line.startswith(";"):
            continue
        parts = line.split()
        if len(parts) != 5 or parts[2] != "IN" or parts[3] != kind:
            raise AssessmentError("DNS aliases and unsupported records are not expanded")
        answers.append(
            {
                "name": _host(parts[0]),
                "type": kind,
                "value": _ip(parts[4]),
                "ttl": _xml_integer(parts[1], "ttl", 0, 2147483647),
            }
        )
    if len(answers) != int(flags[0][1]):
        raise AssessmentError("dig answer count is incomplete")
    return {"name": host, "type": kind, "status": statuses[0], "answers": answers}


class _Observation:
    def __init__(self, storage: WorkflowStorage, manifest: dict[str, Any]) -> None:
        self.storage, self.manifest = storage, manifest
        self.asset = manifest["selected_asset"]
        self.host = _host(urlsplit(self.asset).hostname)
        self.ports = manifest["parameters"].get("ports", [])
        self.deadline = time.monotonic() + 30
        self.last_action = 0.0
        try:
            self.state = AssessmentStore(storage.workspace).dispatch("report", {"limit": 1})
        except AssessmentError as exc:
            raise _ObservationStopped(
                "blocked",
                "ASSESSMENT_REQUIRED",
                "An initialized, intact AssessmentStore is required",
            ) from exc
        if _in_scope(self.host, self.state["denied_hosts"]) or not _in_scope(
            self.host, self.state["allowed_hosts"]
        ):
            raise _ObservationStopped(
                "blocked", "ASSESSMENT_SCOPE", "The selected asset is outside assessment scope"
            )
        try:
            self.roe, raw = storage.read("plan/roe.json", maximum=65536)
        except DefensiveWorkflowError as exc:
            raise _ObservationStopped(
                "blocked", "ENFORCEMENT_REQUIRED", "An explicit, safe plan/roe.json is required"
            ) from exc
        manifest["authorization"] = {"roe": self.roe, "assessment_revision": self.state["revision"]}
        self.save("roe.json", raw)
        try:
            self.rules = _machine(_json_object(raw), self.asset, self.ports)
        except AssessmentError as exc:
            raise _ObservationStopped(
                "blocked",
                "INVALID_ROE",
                "RoE is malformed or has unsupported enforcement constraints",
            ) from exc

    def save(self, name: str, raw: bytes) -> dict[str, Any]:
        reference = self.storage.write(self.manifest["run_nonce"], name, raw)
        self.manifest["evidence"].append(reference)
        return reference

    def check_ips(self, addresses: list[str]) -> None:
        for address in addresses:
            parsed = ipaddress.ip_address(address)
            variants = [address]
            if isinstance(parsed, ipaddress.IPv6Address) and parsed.ipv4_mapped is not None:
                variants.append(str(parsed.ipv4_mapped))
            for variant in variants:
                decision = evaluate_target(variant, replace(self.rules, in_scope=()))
                if (
                    not decision.allow
                    or _in_scope(variant, self.state["denied_hosts"])
                    or parsed.is_unspecified
                    or parsed.is_multicast
                ):
                    raise _ObservationStopped(
                        "blocked",
                        "RESOLVED_IP_DENIED",
                        "A resolved address is forbidden; no target connection was authorized",
                    )

    def guard(self, argv: list[str], duration: float, addresses: list[str]) -> None:
        if self.storage.abort_present():
            raise _ObservationStopped(
                "blocked", "EMERGENCY_ABORT", "The workspace .abort marker is present"
            )
        current, _ = self.storage.read("plan/roe.json", maximum=65536)
        if current != self.roe:
            raise _ObservationStopped("blocked", "ROE_CHANGED", "RoE changed during observation")
        try:
            state = AssessmentStore(self.storage.workspace).dispatch("report", {"limit": 1})
        except AssessmentError as exc:
            raise _ObservationStopped(
                "blocked", "ASSESSMENT_CHANGED", "Assessment authorization is no longer intact"
            ) from exc
        if any(
            state[field] != self.state[field]
            for field in ("engagement_name", "allowed_hosts", "denied_hosts")
        ):
            raise _ObservationStopped(
                "blocked", "ASSESSMENT_CHANGED", "Assessment authorization changed"
            )
        now = datetime.now(timezone.utc)
        end = now + timedelta(seconds=duration + 1)
        decision = evaluate_time_window(now, self.rules)
        if (
            not decision.allow
            or any(now < stop and end >= start for start, stop in self.rules.blackout_windows)
            or self.rules.authorized_windows
            and not any(
                start <= now and end < stop for start, stop in self.rules.authorized_windows
            )
        ):
            raise _ObservationStopped(
                "blocked",
                "TIME_WINDOW",
                "The complete bounded action must fit authorized non-blackout time",
            )
        logical_argv = [self.host if argument in addresses else argument for argument in argv]
        if any(
            not evaluate_command(shlex.join(command), self.rules).allow
            for command in (argv, logical_argv)
        ):
            raise _ObservationStopped(
                "blocked", "FORBIDDEN_COMMAND", "RoE forbids the fixed observation command"
            )
        if time.monotonic() >= self.deadline:
            raise _ObservationStopped(
                "inconclusive", "DEADLINE", "Workflow observation deadline exhausted"
            )
        self.check_ips(addresses)

    def command(
        self, argv: list[str], tag: str, duration: float = 4, addresses: list[str] | None = None
    ) -> bytes:
        addresses = addresses or []
        minimum_delay = max(
            self.rules.min_inter_request_delay_ms / 1000, 1.0 if argv[0] == "nmap" else 0.0
        )
        delay = minimum_delay - (time.monotonic() - self.last_action)
        if delay > 0:
            time.sleep(delay)
        duration = min(duration, self.deadline - time.monotonic())
        self.guard(argv, duration, addresses)
        duration = min(duration, self.deadline - time.monotonic())
        if duration <= 0:
            raise _ObservationStopped(
                "inconclusive", "DEADLINE", "Observation deadline exhausted before execution"
            )
        started = _now()
        self.manifest["tool"] = {"name": argv[0], "version": "unknown"}
        result = run_bounded(
            argv, cwd=self.storage.workspace, timeout=duration, max_output_bytes=LIMIT
        )
        self.last_action = time.monotonic()
        stdout = self.save(tag + ".stdout", result.stdout)
        stderr = self.save(tag + ".stderr", result.stderr)
        process = {"status": result.status, "exit_code": result.exit_code}
        self.manifest["process"] = process
        self.manifest.setdefault("processes", []).append(
            process
            | {
                "argv": argv,
                "started_at": started,
                "finished_at": _now(),
                "stdout": stdout,
                "stderr": stderr,
            }
        )
        self.guard(argv, 0, addresses)
        if result.status != "completed" or result.exit_code != 0:
            raise _ObservationStopped(
                "unavailable" if result.status == "unavailable" else "inconclusive",
                "COMMAND_" + (result.status.upper() if result.status != "completed" else "EXIT"),
                "The fixed command did not complete successfully; no weaker fallback was attempted",
            )
        return result.stdout

    def resolve(self) -> tuple[list[str], bytes | None]:
        try:
            literal = str(ipaddress.ip_address(self.host))
        except ValueError:
            literal = None
        if literal is not None:
            if self.manifest["workflow_id"] == "dns-inventory":
                raise _ObservationStopped(
                    "blocked",
                    "DNS_NAME_REQUIRED",
                    "DNS inventory requires an exact DNS name, not reverse discovery",
                )
            addresses, raw = [literal], None
        else:
            queries = []
            for kind in ("A", "AAAA"):
                argv = [
                    "dig",
                    "-r",
                    "-q",
                    self.host + ".",
                    "-t",
                    kind,
                    "+time=2",
                    "+tries=1",
                    "+nosearch",
                    "+ignore",
                    "+noall",
                    "+comments",
                    "+question",
                    "+answer",
                    "+stats",
                ]
                queries.append(
                    _dig_query(self.command(argv, "dns-" + kind.lower()), self.host, kind)
                )
            raw = _dump(
                {
                    "schema_version": 1,
                    "kind": "dns-observation",
                    "asset": self.asset,
                    "observed_at": _now(),
                    "queries": queries,
                    "tool": {"name": "dig", "version": "unknown"},
                }
            ).encode()
            self.manifest["resolution_artifact"] = self.save("dns.json", raw)
            if self.manifest["workflow_id"] == "dns-inventory":
                self.manifest["artifact"] = self.manifest["resolution_artifact"]
            result = _dns(raw, self.asset)
            self.manifest["query_statuses"] = result["query_statuses"]
            addresses = sorted(
                {item["value"] for item in result["observations"]},
                key=lambda value: (
                    ipaddress.ip_address(value).version,
                    int(ipaddress.ip_address(value)),
                ),
            )
            if result["status"] != "observed" or not addresses:
                raise _ObservationStopped(
                    "inconclusive",
                    "NO_USABLE_DNS",
                    "No complete usable A/AAAA observation; no target connection attempted",
                )
        if len(addresses) > 16:
            raise _ObservationStopped(
                "blocked", "ADDRESS_LIMIT", "Resolved address set exceeds the fixed bound"
            )
        self.check_ips(addresses)
        self.manifest["resolved_ips"] = addresses
        return addresses, raw

    def target_argv(self, peer: str, port: int | None = None) -> list[str]:
        if self.manifest["workflow_id"] == "network-inventory":
            argv = [
                "nmap",
                "-sT",
                "-Pn",
                "-n",
                "--unprivileged",
                "--disable-arp-ping",
                "--no-stylesheet",
                "--max-retries",
                "0",
                "--max-rate",
                "1",
                "--host-timeout",
                "18s",
                "-p",
                str(port if port is not None else self.ports[0]),
                "-oX",
                "-",
            ]
            return argv + (["-6", peer] if ":" in peer else [peer])
        return [
            "python",
            "ssl",
            "--verify",
            self.host,
            "--connect",
            peer,
            str(urlsplit(self.asset).port or 443),
        ]

    def inspect_network(self, addresses: list[str]) -> dict[str, Any]:
        observations = []
        tool = None
        complete = True
        self.manifest["artifacts"] = []
        for port in self.ports:
            raw = self.command(
                self.target_argv(addresses[0], port), f"network-{port}", 20, addresses
            )
            reference = self.save(f"nmap-{port}.xml", raw)
            self.manifest["artifacts"].append(reference)
            if self.manifest["artifact"] is None:
                self.manifest["artifact"] = reference
            result = _network(raw, self.asset, addresses[0])
            if any(
                item["protocol"] != "tcp" or item["port"] != port for item in result["observations"]
            ):
                raise AssessmentError("Nmap returned observations outside the selected TCP port")
            if tool is not None and tool != result["tool"]:
                raise AssessmentError("Nmap tool identity changed between port observations")
            tool = result["tool"]
            observations.extend(result["observations"])
            complete = complete and result["status"] == "observed"
        missing = sorted(set(self.ports) - {item["port"] for item in observations})
        return {
            "status": "observed" if complete and observations and not missing else "inconclusive",
            "observations": observations,
            "tool": tool,
            "unobserved_ports": missing,
        }

    def inspect_tls(self, addresses: list[str]) -> dict[str, Any]:
        peer = addresses[0]
        port = urlsplit(self.asset).port or 443
        argv = self.target_argv(peer)
        delay = self.rules.min_inter_request_delay_ms / 1000 - (time.monotonic() - self.last_action)
        if delay > 0:
            time.sleep(delay)
        self.guard(argv, 8, addresses)
        deadline = min(self.deadline, time.monotonic() + 8)
        value: dict[str, Any] = {
            "schema_version": 1,
            "kind": "tls-observation",
            "asset": self.asset,
            "peer_ip": peer,
            "port": port,
            "server_name": self.host,
            "handshake": "failed",
            "certificate_validation": "unknown",
            "protocol": "unknown",
            "cipher": "unknown",
            "certificate_sha256": None,
            "not_before": None,
            "not_after": None,
            "tool": {"name": "python-ssl", "version": ssl.OPENSSL_VERSION},
        }
        self.manifest["tool"] = value["tool"]
        process: dict[str, Any] = {"status": "error", "exit_code": None}
        error = None
        stopped: _ObservationStopped | None = None
        started = _now()
        try:
            context = ssl.create_default_context()
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            context.check_hostname = True
            context.verify_mode = ssl.CERT_REQUIRED
            with closing(
                socket.socket(
                    socket.AF_INET6 if ":" in peer else socket.AF_INET, socket.SOCK_STREAM
                )
            ) as transport:
                self.guard(argv, max(0, deadline - time.monotonic()), addresses)
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("TLS deadline exhausted")
                transport.settimeout(min(4.0, remaining))
                transport.connect((peer, port))
                self.guard(argv, max(0, deadline - time.monotonic()), addresses)
                if _ip(transport.getpeername()[0]) != peer:
                    raise _ObservationStopped(
                        "blocked",
                        "PEER_MISMATCH",
                        "TLS peer differs from the authorized pinned address",
                    )
                with context.wrap_socket(
                    transport, server_hostname=self.host, do_handshake_on_connect=False
                ) as secured:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise TimeoutError("TLS deadline exhausted")
                    secured.settimeout(min(4.0, remaining))
                    secured.do_handshake()
                    if _ip(secured.getpeername()[0]) != peer:
                        raise _ObservationStopped(
                            "blocked",
                            "PEER_MISMATCH",
                            "TLS peer differs from the authorized pinned address",
                        )
                    certificate = secured.getpeercert(binary_form=True)
                    if not certificate or len(certificate) > 65536:
                        raise AssessmentError(
                            "TLS certificate metadata exceeds the fixed bound or is absent"
                        )
                    details = secured.getpeercert() or {}
                    cipher = secured.cipher()
                    value.update(
                        handshake="completed",
                        certificate_validation="valid",
                        certificate_sha256=_sha(certificate),
                        protocol=secured.version() or "unknown",
                        cipher=cipher[0] if cipher else "unknown",
                    )
                    for source, field in (("notBefore", "not_before"), ("notAfter", "not_after")):
                        if source in details:
                            value[field] = datetime.fromtimestamp(
                                ssl.cert_time_to_seconds(str(details[source])), timezone.utc
                            ).isoformat()
                    process["status"] = "completed"
        except _ObservationStopped as exc:
            stopped = exc
        except ssl.SSLCertVerificationError:
            value["certificate_validation"] = "invalid"
            error = {
                "code": "TLS_CERTIFICATE_INVALID",
                "message": "Certificate validation failed; no unverified retry was attempted",
            }
        except (ValueError, OverflowError):
            value.update(
                handshake="failed",
                certificate_validation="unknown",
                certificate_sha256=None,
                not_before=None,
                not_after=None,
            )
            error = {
                "code": "TLS_METADATA_INVALID",
                "message": "TLS metadata is invalid; certificate assurance is unavailable",
            }
        except (TimeoutError, OSError) as exc:
            process["status"] = "timeout" if isinstance(exc, TimeoutError) else "error"
            error = {
                "code": "TLS_HANDSHAKE_UNAVAILABLE",
                "message": "The bounded verified TLS handshake did not complete",
            }
        self.manifest["process"] = process
        self.manifest.setdefault("processes", []).append(
            process | {"transport": "python-ssl", "started_at": started, "finished_at": _now()}
        )
        value["observed_at"] = _now()
        raw = _dump(value).encode()
        self.manifest["artifact"] = self.save("tls.json", raw)
        if stopped is not None:
            raise stopped
        self.guard(argv, 0, addresses)
        result = _tls(raw, self.asset)
        return result | ({"error": error} if error is not None else {})

    def run(self) -> dict[str, Any]:
        if self.manifest["workflow_id"] == "network-inventory":
            for port in self.ports:
                self.guard(self.target_argv(self.host, port), 20, [])
        elif self.manifest["workflow_id"] == "tls-inspection":
            self.guard(self.target_argv(self.host), 8, [])
        addresses, raw = self.resolve()
        if self.manifest["workflow_id"] == "dns-inventory" and raw is not None:
            return _dns(raw, self.asset)
        self.manifest["pinned_ip"] = addresses[0]
        if self.manifest["workflow_id"] == "network-inventory":
            return self.inspect_network(addresses)
        return self.inspect_tls(addresses)


def _parameters(workflow_id: str, payload: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(workflow_id, str) or workflow_id not in _WORKFLOWS:
        raise WorkflowInputError("Unknown defensive workflow_id")
    if not isinstance(payload, dict):
        raise WorkflowInputError("Workflow payload must be an object")
    allowed = {"url", "artifact_path", "observe"}
    allowed.update(
        {"method"}
        if workflow_id == "http-capture-review"
        else {"ports"}
        if workflow_id == "network-inventory"
        else set()
    )
    if set(payload) - allowed:
        raise WorkflowInputError("Unknown workflow parameters")
    try:
        observe = _boolean(payload.get("observe", False), "observe")
        asset = _url(payload.get("url"))
        parameters: dict[str, Any] = {"url": asset, "observe": observe}
        if workflow_id == "http-capture-review":
            parameters["method"] = _method(payload.get("method", "GET"))
        if observe:
            if (
                workflow_id not in {"network-inventory", "dns-inventory", "tls-inspection"}
                or "artifact_path" in payload
            ):
                raise WorkflowInputError("Observation and supplied artifacts are separate modes")
            target = urlsplit(asset)
            if target.path != "/" or target.query or "?" in payload["url"] or "#" in payload["url"]:
                raise WorkflowInputError(
                    "Host observation requires an exact origin URL without path, query, or fragment"
                )
            if workflow_id == "tls-inspection" and target.scheme != "https":
                raise WorkflowInputError("TLS observation requires HTTPS")
            if workflow_id == "network-inventory":
                ports = [
                    _integer(port, "port", 1, 65535)
                    for port in _items(payload.get("ports"), "ports", 16)
                ]
                if not ports or len(set(ports)) != len(ports):
                    raise WorkflowInputError(
                        "Network observation requires 1 to 16 unique explicit ports"
                    )
                parameters["ports"] = sorted(ports)
        elif "ports" in payload:
            raise WorkflowInputError("ports is only accepted for explicit network observation")
        return parameters
    except AssessmentError as exc:
        raise WorkflowInputError(str(exc)) from exc


class DefensiveWorkflowRunner:
    def __init__(self, workspace: str | Path) -> None:
        self._storage = WorkflowStorage(workspace)
        self.workspace = self._storage.workspace

    def run(self, workflow_id: str, payload: dict[str, Any]) -> dict[str, Any]:
        parameters = _parameters(workflow_id, payload)
        observe, asset = parameters["observe"], parameters["url"]
        source, raw = (None, b"") if observe else self._storage.read(payload.get("artifact_path"))
        nonce = self._storage.new_run()
        manifest = NON_ASSURANCE | {
            "schema_version": 1,
            "run_nonce": nonce,
            "workflow_id": workflow_id,
            "workflow_version": _VERSION,
            "engine": {"name": "defensive-workflows", "version": _VERSION},
            "selected_asset": asset,
            "parameters": parameters,
            "mode": "observation" if observe else "supplied_artifact",
            "started_at": _now(),
            "source_artifact": source,
            "artifact": None,
            "evidence": [],
            "observations": [],
            "tool": {"name": "unknown", "version": "unknown"},
            "process": {"status": "not_run", "exit_code": None},
            "limitations": list(_LIMITATIONS),
        }
        try:
            if observe:
                result = self._observe(manifest)
            else:
                name = "input.xml" if workflow_id == "network-inventory" else "input.json"
                manifest["artifact"] = self._storage.write(nonce, name, raw)
                manifest["evidence"].append(manifest["artifact"])
                if workflow_id == "network-inventory":
                    result = _network(raw, asset)
                elif workflow_id == "dns-inventory":
                    result = _dns(raw, asset)
                elif workflow_id == "tls-inspection":
                    result = _tls(raw, asset)
                elif workflow_id == "sarif-review":
                    result = _sarif(raw, asset)
                else:
                    result = _capture(raw, asset, parameters["method"])
            manifest.update(result)
        except _ObservationStopped as exc:
            manifest.update(status=exc.status, error={"code": exc.code, "message": str(exc)})
        except AssessmentError as exc:
            manifest.update(
                status="inconclusive" if observe else "rejected",
                error={
                    "code": "INVALID_OBSERVATION" if observe else "INVALID_ARTIFACT",
                    "message": str(exc),
                },
            )
        manifest["finished_at"] = _now()
        return self.report(self._storage.finish(manifest))

    def _observe(self, manifest: dict[str, Any]) -> dict[str, Any]:
        try:
            with self._storage.observation_lock():
                return _Observation(self._storage, manifest).run()
        except WorkflowStorageError as exc:
            raise _ObservationStopped(
                "blocked",
                "OBSERVATION_STORAGE",
                "Safe exclusive observation storage is unavailable",
            ) from exc

    def report(self, run_id: str) -> dict[str, Any]:
        return self._storage.report(run_id)
