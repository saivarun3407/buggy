"""Tests for the proof-verification gate (reporting/proof_gate.py)
and the gated ``report_record_finding`` recording tool.

No real network / proxy / Neo4j. The proxy double, :class:`FakeCaido`, is the
REAL :class:`CaidoClient` with only ``subprocess.run`` scripted: every
``CaidoError`` message and every ``{"raw": ...}`` wrap the gate sees is produced
by the real ``CaidoClient._run``, so the tests cannot drift from the real
contract (a missing id is a non-zero CLI exit, not a convenient ``{}``). KG
persistence is patched to a soft no-op.

Covers the gate matrix:
  (a) full proof + confirmed ids              -> accepted, live_verified
  (b) missing poc_script_code / evidence      -> rejected, specific errors
  (c) id the proxy reports absent             -> rejected (non-zero exit,
      exit-0 raw "not found", empty stdout, wrong-id payload)
  (d) transport failure (CLI missing, timeout,
      connection refused)                     -> kept WITH warning, NOT rejected
  (e) ambiguous CLI failure                   -> rejected (fail closed)
  (f) strict mode with zero cited ids         -> rejected
  (g) analysis-only (non-strict), zero ids    -> accepted, NOT live_verified
"""

from __future__ import annotations

import asyncio
import json
import subprocess
from unittest.mock import patch

import pytest

from buggy.tools.proxy.tools import CaidoClient, CaidoConfig, CaidoError
from buggy.tools.reporting.proof_gate import (
    LIVE_EVIDENCE_REQUIRED_ERROR,
    REQUIRED_PROOF_ERRORS,
    GateResult,
    _Probe,
    _probe_exchange_id,
    normalize_http_exchange_ids,
    proof_gate_strict,
    required_proof_errors,
    verify_finding,
    verify_http_exchange_ids,
)

# ── Proxy double: the real CaidoClient over a scripted CLI ─────────────

#: Per-id CLI behaviours. Each maps to what ``caido requests view <id> --json``
#: does; the real ``CaidoClient._run`` turns that into a payload or CaidoError.
EXISTS = "exists"  # exit 0, JSON request record for the id
NOTFOUND_EXIT = "notfound_exit"  # exit 1, stderr "request <id> not found"
NOTFOUND_RAW = "notfound_raw"  # exit 0, plain-text "Request not found" stdout
EMPTY = "empty"  # exit 0, empty stdout
WRONG_ID = "wrong_id"  # exit 0, JSON record for a different id
ERROR_JSON = "error_json"  # exit 0, JSON {"error": "..."}
RAW_OTHER = "raw_other"  # exit 0, unrecognised plain text
CONN_REFUSED = "conn_refused"  # exit 1, stderr ECONNREFUSED (proxy daemon down)
CLI_MISSING = "cli_missing"  # binary not on PATH -> FileNotFoundError
TIMEOUT = "timeout"  # subprocess.TimeoutExpired
AUTH_ERROR = "auth_error"  # exit 2, stderr "unauthorized" (not transport)


class FakeCaido(CaidoClient):
    """The real :class:`CaidoClient`, with ``subprocess.run`` scripted per id.

    ``existing`` ids answer like a captured request; ``unreachable`` ids hit a
    transport failure (``transport`` behaviour); every other id answers with
    ``missing`` (default: the real CLI's non-zero "not found" exit).
    ``behaviours`` overrides any single id.
    """

    def __init__(
        self,
        existing: set[str] | None = None,
        unreachable: set[str] | None = None,
        *,
        missing: str = NOTFOUND_EXIT,
        transport: str = CONN_REFUSED,
        behaviours: dict[str, str] | None = None,
    ) -> None:
        super().__init__(CaidoConfig(cli="caido", timeout_seconds=5))
        self.existing = existing or set()
        self.unreachable = unreachable or set()
        self.missing = missing
        self.transport = transport
        self.behaviours = behaviours or {}
        self.calls: list[str] = []
        self.argv: list[list[str]] = []

    def _behaviour(self, request_id: str) -> str:
        if request_id in self.behaviours:
            return self.behaviours[request_id]
        if request_id in self.unreachable:
            return self.transport
        if request_id in self.existing:
            return EXISTS
        return self.missing

    def view_request(self, request_id: str) -> dict[str, object]:
        self.calls.append(request_id)
        with patch("buggy.tools.proxy.tools.subprocess.run", self._fake_subprocess_run):
            return super().view_request(request_id)  # real _run

    def _fake_subprocess_run(
        self, argv: list[str], **kwargs: object
    ) -> subprocess.CompletedProcess[str]:
        self.argv.append(list(argv))
        request_id = argv[3]  # caido requests view <id> --json
        kind = self._behaviour(request_id)

        def done(rc: int, out: str = "", err: str = "") -> subprocess.CompletedProcess[str]:
            return subprocess.CompletedProcess(argv, rc, stdout=out, stderr=err)

        if kind == EXISTS:
            body = {"id": request_id, "method": "GET", "host": "t", "path": "/x"}
            return done(0, json.dumps(body))
        if kind == NOTFOUND_EXIT:
            return done(1, err=f"Error: request {request_id} not found")
        if kind == NOTFOUND_RAW:
            return done(0, out="Request not found")
        if kind == EMPTY:
            return done(0)
        if kind == WRONG_ID:
            return done(0, json.dumps({"id": "1", "method": "GET"}))
        if kind == ERROR_JSON:
            return done(0, json.dumps({"error": "no such request"}))
        if kind == RAW_OTHER:
            return done(0, out="OK")
        if kind == CONN_REFUSED:
            return done(1, err="Error: connect ECONNREFUSED 127.0.0.1:8080")
        if kind == CLI_MISSING:
            raise FileNotFoundError(2, "No such file or directory", "caido")
        if kind == TIMEOUT:
            raise subprocess.TimeoutExpired(argv, kwargs.get("timeout", 5))
        if kind == AUTH_ERROR:
            return done(2, err="Error: unauthorized - invalid API token")
        raise AssertionError(f"unknown behaviour {kind!r}")


def _full_finding(**over: object) -> dict[str, object]:
    base: dict[str, object] = {
        "title": "Reflected XSS in /search",
        "severity": "high",
        "poc_script_code": "GET /search?q=<script>alert(1)</script>",
        "poc_description": "1. Open the crafted URL. 2. Observe script executes.",
        "evidence": "Response echoes the payload verbatim in the HTML body.",
        "http_exchange_ids": ["101", "102"],
    }
    base.update(over)
    return base


# ── (a) full proof + existing ids -> accepted ──────────────────────────


def test_accept_full_proof_and_existing_ids() -> None:
    client = FakeCaido(existing={"101", "102"})
    result = verify_finding(_full_finding(), client=client, strict=True)
    assert result.accepted is True
    assert result.errors == []
    assert result.warning is None
    assert result.evidence_unverified is False
    assert result.live_verified is True
    assert result.http_exchange_ids == ["101", "102"]


# ── (b) missing required proof -> rejected with specific errors ─────────


def test_reject_missing_poc_script_code() -> None:
    finding = _full_finding(poc_script_code="")
    client = FakeCaido(existing={"101", "102"})
    result = verify_finding(finding, client=client, strict=True)
    assert result.accepted is False
    assert any("PoC script/code is REQUIRED" in e for e in result.errors)


def test_reject_missing_evidence() -> None:
    finding = _full_finding(evidence="   ")  # whitespace-only is still empty
    client = FakeCaido(existing={"101", "102"})
    result = verify_finding(finding, client=client, strict=True)
    assert result.accepted is False
    assert any("Evidence cannot be empty" in e for e in result.errors)


def test_reject_lists_every_missing_proof_field() -> None:
    # No cited ids: the three missing proof fields AND the missing live evidence.
    finding = _full_finding(
        poc_script_code="", poc_description="", evidence="", http_exchange_ids=None
    )
    result = verify_finding(finding, client=FakeCaido(), strict=True)
    assert result.accepted is False
    assert len(result.errors) == 4
    assert set(result.errors) == {
        *REQUIRED_PROOF_ERRORS.values(),
        LIVE_EVIDENCE_REQUIRED_ERROR,
    }


# ── (c) reachable proxy reports id absent -> rejected ──────────────────


def test_reject_when_reachable_proxy_lacks_cited_id() -> None:
    # 101 exists; 999 does not: the real CLI exits 1 "request 999 not found".
    finding = _full_finding(http_exchange_ids=["101", "999"])
    client = FakeCaido(existing={"101"})
    result = verify_finding(finding, client=client, strict=True)
    assert result.accepted is False
    assert any("do not exist in the current proxy capture" in e for e in result.errors)
    assert any("999" in e for e in result.errors)


# ── (d) unreachable proxy -> kept WITH warning, NOT rejected ───────────


def test_unreachable_proxy_keeps_ids_with_warning() -> None:
    finding = _full_finding(http_exchange_ids=["101", "102"])
    # 101: connection error on probe; 102 confirmed. No id is rejected, so
    # the transport failure keeps both with a warning.
    client = FakeCaido(existing={"102"}, unreachable={"101"})
    result = verify_finding(finding, client=client, strict=True)
    assert result.accepted is True  # fail-open: a real finding is never deleted
    assert result.warning is not None
    assert result.evidence_unverified is True
    assert result.http_exchange_ids == ["101", "102"]  # ids kept, not stripped
    assert result.live_verified is False


def test_missing_verdict_wins_over_unreachable_probe() -> None:
    # 888 is positively reported absent; 101 hits a transport failure. The
    # positive "not found" answer is authoritative — one flaky probe must not
    # launder a fabricated id through the fail-open path.
    finding = _full_finding(http_exchange_ids=["101", "888"])
    client = FakeCaido(existing=set(), unreachable={"101"})
    result = verify_finding(finding, client=client, strict=True)
    assert result.accepted is False
    assert any("888" in e and "do not exist" in e for e in result.errors)


def test_no_client_is_fail_open() -> None:
    finding = _full_finding(http_exchange_ids=["101"])
    result = verify_finding(finding, client=None, strict=True)
    assert result.accepted is True
    assert result.evidence_unverified is True
    assert result.live_verified is False


# ── (e) analysis-only / non-strict -> proof-optional path ──────────────


def test_analysis_only_allows_missing_poc() -> None:
    finding = {
        "title": "SQLi via static trace in db/queries.py",
        "severity": "medium",
        # no poc_script_code / poc_description / evidence
    }
    result = verify_finding(finding, client=FakeCaido(), strict=False)
    assert result.accepted is True
    assert result.errors == []
    assert result.live_verified is False  # source-only: never live-proven


def test_non_strict_still_verifies_cited_ids() -> None:
    # Proof optional, but a cited id a reachable proxy lacks is still rejected.
    finding = {"title": "x", "http_exchange_ids": ["404"]}
    client = FakeCaido(existing=set())
    result = verify_finding(finding, client=client, strict=False)
    assert result.accepted is False
    assert any("do not exist" in e for e in result.errors)


# ── required_proof_errors unit ─────────────────────────────────────────


def test_required_proof_errors_strict_vs_relaxed() -> None:
    empty: dict[str, object] = {}
    assert len(required_proof_errors(empty, strict=True)) == 3
    assert required_proof_errors(empty, strict=False) == []


# ── normalize_http_exchange_ids unit ───────────────────────────────────


def test_normalize_none_and_empty() -> None:
    assert normalize_http_exchange_ids(None) == (None, [])
    assert normalize_http_exchange_ids([]) == ([], [])


def test_normalize_dedupes_preserving_order() -> None:
    ids, errors = normalize_http_exchange_ids(["3", "1", "3", "2"])
    assert ids == ["3", "1", "2"]
    assert errors == []


def test_normalize_rejects_non_numeric_and_non_list() -> None:
    _, errors = normalize_http_exchange_ids(["abc"])
    assert any("numeric proxy request id" in e for e in errors)
    ids, errors2 = normalize_http_exchange_ids("101")
    assert ids is None
    assert any("must be a list" in e for e in errors2)


def test_normalize_caps_distinct_ids() -> None:
    _, errors = normalize_http_exchange_ids([str(i) for i in range(20)])
    assert any("at most" in e for e in errors)


# ── verify_http_exchange_ids direct ────────────────────────────────────


def test_verify_ids_all_present() -> None:
    client = FakeCaido(existing={"1", "2"})
    ids, errors, warning = verify_http_exchange_ids(client, ["1", "2"])
    assert ids == ["1", "2"]
    assert errors == []
    assert warning is None


def test_verify_ids_empty_list_no_probe() -> None:
    client = FakeCaido()
    ids, errors, warning = verify_http_exchange_ids(client, [])
    assert ids == []
    assert errors == []
    assert warning is None
    assert client.calls == []  # nothing to verify, proxy not touched


# ── cvss_vector validation (reuses spine cvss.py) ──────────────────────


def test_invalid_cvss_vector_rejected() -> None:
    finding = _full_finding(cvss_vector="CVSS:3.1/AV:Z/AC:L")
    client = FakeCaido(existing={"101", "102"})
    result = verify_finding(finding, client=client, strict=True)
    assert result.accepted is False
    assert any("cvss_vector is invalid" in e for e in result.errors)


def test_valid_cvss_vector_accepted() -> None:
    finding = _full_finding(cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N")
    client = FakeCaido(existing={"101", "102"})
    result = verify_finding(finding, client=client, strict=True)
    assert result.accepted is True


# ── proof_gate_strict env flag ─────────────────────────────────────────


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (None, True),
        ("1", True),
        ("true", True),
        ("0", False),
        ("false", False),
        ("off", False),
        ("", True),
    ],
)
def test_proof_gate_strict_env(value: str | None, expected: bool) -> None:
    env = {} if value is None else {"BUGGY_PROOF_GATE_STRICT": value}
    with patch.dict("os.environ", env, clear=False):
        if value is None:
            import os

            os.environ.pop("BUGGY_PROOF_GATE_STRICT", None)
        assert proof_gate_strict() is expected


# ── Tool-level: report_record_finding ──────────────────────────────────


def _run_record(**kwargs: object) -> dict[str, object]:
    from buggy.tools.reporting.tools import report_record_finding

    with (
        patch(
            "buggy.tools.reporting.tools.publish_finding_node",
            return_value=("node123", True),
        ),
        patch(
            "buggy.tools.reporting.tools.get_active_engagement",
            return_value="eng-1",
        ),
    ):
        raw = asyncio.run(report_record_finding.ainvoke(kwargs))
    return json.loads(raw)


def test_tool_accepts_full_finding() -> None:
    client = FakeCaido(existing={"101"})
    with (
        patch("buggy.tools.reporting.tools._new_caido_client", return_value=client),
        patch.dict("os.environ", {"BUGGY_PROOF_GATE_STRICT": "1"}, clear=False),
    ):
        payload = _run_record(
            title="XSS",
            severity="high",
            poc_script_code="payload",
            poc_description="steps",
            evidence="echoed back",
            http_exchange_ids=["101"],
        )
    assert payload["success"] is True
    assert payload["report_id"] == "node123"
    assert payload["persisted"] is True
    assert payload["evidence_unverified"] is False
    assert payload["live_verified"] is True


def test_tool_rejects_fabricated_evidence() -> None:
    # Cites an id a reachable proxy does not hold -> rejected, nothing persisted.
    client = FakeCaido(existing=set())
    with (
        patch("buggy.tools.reporting.tools._new_caido_client", return_value=client),
        patch("buggy.tools.reporting.tools.publish_finding_node") as persist,
        patch.dict("os.environ", {"BUGGY_PROOF_GATE_STRICT": "1"}, clear=False),
    ):
        from buggy.tools.reporting.tools import report_record_finding

        raw = asyncio.run(
            report_record_finding.ainvoke(
                {
                    "title": "fake",
                    "poc_script_code": "p",
                    "poc_description": "d",
                    "evidence": "e",
                    "http_exchange_ids": ["777"],
                }
            )
        )
        payload = json.loads(raw)
    assert payload["success"] is False
    assert "Validation failed" == payload["error"]
    persist.assert_not_called()  # a rejected finding never reaches the KG


def test_tool_unreachable_proxy_persists_with_warning() -> None:
    client = FakeCaido(unreachable={"101"})
    with (
        patch("buggy.tools.reporting.tools._new_caido_client", return_value=client),
        patch(
            "buggy.tools.reporting.tools.publish_finding_node",
            return_value=("node9", True),
        ),
        patch(
            "buggy.tools.reporting.tools.get_active_engagement",
            return_value="eng-1",
        ),
        patch.dict("os.environ", {"BUGGY_PROOF_GATE_STRICT": "1"}, clear=False),
    ):
        from buggy.tools.reporting.tools import report_record_finding

        raw = asyncio.run(
            report_record_finding.ainvoke(
                {
                    "title": "real",
                    "poc_script_code": "p",
                    "poc_description": "d",
                    "evidence": "e",
                    "http_exchange_ids": ["101"],
                }
            )
        )
        payload = json.loads(raw)
    assert payload["success"] is True
    assert payload["evidence_unverified"] is True
    assert payload["live_verified"] is False
    assert "warning" in payload


def test_tool_analysis_only_requires_nonstrict_env() -> None:
    from buggy.tools.reporting.tools import report_record_finding

    # strict env: analysis_only is ignored, proof still required -> rejected.
    with (
        patch("buggy.tools.reporting.tools._new_caido_client", return_value=FakeCaido()),
        patch.dict("os.environ", {"BUGGY_PROOF_GATE_STRICT": "1"}, clear=False),
    ):
        raw = asyncio.run(report_record_finding.ainvoke({"title": "static", "analysis_only": True}))
        assert json.loads(raw)["success"] is False

    # non-strict env: analysis_only unlocks the proof-optional path -> accepted.
    with (
        patch("buggy.tools.reporting.tools._new_caido_client", return_value=FakeCaido()),
        patch(
            "buggy.tools.reporting.tools.publish_finding_node",
            return_value=("n", False),
        ),
        patch("buggy.tools.reporting.tools.get_active_engagement", return_value="e"),
        patch.dict("os.environ", {"BUGGY_PROOF_GATE_STRICT": "0"}, clear=False),
    ):
        raw = asyncio.run(report_record_finding.ainvoke({"title": "static", "analysis_only": True}))
        payload = json.loads(raw)
        assert payload["success"] is True
        assert payload["persisted"] is False
        assert payload["live_verified"] is False


def test_gate_result_shape() -> None:
    r = GateResult(accepted=True)
    assert r.errors == []
    assert r.warning is None


# ── FakeCaido fidelity: outcomes come from the real CaidoClient._run ────


def test_fake_caido_runs_the_real_client_contract() -> None:
    client = FakeCaido(
        existing={"101"},
        behaviours={"202": NOTFOUND_RAW, "303": CLI_MISSING, "404": TIMEOUT},
    )
    assert isinstance(client, CaidoClient)
    # Missing id: the real _run raises on the non-zero exit, never returns {}.
    with pytest.raises(CaidoError, match=r"^Caido CLI exited 1: Error: request 999 not found$"):
        client.view_request("999")
    # Exit-0 plain text: the real _run wraps it as {"raw": ...}.
    assert client.view_request("202") == {"raw": "Request not found"}
    # Transport failures: the real _run's own messages.
    with pytest.raises(CaidoError, match=r"^Caido CLI not found: caido$"):
        client.view_request("303")
    with pytest.raises(CaidoError, match=r"^Caido CLI timed out after 5s"):
        client.view_request("404")
    assert client.view_request("101")["id"] == "101"
    assert client.argv[0] == ["caido", "requests", "view", "999", "--json"]


# ── (R-a) audit #1: reachable proxy, non-zero-exit not-found -> REJECT ──


def test_regression_1_nonzero_exit_not_found_is_missing_not_unreachable() -> None:
    client = FakeCaido(existing=set())  # default missing = non-zero "not found" exit
    assert _probe_exchange_id(client, "777") is _Probe.MISSING
    result = verify_finding(_full_finding(http_exchange_ids=["777"]), client=client, strict=True)
    assert result.accepted is False
    assert result.warning is None
    assert any("do not exist" in e and "777" in e for e in result.errors)


def test_regression_1_tool_does_not_publish_fabricated_id() -> None:
    from buggy.tools.reporting.tools import report_record_finding

    client = FakeCaido(existing=set(), missing=NOTFOUND_EXIT)
    with (
        patch("buggy.tools.reporting.tools._new_caido_client", return_value=client),
        patch("buggy.tools.reporting.tools.publish_finding_node") as persist,
        patch.dict("os.environ", {"BUGGY_PROOF_GATE_STRICT": "1"}, clear=False),
    ):
        raw = asyncio.run(
            report_record_finding.ainvoke(
                {
                    "title": "fabricated",
                    "poc_script_code": "p",
                    "poc_description": "d",
                    "evidence": "e",
                    "http_exchange_ids": ["777"],
                }
            )
        )
    payload = json.loads(raw)
    assert payload["success"] is False
    assert any("777" in e for e in payload["errors"])
    persist.assert_not_called()


# ── (R-b) audit #2: exit-0 non-confirming payloads -> REJECT ────────────


@pytest.mark.parametrize(
    ("behaviour", "probe"),
    [
        (NOTFOUND_RAW, _Probe.MISSING),  # {"raw": "Request not found"}
        (EMPTY, _Probe.MISSING),  # {}
        (ERROR_JSON, _Probe.MISSING),  # {"error": "no such request"}
        (WRONG_ID, _Probe.UNVERIFIABLE),  # record for a different id
        (RAW_OTHER, _Probe.UNVERIFIABLE),  # {"raw": "OK"}
    ],
)
def test_regression_2_exit0_non_confirming_payload_rejects(behaviour: str, probe: _Probe) -> None:
    client = FakeCaido(behaviours={"555": behaviour})
    assert _probe_exchange_id(client, "555") is probe
    result = verify_finding(_full_finding(http_exchange_ids=["555"]), client=client, strict=True)
    assert result.accepted is False
    assert result.warning is None
    assert any("555" in e for e in result.errors)


# ── (R-c) genuine transport failure -> fail-open keep + warn ────────────


@pytest.mark.parametrize("transport", [CLI_MISSING, TIMEOUT, CONN_REFUSED])
def test_transport_failure_fails_open_with_warning(transport: str) -> None:
    client = FakeCaido(unreachable={"101"}, transport=transport)
    assert _probe_exchange_id(client, "101") is _Probe.UNREACHABLE
    result = verify_finding(_full_finding(http_exchange_ids=["101"]), client=client, strict=True)
    assert result.accepted is True
    assert result.evidence_unverified is True
    assert result.live_verified is False
    assert result.warning is not None
    assert result.http_exchange_ids == ["101"]


# ── ambiguous failures -> fail closed ──────────────────────────────────


def test_ambiguous_nonzero_exit_fails_closed() -> None:
    # Exit 2 "unauthorized": the CLI reached something but is not a transport
    # failure and not a not-found answer — cannot verify, so reject.
    client = FakeCaido(behaviours={"101": AUTH_ERROR})
    assert _probe_exchange_id(client, "101") is _Probe.UNVERIFIABLE
    result = verify_finding(_full_finding(http_exchange_ids=["101"]), client=client, strict=True)
    assert result.accepted is False
    assert any("could not be verified" in e for e in result.errors)


def test_not_found_marker_wins_over_transport_marker() -> None:
    class _Both(CaidoClient):
        def view_request(self, request_id: str) -> dict[str, object]:
            raise CaidoError(
                f"Caido CLI exited 1: request {request_id} not found (connection reset)"
            )

    assert _probe_exchange_id(_Both(), "9") is _Probe.MISSING


def test_unexpected_exception_fails_closed() -> None:
    class _Buggy(CaidoClient):
        def view_request(self, request_id: str) -> dict[str, object]:
            raise ValueError("bug")

    assert _probe_exchange_id(_Buggy(), "9") is _Probe.UNVERIFIABLE


# ── (R-d) positive confirmation -> EXISTS / accept ─────────────────────


@pytest.mark.parametrize(
    "payload",
    [
        {"id": "101", "method": "GET"},
        {"id": 101, "method": "GET"},  # numeric id in JSON
        {"request": {"id": "101", "method": "GET"}},
        {"data": {"request": {"id": "101"}}},
    ],
)
def test_positive_confirmation_shapes_exist(payload: dict[str, object]) -> None:
    class _Confirms(CaidoClient):
        def view_request(self, request_id: str) -> dict[str, object]:
            return payload

    assert _probe_exchange_id(_Confirms(), "101") is _Probe.EXISTS
    result = verify_finding(
        _full_finding(http_exchange_ids=["101"]), client=_Confirms(), strict=True
    )
    assert result.accepted is True
    assert result.live_verified is True
    assert result.evidence_unverified is False


# ── (R-e) audit #3: strict mode with zero cited ids -> REJECT ──────────


@pytest.mark.parametrize("ids", [None, []])
def test_regression_3_strict_requires_live_evidence(ids: list[str] | None) -> None:
    client = FakeCaido()
    result = verify_finding(_full_finding(http_exchange_ids=ids), client=client, strict=True)
    assert result.accepted is False
    assert result.errors == [LIVE_EVIDENCE_REQUIRED_ERROR]
    assert client.calls == []


def test_regression_3_tool_rejects_text_only_finding() -> None:
    from buggy.tools.reporting.tools import report_record_finding

    with (
        patch("buggy.tools.reporting.tools._new_caido_client", return_value=FakeCaido()),
        patch("buggy.tools.reporting.tools.publish_finding_node") as persist,
        patch.dict("os.environ", {"BUGGY_PROOF_GATE_STRICT": "1"}, clear=False),
    ):
        raw = asyncio.run(
            report_record_finding.ainvoke(
                {
                    "title": "text only",
                    "poc_script_code": "p",
                    "poc_description": "d",
                    "evidence": "e",
                }
            )
        )
    payload = json.loads(raw)
    assert payload["success"] is False
    assert LIVE_EVIDENCE_REQUIRED_ERROR in payload["errors"]
    persist.assert_not_called()


# ── (R-f) analysis-only with zero ids -> allowed, not live-proven ──────


def test_analysis_only_zero_ids_not_live_verified() -> None:
    finding = {"title": "static", "http_exchange_ids": []}
    result = verify_finding(finding, client=FakeCaido(), strict=False)
    assert result.accepted is True
    assert result.live_verified is False
    assert result.evidence_unverified is False
