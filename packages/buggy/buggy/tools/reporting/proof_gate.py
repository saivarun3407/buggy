"""Proof-verification gate — the anti-false-positive check that runs before a
finding becomes a published / KG finding node.

Ported reporting discipline (provenance: SPEC.md). The rule: a vulnerability report is REJECTED
unless

1. the required proof fields are present and non-empty — a working PoC
   (``poc_script_code``), a PoC description (``poc_description``), and
   concrete ``evidence``; and
2. in strict mode at least one live HTTP exchange id is cited, and every
   cited id is *positively confirmed* present in the live proxy capture
   (verified against :class:`CaidoClient`).

A fabricated finding whose "evidence" references requests that were never
actually sent — or that cites no live request at all — is blocked here,
before it can reach a report.

**Fail-open ONLY on genuine proxy unreachability.** If the proxy cannot be
queried at all (CLI binary missing, CLI timeout, connection refused / proxy
daemon down), the cited ids are *kept* with a warning rather than stripped —
a slow or unreachable proxy must never silently delete a real finding. Every
other outcome that does not positively confirm the cited request — a
reachable proxy saying "not found", an empty / non-JSON / unrecognised
payload, or a CLI failure we cannot classify as a transport failure —
REJECTS the finding (fail closed). See :func:`_probe_exchange_id` for the
exact classification rule against the real ``CaidoClient._run`` contract.

Strictness is configurable: the ``BUGGY_PROOF_GATE_STRICT`` env flag (default
strict → proof required) can be turned off to allow "analysis-only" findings
without a live PoC, which a later source-only phase relies on.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from buggy.tools.proxy.tools import CaidoClient, CaidoError
from buggy.tools.reporting.cvss import CVSSError, score_vector

# ── Config ─────────────────────────────────────────────────────────────

#: Env flag gating proof strictness. Unset / truthy → STRICT (proof required,
#: the default). A later source-only phase sets this falsey to permit
#: analysis-only findings without a live PoC.
PROOF_GATE_STRICT_ENV = "BUGGY_PROOF_GATE_STRICT"

_FALSEY = frozenset({"0", "false", "no", "off"})


def proof_gate_strict() -> bool:
    """Resolve the gate's strictness from the environment (default: strict)."""
    raw = os.getenv(PROOF_GATE_STRICT_ENV)
    if raw is None:
        return True
    value = raw.strip().lower()
    if not value:
        return True
    return value not in _FALSEY


# ── Required proof fields ──────────────────────────────────────────────

# Required-proof error messages for the three proof fields this phase
# gates on: a working PoC, a PoC description, and concrete evidence.
REQUIRED_PROOF_ERRORS: dict[str, str] = {
    "poc_script_code": ("PoC script/code is REQUIRED - provide the actual exploit/payload"),
    "poc_description": "PoC description cannot be empty",
    "evidence": "Evidence cannot be empty - provide concrete proof of the finding",
}


def required_proof_errors(finding: dict[str, Any], *, strict: bool) -> list[str]:
    """Report every required proof field that arrived blank.

    In strict mode all of :data:`REQUIRED_PROOF_ERRORS` must be present and
    non-empty. In non-strict ("analysis-only") mode the proof fields are
    optional — a static / source-only finding has no live PoC to supply.
    """
    if not strict:
        return []
    return [
        msg
        for name, msg in REQUIRED_PROOF_ERRORS.items()
        if not str(finding.get(name) or "").strip()
    ]


# ── HTTP exchange id normalization ─────────────────────────────────────

_MAX_HTTP_EXCHANGE_IDS = 10
_MAX_HTTP_EXCHANGE_ID_CHARS = 128

HTTP_EXCHANGE_UNVERIFIED_WARNING = (
    "http_exchange_ids were stored without verification because the proxy "
    "could not be reached. Ids that do not exist in the capture will not "
    "render as evidence; re-verify once the proxy responds."
)


def normalize_http_exchange_ids(raw: Any) -> tuple[list[str] | None, list[str]]:
    """Return distinct numeric proxy exchange ids in their original order.

    Normalizes http-exchange ids: ids must be a list of
    non-empty, visible-ASCII, numeric strings; duplicates are collapsed and
    order preserved; the count and per-id length are bounded.
    """
    if raw is None:
        return None, []
    if not isinstance(raw, list):
        return None, ["http_exchange_ids must be a list of proxy request ids"]

    normalized: list[str] = []
    errors: list[str] = []
    seen: set[str] = set()
    for index, value in enumerate(raw):
        if not isinstance(value, str):
            errors.append(f"http_exchange_ids[{index}] must be a string")
            continue
        request_id = value.strip()
        if not request_id:
            errors.append(f"http_exchange_ids[{index}] cannot be empty")
            continue
        if len(request_id) > _MAX_HTTP_EXCHANGE_ID_CHARS:
            errors.append(
                f"http_exchange_ids[{index}] must be "
                f"{_MAX_HTTP_EXCHANGE_ID_CHARS} characters or fewer"
            )
            continue
        if any(ord(char) < 0x21 or ord(char) > 0x7E for char in request_id):
            errors.append(f"http_exchange_ids[{index}] must contain only visible ASCII characters")
            continue
        if not request_id.isdigit():
            errors.append(f"http_exchange_ids[{index}] must be a numeric proxy request id")
            continue
        if request_id not in seen:
            seen.add(request_id)
            normalized.append(request_id)
            if len(normalized) > _MAX_HTTP_EXCHANGE_IDS:
                errors.append(
                    f"http_exchange_ids can contain at most "
                    f"{_MAX_HTTP_EXCHANGE_IDS} distinct request ids"
                )
                break
    return normalized, errors


# ── Live-evidence verification against the proxy ───────────────────────


class _Probe(Enum):
    """Outcome of resolving one cited exchange id against the proxy."""

    EXISTS = "exists"  # payload positively describes the cited request
    MISSING = "missing"  # proxy answered: no such request
    UNREACHABLE = "unreachable"  # transport failure: proxy could not be queried
    UNVERIFIABLE = "unverifiable"  # proxy answered, but not a confirmation


# Message shapes ``CaidoClient._run`` raises (tools/proxy/tools.py). CaidoError
# now carries a typed ``kind`` — these regexes are the fallback for errors
# constructed outside ``_run`` (kind="unknown"), so both paths agree.
_CLI_MISSING_RE = re.compile(r"^Caido CLI not found:")
_CLI_TIMEOUT_RE = re.compile(r"^Caido CLI timed out after ")
_CLI_EXITED_RE = re.compile(r"^Caido CLI exited (-?\d+): ?(.*)$", re.DOTALL)

#: stderr/stdout text meaning "the proxy has no such request".
_NOT_FOUND_MARKERS = (
    "not found",
    "no such request",
    "no request",
    "does not exist",
    "doesn't exist",
    "unknown request",
    "404",
)

#: stderr text meaning the CLI could not reach the proxy at all.
_TRANSPORT_MARKERS = (
    "connection refused",
    "econnrefused",
    "connection reset",
    "econnreset",
    "could not connect",
    "couldn't connect",
    "failed to connect",
    "unable to connect",
    "network is unreachable",
    "no route to host",
    "host is unreachable",
    "name or service not known",
    "nodename nor servname",
    "temporary failure in name resolution",
    "timed out",
    "etimedout",
)


def _has_marker(text: str, markers: tuple[str, ...]) -> bool:
    lowered = text.lower()
    return any(marker in lowered for marker in markers)


def _classify_caido_error(exc: CaidoError) -> _Probe:
    """Classify a :class:`CaidoError` raised by the real ``CaidoClient._run``.

    ``_run`` raises ``CaidoError`` for three distinct situations, and only
    the first two are transport failures:

    1. ``"Caido CLI not found: ..."`` (binary missing) → ``UNREACHABLE``.
    2. ``"Caido CLI timed out after ..."`` (subprocess timeout) → ``UNREACHABLE``.
    3. ``"Caido CLI exited <code>: <stderr-or-stdout>"`` — the CLI *ran* and
       exited non-zero. A real ``caido requests view <missing-id>`` lands
       here. The detail text decides:

       - a not-found marker (``not found``, ``no such request``, ``404``…)
         → ``MISSING``. Checked first: a positive "absent" answer always
         rejects, even if the text also mentions a network word.
       - a transport marker (``connection refused``, ``could not connect``,
         ``timed out``, DNS failure…) → ``UNREACHABLE``.
       - anything else (auth failure, unknown flag, empty detail, a message
         shape we do not recognise) → ``UNVERIFIABLE`` — fail closed.

    Any other shape → ``UNVERIFIABLE`` (fail closed).

    Primary classification is the typed ``exc.kind``; the message regexes
    are the fallback for errors constructed outside ``_run``
    (``kind="unknown"``, e.g. test doubles) so both paths agree. Detail
    text is only ever consulted to distinguish MISSING vs UNREACHABLE vs
    UNVERIFIABLE *within* an exited error — it cannot be steered by the
    finding author because cited ids are normalised to plain digits
    before they reach the CLI.
    """
    kind = getattr(exc, "kind", "unknown")
    message = str(exc).strip()
    if kind in ("cli_missing", "timeout"):
        return _Probe.UNREACHABLE
    if kind == "unknown":
        # Legacy/foreign CaidoError — classify by message shape.
        if _CLI_MISSING_RE.match(message) or _CLI_TIMEOUT_RE.match(message):
            return _Probe.UNREACHABLE
        exited = _CLI_EXITED_RE.match(message)
        if exited is None:
            return _Probe.UNVERIFIABLE
        detail = exited.group(2)
    elif kind == "exited":
        # Split "exited N: detail" the same way the regex did so the
        # marker scan sees identical input.
        exited = _CLI_EXITED_RE.match(message)
        detail = exited.group(2) if exited is not None else message
    else:
        return _Probe.UNVERIFIABLE
    if _has_marker(detail, _NOT_FOUND_MARKERS):
        return _Probe.MISSING
    if _has_marker(detail, _TRANSPORT_MARKERS):
        return _Probe.UNREACHABLE
    return _Probe.UNVERIFIABLE


def _describes_request(obj: Any, request_id: str) -> bool:
    """True when ``obj`` is a request record whose id is ``request_id``."""
    if not isinstance(obj, dict):
        return False
    return any(
        key in obj and str(obj[key]).strip() == request_id
        for key in ("id", "request_id", "requestId")
    )


def _payload_confirms(payload: Any, request_id: str) -> bool:
    """Decide whether an exit-0 ``view_request`` payload confirms the request.

    Confirmation is positive, never inferred from "non-empty": the payload
    must carry the cited request's own id, at the top level
    (``{"id": "101", ...}``) or in a nested request record
    (``{"request": {"id": "101"}}``, ``{"data": {"request": {"id": "101"}}}``).

    Never confirms: ``{}`` (empty stdout), ``{"raw": ...}`` (``_run`` wraps
    non-JSON stdout such as ``"Request not found"`` this way), a payload
    with an ``error`` or ``found``/``exists: false`` marker, or a record for a
    different id.
    """
    if not isinstance(payload, dict) or not payload:
        return False
    if "raw" in payload:
        return False
    if payload.get("found") is False or payload.get("exists") is False:
        return False
    if payload.get("error"):
        return False
    data = payload.get("data")
    candidates = [
        payload,
        payload.get("request"),
        data,
        data.get("request") if isinstance(data, dict) else None,
    ]
    return any(_describes_request(c, request_id) for c in candidates)


def _classify_payload(payload: Any, request_id: str) -> _Probe:
    """Classify an exit-0 payload: confirmed, not-found, or unverifiable."""
    if _payload_confirms(payload, request_id):
        return _Probe.EXISTS
    if not isinstance(payload, dict) or not payload:
        return _Probe.MISSING  # empty stdout: nothing held under that id
    if payload.get("found") is False or payload.get("exists") is False:
        return _Probe.MISSING
    text = str(payload.get("raw") or payload.get("error") or "")
    if _has_marker(text, _NOT_FOUND_MARKERS):
        return _Probe.MISSING
    return _Probe.UNVERIFIABLE


def _probe_exchange_id(client: CaidoClient, request_id: str) -> _Probe:
    """Resolve one id against the proxy, mirroring the real CaidoClient contract.

    - ``view_request`` raises :class:`CaidoError` → :func:`_classify_caido_error`
      (only "CLI missing", "timeout" and transport-marked exits are
      ``UNREACHABLE``; not-found exits are ``MISSING``; the rest is
      ``UNVERIFIABLE``).
    - ``OSError`` escaping the subprocess call (e.g. CLI not executable)
      → ``UNREACHABLE``.
    - Any other exception → ``UNVERIFIABLE`` (fail closed: a bug is not an
      outage).
    - Exit 0 → :func:`_classify_payload`.
    """
    try:
        payload = client.view_request(request_id)
    except CaidoError as exc:
        return _classify_caido_error(exc)
    except OSError:
        return _Probe.UNREACHABLE
    except Exception:  # noqa: BLE001 — unknown failure: fail closed
        return _Probe.UNVERIFIABLE
    return _classify_payload(payload, request_id)


def verify_http_exchange_ids(
    client: CaidoClient | None,
    raw: Any,
) -> tuple[list[str] | None, list[str], str | None]:
    """Verify cited exchange ids against the live proxy capture.

    Returns ``(ids, errors, warning)``:

    - ``errors`` non-empty → the finding is rejected. This happens on a
      malformed id list, when the proxy reports an id absent (``MISSING``),
      or when an answer neither confirms nor is a transport failure
      (``UNVERIFIABLE``). A rejecting verdict on any id wins over an
      unreachable probe on another id.
    - ``warning`` set (with ``ids`` kept) → no id was rejected but at least
      one probe hit a transport failure; the ids are stored unverified
      rather than stripped (fail-open, the only one).
    - otherwise every id was positively confirmed present.
    """
    request_ids, errors = normalize_http_exchange_ids(raw)
    if request_ids is None or errors or not request_ids:
        return request_ids, errors, None

    if client is None:
        # No proxy client available at all — same fail-open path: keep + warn.
        return request_ids, [], HTTP_EXCHANGE_UNVERIFIED_WARNING

    probes = {rid: _probe_exchange_id(client, rid) for rid in request_ids}

    missing = [rid for rid, p in probes.items() if p is _Probe.MISSING]
    unverifiable = [rid for rid, p in probes.items() if p is _Probe.UNVERIFIABLE]
    rejections: list[str] = []
    if missing:
        rejections.append(
            "http_exchange_ids do not exist in the current proxy capture: " + ", ".join(missing)
        )
    if unverifiable:
        rejections.append(
            "http_exchange_ids could not be verified - the proxy answered but "
            "did not confirm the request: " + ", ".join(unverifiable)
        )
    if rejections:
        return None, rejections, None

    if any(p is _Probe.UNREACHABLE for p in probes.values()):
        return request_ids, [], HTTP_EXCHANGE_UNVERIFIED_WARNING
    return request_ids, [], None


# ── Optional CVSS validation (reuses the spine's cvss.py) ──────────────


def cvss_errors(finding: dict[str, Any]) -> list[str]:
    """Validate a cited CVSS vector, if any, with the spine's scorer.

    Only runs when the finding carries a ``cvss_vector`` — an invalid vector is
    a defect (the number a triager keys off would be wrong), so it rejects.
    Reuses ``reporting/cvss.py`` (in-tree).
    """
    vector = str(finding.get("cvss_vector") or "").strip()
    if not vector:
        return []
    try:
        score_vector(vector)
    except CVSSError as exc:
        return [f"cvss_vector is invalid: {exc}"]
    return []


# ── Top-level gate ─────────────────────────────────────────────────────

#: Strict-mode error when a finding cites no live proxy request at all.
LIVE_EVIDENCE_REQUIRED_ERROR = (
    "http_exchange_ids is REQUIRED - cite at least one live proxy request id "
    "that proves the finding (set analysis_only in a non-strict deployment "
    "for a source-only finding)"
)


@dataclass(frozen=True, slots=True)
class GateResult:
    """The gate's verdict on one finding."""

    accepted: bool
    errors: list[str] = field(default_factory=list)
    warning: str | None = None
    http_exchange_ids: list[str] | None = None
    #: True when evidence was kept unverified because the proxy was unreachable.
    evidence_unverified: bool = False
    #: True only when at least one id was cited and every cited id was
    #: positively confirmed in the live capture. An analysis-only finding
    #: with no ids, or a fail-open (unreachable proxy) finding, is never
    #: live-verified.
    live_verified: bool = False


def verify_finding(
    finding: dict[str, Any],
    *,
    client: CaidoClient | None = None,
    strict: bool | None = None,
) -> GateResult:
    """Run the full proof gate over a candidate finding.

    Rejected (``accepted=False``, never persisted): missing required proof;
    in strict mode, no cited ``http_exchange_ids``; a malformed id list; an
    id the proxy reports absent or answers for without confirming; an
    invalid CVSS vector. A finding whose probes hit only transport failures
    is accepted with ``evidence_unverified=True`` and a warning.

    Non-strict ("analysis-only") mode drops the proof-field and cited-id
    requirements, but any cited id is still verified, and a finding with no
    ids is returned with ``live_verified=False``.

    ``strict`` defaults to :func:`proof_gate_strict` (the env flag).
    """
    if strict is None:
        strict = proof_gate_strict()

    errors = required_proof_errors(finding, strict=strict)
    errors.extend(cvss_errors(finding))

    ids, id_errors, warning = verify_http_exchange_ids(client, finding.get("http_exchange_ids"))
    errors.extend(id_errors)
    if strict and not id_errors and not ids:
        errors.append(LIVE_EVIDENCE_REQUIRED_ERROR)

    if errors:
        return GateResult(accepted=False, errors=errors)
    return GateResult(
        accepted=True,
        warning=warning,
        http_exchange_ids=ids,
        evidence_unverified=warning is not None,
        live_verified=bool(ids) and warning is None,
    )


__all__ = [
    "HTTP_EXCHANGE_UNVERIFIED_WARNING",
    "LIVE_EVIDENCE_REQUIRED_ERROR",
    "PROOF_GATE_STRICT_ENV",
    "REQUIRED_PROOF_ERRORS",
    "GateResult",
    "cvss_errors",
    "normalize_http_exchange_ids",
    "proof_gate_strict",
    "required_proof_errors",
    "verify_finding",
    "verify_http_exchange_ids",
]
