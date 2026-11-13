"""Telemetry allowlist invariants for the expanded tool arsenal.

The privacy-preserving program capture (:mod:`buggy.runtime.programs`)
only measures "was the arsenal used?" if every tool the sandbox actually
ships is on the allowlist. These tests lock that — and the internal
consistency of the allowlist subsets — so a future tool addition that
forgets the telemetry side is caught in CI, not months later in a blind
retrospective.
"""

from __future__ import annotations

import pytest

from buggy.runtime.programs import (
    GENERIC_PROGRAMS,
    KNOWN_PROGRAMS,
    SECURITY_PROGRAMS,
    WEB_SCANNER_PROGRAMS,
    extract_programs,
)
from buggy_core.capabilities import security_binaries

# The headless tranche added to the base sandbox image — each must be
# capturable or its usage is invisible to under-use analysis.
_TRANCHE = (
    "ffuf",
    "feroxbuster",
    "nuclei",
    "httpx-toolkit",
    "whatweb",
    "wafw00f",
    "commix",
    "dalfox",
    "testssl",
    "sslscan",
    "sslyze",
    "gitleaks",
    "trufflehog",
    "tcpdump",
    "tshark",
    "enum4linux",
    "netexec",
)


@pytest.mark.parametrize("prog", _TRANCHE)
def test_tranche_tools_are_captured(prog: str) -> None:
    assert prog in KNOWN_PROGRAMS, f"{prog} not in telemetry allowlist"


@pytest.mark.parametrize("prog", _TRANCHE)
def test_extract_programs_recognizes_tranche(prog: str) -> None:
    # A realistic invocation with a path prefix and arguments must still
    # resolve to the bare basename.
    assert extract_programs(f"/usr/bin/{prog} -u https://target.example") == [prog]


# Impacket installs ``impacket-``-prefixed executables (python3-impacket +
# impacket-scripts), several with camelCase names. extract_programs()
# lowercases basenames, so a realistic invocation must resolve to the
# lowercased allowlist entry — this is exactly the mapping that was broken
# when the registry listed ``secretsdump.py`` etc.
@pytest.mark.parametrize(
    ("invocation", "expected"),
    [
        ("impacket-secretsdump corp/admin:pw@10.0.0.10", "impacket-secretsdump"),
        ("impacket-GetNPUsers corp.local/ -usersfile users.txt", "impacket-getnpusers"),
        ("impacket-GetUserSPNs -request corp.local/user:pw", "impacket-getuserspns"),
        ("impacket-getTGT corp.local/user:pw", "impacket-gettgt"),
        ("/usr/bin/impacket-ntlmrelayx -tf targets.txt -smb2support", "impacket-ntlmrelayx"),
        ("impacket-psexec corp/admin:pw@10.0.0.10", "impacket-psexec"),
    ],
)
def test_extract_programs_recognizes_impacket(invocation: str, expected: str) -> None:
    assert extract_programs(invocation) == [expected]


def test_web_scanner_subset_of_security() -> None:
    assert WEB_SCANNER_PROGRAMS <= SECURITY_PROGRAMS


def test_security_and_generic_disjoint_except_dual_use() -> None:
    """Programs are classified security XOR generic; the only overlaps are
    dual-use network utilities intentionally tracked as generic."""
    overlap = SECURITY_PROGRAMS & GENERIC_PROGRAMS
    assert overlap <= {"nc", "ncat", "socat"}


def test_every_shipped_security_binary_is_known() -> None:
    """Registry-shipped security binaries must all be capturable.

    extract_programs() lowercases basenames, so capturability is checked
    against the lowercased binary name (e.g. impacket-GetNPUsers is stored
    as impacket-getnpusers in the allowlist).
    """
    uncapturable = {b for b in security_binaries() if b.lower() not in KNOWN_PROGRAMS}
    assert not uncapturable, sorted(uncapturable)


def test_extract_programs_caps_and_dedupes() -> None:
    cmd = " && ".join(["nmap -sV target"] * 20)
    progs = extract_programs(cmd)
    assert progs == ["nmap"]  # deduped
