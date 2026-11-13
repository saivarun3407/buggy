"""Kali capability registry — machine-readable tool inventory.

Central source of truth for every security tool the platform supports.
The registry drives:

  * **Prompt generation** — the ``<KALI_ENVIRONMENT>`` block is derived
    from the registry, never hard-coded.
  * **Telemetry validation** — ``runtime/programs.py`` derives its
    ``SECURITY_PROGRAMS`` / ``GENERIC_PROGRAMS`` from the registry so
    the event capture, retrospective analysis, and prompt never drift.
  * **Sandbox image CI** — a test asserts that every ``base``-delivery
    capability has a matching ``apt-get install`` line in the Dockerfile
    and vice-versa.
  * **Agent discovery** — agents query the registry by role/phase/category
    to find eligible tools before falling back to generic scripting.

Lifecycle values:

  * ``supported`` — validated, smoke-tested, evidence adapter optional.
  * ``preview`` — installed but not yet fully evaluated.
  * ``planned`` — tracked for future inclusion.
  * ``quarantined`` — temporarily disabled (broken build, CVE, etc.).
  * ``deprecated`` — scheduled for removal.

Delivery classes:

  * ``base`` — pre-installed in the default sandbox image (run directly
    with bash). Sourced from apt (``apt_packages``) or, for tools with no
    apt package, pip-installed at BUILD time (``pip_packages``).
  * ``profile:<name>`` — available when the named Compose profile is
    active (e.g. ``profile:reversing``, ``profile:ad``).
  * ``pip`` — NOT pre-installed; the agent installs it at runtime with
    ``pip3 install --break-system-packages`` (Kali's Python is
    externally managed).
  * ``sidecar`` — runs as a separate container service.
  * ``external`` — requires an external provider (GPU, hardware, cloud).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Lifecycle(Enum):
    SUPPORTED = "supported"
    PREVIEW = "preview"
    PLANNED = "planned"
    QUARANTINED = "quarantined"
    DEPRECATED = "deprecated"


class RiskTier(Enum):
    """Agent-visible risk classification."""

    PASSIVE = 0  # OSINT, local analysis, version lookup
    BOUNDED_ACTIVE = 1  # port scan, web crawl, vuln scan
    INTRUSIVE = 2  # fuzzing, credential testing, exploit validation
    HIGH_IMPACT = 3  # post-exploitation, credential extraction, C2
    HARDWARE = 4  # requires physical hardware / external provider


@dataclass(frozen=True, slots=True)
class Capability:
    """One security tool or binary the platform can provide."""

    id: str
    """Unique slug, usually the binary name (``nmap``, ``ffuf``)."""

    category: str
    """Functional bucket: ``recon``, ``web``, ``exploit``, etc."""

    description: str
    """One-line human-readable summary."""

    binaries: tuple[str, ...]
    """Executable basenames this capability provides."""

    delivery: str
    """How the tool reaches the sandbox: ``base``, ``profile:ad``, ``pip``, etc."""

    apt_packages: tuple[str, ...] = ()
    """Debian/Kali package names that supply the binaries (base delivery)."""

    risk_tier: RiskTier = RiskTier.BOUNDED_ACTIVE

    roles: frozenset[str] = field(default_factory=frozenset)
    """Agent roles allowed to use this capability.  Empty = all roles."""

    phases: tuple[str, ...] = ()
    """Kill-chain phases where this tool is relevant (MITRE tactic IDs)."""

    lifecycle: Lifecycle = Lifecycle.SUPPORTED

    requires_service: str | None = None
    """Compose service name that must be running (e.g. ``c2-sliver``)."""

    requires_profile: str | None = None
    """Compose profile that must be active (e.g. ``reversing``)."""

    pip_packages: tuple[str, ...] = ()
    """PyPI names pip-installed at image BUILD time for base-delivery tools
    that have no apt package (e.g. ``volatility3``). Distinct from the
    ``pip`` *delivery* class, which the agent installs at runtime. Kept last
    in the field order so it never shifts the positional constructor
    contract of the pre-existing fields."""


# ── Registry ────────────────────────────────────────────────────────────
# Sorted by category then id. Each entry's ``binaries`` field lists every
# executable basename the capability exposes — this is the join key to
# ``runtime/programs.py``'s telemetry allowlist.

CAPABILITY_REGISTRY: tuple[Capability, ...] = (
    # ── Core runtime (not security tools, but required infrastructure) ──
    Capability(
        id="curl",
        category="runtime",
        description="HTTP client for manual probing and scripting",
        binaries=("curl",),
        delivery="base",
        apt_packages=("curl",),
        risk_tier=RiskTier.PASSIVE,
        lifecycle=Lifecycle.SUPPORTED,
    ),
    Capability(
        id="wget",
        category="runtime",
        description="HTTP/FTP file retrieval",
        binaries=("wget",),
        delivery="base",
        apt_packages=("wget",),
        risk_tier=RiskTier.PASSIVE,
        lifecycle=Lifecycle.SUPPORTED,
    ),
    Capability(
        id="python3",
        category="runtime",
        description="Python 3 interpreter for custom scripts",
        binaries=("python3", "python"),
        delivery="base",
        apt_packages=("python3",),
        risk_tier=RiskTier.PASSIVE,
        lifecycle=Lifecycle.SUPPORTED,
    ),
    Capability(
        id="python3-pip",
        category="runtime",
        description="Python package installer (pip)",
        binaries=("pip3", "pip"),
        delivery="base",
        apt_packages=("python3-pip",),
        risk_tier=RiskTier.PASSIVE,
        lifecycle=Lifecycle.SUPPORTED,
    ),
    Capability(
        id="tmux",
        category="runtime",
        description="Terminal multiplexer (backs the sandbox bash session)",
        binaries=("tmux",),
        delivery="base",
        apt_packages=("tmux",),
        risk_tier=RiskTier.PASSIVE,
        lifecycle=Lifecycle.SUPPORTED,
    ),
    Capability(
        id="nodejs",
        category="runtime",
        description="Node.js runtime (payload encoding, Playwright templates)",
        binaries=("node", "nodejs"),
        delivery="base",
        apt_packages=("nodejs",),
        risk_tier=RiskTier.PASSIVE,
        lifecycle=Lifecycle.SUPPORTED,
    ),
    Capability(
        id="npm",
        category="runtime",
        description="Node package manager",
        binaries=("npm",),
        delivery="base",
        apt_packages=("npm",),
        risk_tier=RiskTier.PASSIVE,
        lifecycle=Lifecycle.SUPPORTED,
    ),
    Capability(
        id="openssh-client",
        category="runtime",
        description="SSH client for lateral movement and tunneling",
        binaries=("ssh", "scp"),
        delivery="base",
        apt_packages=("openssh-client", "sshpass"),
        risk_tier=RiskTier.BOUNDED_ACTIVE,
        lifecycle=Lifecycle.SUPPORTED,
    ),
    # ── Recon / enumeration ──
    Capability(
        id="nmap",
        category="recon",
        description="Port scanner and service fingerprinter",
        binaries=("nmap",),
        delivery="base",
        apt_packages=("nmap",),
        risk_tier=RiskTier.BOUNDED_ACTIVE,
        phases=("TA0043",),
        lifecycle=Lifecycle.SUPPORTED,
    ),
    Capability(
        id="dnsutils",
        category="recon",
        description="DNS lookup utilities (dig, nslookup, host)",
        binaries=("dig", "host", "nslookup"),
        delivery="base",
        apt_packages=("dnsutils",),
        risk_tier=RiskTier.PASSIVE,
        phases=("TA0043",),
        lifecycle=Lifecycle.SUPPORTED,
    ),
    Capability(
        id="whois",
        category="recon",
        description="WHOIS domain/IP registration lookup",
        binaries=("whois",),
        delivery="base",
        apt_packages=("whois",),
        risk_tier=RiskTier.PASSIVE,
        phases=("TA0043",),
        lifecycle=Lifecycle.SUPPORTED,
    ),
    Capability(
        id="subfinder",
        category="recon",
        description="Passive subdomain discovery",
        binaries=("subfinder",),
        delivery="base",
        apt_packages=("subfinder",),
        risk_tier=RiskTier.PASSIVE,
        phases=("TA0043",),
        lifecycle=Lifecycle.SUPPORTED,
    ),
    Capability(
        id="netcat",
        category="recon",
        description="TCP/UDP connection utility",
        binaries=("nc", "ncat"),
        delivery="base",
        apt_packages=("netcat-openbsd",),
        risk_tier=RiskTier.BOUNDED_ACTIVE,
        lifecycle=Lifecycle.SUPPORTED,
    ),
    Capability(
        id="masscan",
        category="recon",
        description="High-speed port scanner for large networks",
        binaries=("masscan",),
        delivery="base",
        apt_packages=("masscan",),
        risk_tier=RiskTier.BOUNDED_ACTIVE,
        phases=("TA0043",),
        lifecycle=Lifecycle.SUPPORTED,
    ),
    Capability(
        id="iputils",
        category="recon",
        description="ICMP ping and network probing",
        binaries=(),
        delivery="base",
        apt_packages=("iputils-ping",),
        risk_tier=RiskTier.PASSIVE,
        lifecycle=Lifecycle.SUPPORTED,
    ),
    # ── Web fuzzing / scanning ──
    Capability(
        id="nikto",
        category="web",
        description="Web server vulnerability scanner",
        binaries=("nikto",),
        delivery="base",
        apt_packages=("nikto",),
        risk_tier=RiskTier.BOUNDED_ACTIVE,
        phases=("TA0043",),
        lifecycle=Lifecycle.SUPPORTED,
    ),
    Capability(
        id="gobuster",
        category="web",
        description="URI/DNS/vhost brute-force enumerator",
        binaries=("gobuster",),
        delivery="base",
        apt_packages=("gobuster",),
        risk_tier=RiskTier.BOUNDED_ACTIVE,
        phases=("TA0043",),
        lifecycle=Lifecycle.SUPPORTED,
    ),
    Capability(
        id="dirb",
        category="web",
        description="Web content discovery (dictionary-based)",
        binaries=("dirb",),
        delivery="base",
        apt_packages=("dirb",),
        risk_tier=RiskTier.BOUNDED_ACTIVE,
        phases=("TA0043",),
        lifecycle=Lifecycle.SUPPORTED,
    ),
    Capability(
        id="ffuf",
        category="web",
        description="Fast web fuzzer for directories, parameters, and vhosts",
        binaries=("ffuf",),
        delivery="base",
        apt_packages=("ffuf",),
        risk_tier=RiskTier.BOUNDED_ACTIVE,
        phases=("TA0043",),
        lifecycle=Lifecycle.SUPPORTED,
    ),
    Capability(
        id="feroxbuster",
        category="web",
        description="Recursive content discovery with auto-filtering",
        binaries=("feroxbuster",),
        delivery="base",
        apt_packages=("feroxbuster",),
        risk_tier=RiskTier.BOUNDED_ACTIVE,
        phases=("TA0043",),
        lifecycle=Lifecycle.SUPPORTED,
    ),
    Capability(
        id="nuclei",
        category="web",
        description="Template-driven vulnerability scanner",
        binaries=("nuclei",),
        delivery="base",
        apt_packages=("nuclei",),
        risk_tier=RiskTier.BOUNDED_ACTIVE,
        phases=("TA0043",),
        lifecycle=Lifecycle.SUPPORTED,
    ),
    Capability(
        id="wpscan",
        category="web",
        description="WordPress security scanner",
        binaries=("wpscan",),
        delivery="base",
        apt_packages=("wpscan",),
        risk_tier=RiskTier.BOUNDED_ACTIVE,
        phases=("TA0043",),
        lifecycle=Lifecycle.SUPPORTED,
    ),
    Capability(
        id="httpx",
        category="web",
        description="Fast HTTP toolkit for probing, tech detection, and status checks",
        binaries=("httpx-toolkit",),
        delivery="base",
        apt_packages=("httpx-toolkit",),
        risk_tier=RiskTier.BOUNDED_ACTIVE,
        phases=("TA0043",),
        lifecycle=Lifecycle.SUPPORTED,
    ),
    Capability(
        id="whatweb",
        category="web",
        description="Web technology fingerprinter",
        binaries=("whatweb",),
        delivery="base",
        apt_packages=("whatweb",),
        risk_tier=RiskTier.PASSIVE,
        phases=("TA0043",),
        lifecycle=Lifecycle.SUPPORTED,
    ),
    Capability(
        id="wafw00f",
        category="web",
        description="Web Application Firewall fingerprinter",
        binaries=("wafw00f",),
        delivery="base",
        apt_packages=("wafw00f",),
        risk_tier=RiskTier.PASSIVE,
        phases=("TA0043",),
        lifecycle=Lifecycle.SUPPORTED,
    ),
    # ── Vuln-specific ──
    Capability(
        id="sqlmap",
        category="vuln",
        description="Automatic SQL injection detection and exploitation",
        binaries=("sqlmap",),
        delivery="base",
        apt_packages=("sqlmap",),
        risk_tier=RiskTier.INTRUSIVE,
        phases=("TA0001",),
        lifecycle=Lifecycle.SUPPORTED,
    ),
    Capability(
        id="commix",
        category="vuln",
        description="OS command injection exploitation tool",
        binaries=("commix",),
        delivery="base",
        apt_packages=("commix",),
        risk_tier=RiskTier.INTRUSIVE,
        phases=("TA0001",),
        lifecycle=Lifecycle.SUPPORTED,
    ),
    Capability(
        id="dalfox",
        category="vuln",
        description="XSS scanner and parameter analysis tool",
        binaries=("dalfox",),
        delivery="base",
        apt_packages=("dalfox",),
        risk_tier=RiskTier.INTRUSIVE,
        phases=("TA0001",),
        lifecycle=Lifecycle.SUPPORTED,
    ),
    # ── Credentials / cracking ──
    Capability(
        id="hydra",
        category="credentials",
        description="Network login brute-forcer (SSH, FTP, HTTP, SMB, etc.)",
        binaries=("hydra",),
        delivery="base",
        apt_packages=("hydra",),
        risk_tier=RiskTier.INTRUSIVE,
        phases=("TA0006",),
        lifecycle=Lifecycle.SUPPORTED,
    ),
    Capability(
        id="john",
        category="credentials",
        description="Password hash cracker (John the Ripper)",
        binaries=("john",),
        delivery="base",
        apt_packages=("john",),
        risk_tier=RiskTier.INTRUSIVE,
        phases=("TA0006",),
        lifecycle=Lifecycle.SUPPORTED,
    ),
    Capability(
        id="hashcat",
        category="credentials",
        description="GPU-accelerated password hash cracker",
        binaries=("hashcat",),
        delivery="base",
        apt_packages=("hashcat",),
        risk_tier=RiskTier.INTRUSIVE,
        phases=("TA0006",),
        lifecycle=Lifecycle.SUPPORTED,
    ),
    # ── SMB / Network ──
    Capability(
        id="smbclient",
        category="smb",
        description="SMB/CIFS file share client",
        binaries=("smbclient",),
        delivery="base",
        apt_packages=("smbclient",),
        risk_tier=RiskTier.BOUNDED_ACTIVE,
        lifecycle=Lifecycle.SUPPORTED,
    ),
    Capability(
        id="enum4linux",
        category="smb",
        description="Windows/Samba enumeration tool",
        binaries=("enum4linux",),
        delivery="base",
        apt_packages=("enum4linux",),
        risk_tier=RiskTier.BOUNDED_ACTIVE,
        phases=("TA0043",),
        lifecycle=Lifecycle.SUPPORTED,
    ),
    Capability(
        id="netexec",
        category="smb",
        description="Network service attack tool (SMB, WinRM, LDAP, MSSQL, SSH)",
        binaries=("netexec", "nxc", "nxcdb"),
        delivery="base",
        apt_packages=("netexec",),
        risk_tier=RiskTier.INTRUSIVE,
        phases=("TA0006", "TA0008"),
        lifecycle=Lifecycle.SUPPORTED,
    ),
    # ── AD / Kerberos (base: Impacket + Responder) ──
    Capability(
        id="impacket",
        category="ad",
        description=(
            "Python AD/SMB/Kerberos toolkit. Kali installs the example scripts as "
            "``impacket-``-prefixed executables (e.g. impacket-secretsdump), NOT the "
            "``.py`` names. The library ships in python3-impacket; the CLI suite "
            "(incl. impacket-ntlmrelayx for the Responder relay chain) is in "
            "impacket-scripts."
        ),
        binaries=(
            "impacket-secretsdump",
            "impacket-ntlmrelayx",
            "impacket-psexec",
            "impacket-wmiexec",
            "impacket-smbexec",
            "impacket-atexec",
            "impacket-dcomexec",
            "impacket-GetNPUsers",
            "impacket-GetUserSPNs",
            "impacket-getTGT",
            "impacket-getST",
            "impacket-ticketer",
            "impacket-lookupsid",
            "impacket-samrdump",
            "impacket-rpcdump",
            "impacket-mssqlclient",
            "impacket-smbserver",
            "impacket-smbclient",
        ),
        delivery="base",
        apt_packages=("python3-impacket", "impacket-scripts"),
        risk_tier=RiskTier.INTRUSIVE,
        phases=("TA0006", "TA0008"),
        lifecycle=Lifecycle.SUPPORTED,
    ),
    Capability(
        id="responder",
        category="ad",
        description="LLMNR/NBT-NS/mDNS poisoner and NTLM relay",
        binaries=("responder",),
        delivery="base",
        apt_packages=("responder",),
        risk_tier=RiskTier.INTRUSIVE,
        phases=("TA0006",),
        lifecycle=Lifecycle.SUPPORTED,
    ),
    # ── Exploitation frameworks (base: searchsploit) ──
    Capability(
        id="exploitdb",
        category="exploit",
        description="Exploit-DB archive and searchsploit CLI",
        binaries=("searchsploit",),
        delivery="base",
        apt_packages=("exploitdb",),
        risk_tier=RiskTier.PASSIVE,
        phases=("TA0001",),
        lifecycle=Lifecycle.SUPPORTED,
    ),
    Capability(
        id="metasploit",
        category="exploit",
        description="Metasploit Framework (msfconsole, msfvenom)",
        binaries=("msfconsole", "msfvenom"),
        delivery="base",
        apt_packages=("metasploit-framework",),
        risk_tier=RiskTier.INTRUSIVE,
        phases=("TA0001", "TA0002", "TA0004"),
        lifecycle=Lifecycle.SUPPORTED,
    ),
    # ── C2 ──
    Capability(
        id="sliver",
        category="c2",
        description="Sliver C2 framework client",
        binaries=("sliver", "sliver-client"),
        delivery="base",
        apt_packages=("sliver",),
        risk_tier=RiskTier.HIGH_IMPACT,
        phases=("TA0011",),
        requires_service="c2-sliver",
        lifecycle=Lifecycle.SUPPORTED,
    ),
    # ── TLS / crypto ──
    Capability(
        id="testssl",
        category="tls",
        description="TLS/SSL configuration and vulnerability scanner",
        binaries=("testssl",),
        delivery="base",
        apt_packages=("testssl.sh",),
        risk_tier=RiskTier.PASSIVE,
        phases=("TA0043",),
        lifecycle=Lifecycle.SUPPORTED,
    ),
    Capability(
        id="sslscan",
        category="tls",
        description="SSL/TLS cipher and certificate scanner",
        binaries=("sslscan",),
        delivery="base",
        apt_packages=("sslscan",),
        risk_tier=RiskTier.PASSIVE,
        phases=("TA0043",),
        lifecycle=Lifecycle.SUPPORTED,
    ),
    Capability(
        id="sslyze",
        category="tls",
        description="Python TLS scanner (certificate, cipher, vulnerability checks)",
        binaries=("sslyze",),
        delivery="base",
        apt_packages=("sslyze",),
        risk_tier=RiskTier.PASSIVE,
        phases=("TA0043",),
        lifecycle=Lifecycle.SUPPORTED,
    ),
    # ── Secrets / supply chain ──
    Capability(
        id="gitleaks",
        category="secrets",
        description="Git repository secret scanner",
        binaries=("gitleaks",),
        delivery="base",
        apt_packages=("gitleaks",),
        risk_tier=RiskTier.PASSIVE,
        phases=("TA0043",),
        lifecycle=Lifecycle.SUPPORTED,
    ),
    Capability(
        id="trufflehog",
        category="secrets",
        description="Credential and secret scanner for git, S3, filesystems",
        binaries=("trufflehog",),
        delivery="base",
        apt_packages=("trufflehog",),
        risk_tier=RiskTier.PASSIVE,
        phases=("TA0043",),
        lifecycle=Lifecycle.SUPPORTED,
    ),
    # ── Packet capture / network analysis ──
    Capability(
        id="tcpdump",
        category="network",
        description="Command-line packet capture and analysis",
        binaries=("tcpdump",),
        delivery="base",
        apt_packages=("tcpdump",),
        risk_tier=RiskTier.PASSIVE,
        lifecycle=Lifecycle.SUPPORTED,
    ),
    Capability(
        id="tshark",
        category="network",
        description="Terminal-based Wireshark for packet analysis",
        binaries=("tshark",),
        delivery="base",
        apt_packages=("tshark",),
        risk_tier=RiskTier.PASSIVE,
        lifecycle=Lifecycle.SUPPORTED,
    ),
    Capability(
        id="socat",
        category="network",
        description="Multipurpose relay for bidirectional data transfer",
        binaries=("socat",),
        delivery="base",
        apt_packages=("socat",),
        risk_tier=RiskTier.BOUNDED_ACTIVE,
        lifecycle=Lifecycle.SUPPORTED,
    ),
    # ── Mobile ──
    Capability(
        id="adb",
        category="mobile",
        description="Android Debug Bridge for device interaction",
        binaries=("adb",),
        delivery="base",
        apt_packages=("adb",),
        risk_tier=RiskTier.BOUNDED_ACTIVE,
        lifecycle=Lifecycle.SUPPORTED,
    ),
    Capability(
        id="apktool",
        category="mobile",
        description="APK reverse engineering (decode/rebuild)",
        binaries=("apktool",),
        delivery="base",
        apt_packages=("apktool",),
        risk_tier=RiskTier.PASSIVE,
        lifecycle=Lifecycle.SUPPORTED,
    ),
    # ── DFIR ──
    Capability(
        id="yara",
        category="dfir",
        description="Pattern matching for malware and IOC detection",
        binaries=("yara",),
        delivery="base",
        apt_packages=("yara",),
        risk_tier=RiskTier.PASSIVE,
        lifecycle=Lifecycle.SUPPORTED,
    ),
    # ── Reversing ──
    # radare2 + binwalk are lightweight apt CLIs and live in the base image,
    # so bash can run them directly. Ghidra is a ~500 MB JDK+suite that is
    # NOT in the sandbox where bash executes — it is reached through the
    # dedicated ``ghidra_*`` @tool wrappers backed by the ghidra-mcp sidecar
    # (delivery="sidecar"), so it must not be advertised as a bash binary.
    Capability(
        id="ghidra",
        category="reversing",
        description=(
            "NSA binary analysis suite. Not runnable from bash — use the dedicated "
            "ghidra_analyze / ghidra_decompile / ghidra_xrefs tools after "
            "ops_start('reversing')."
        ),
        binaries=("ghidra",),
        delivery="sidecar",
        risk_tier=RiskTier.PASSIVE,
        requires_service="ghidra-mcp",
        requires_profile="reversing",
        lifecycle=Lifecycle.SUPPORTED,
    ),
    Capability(
        id="radare2",
        category="reversing",
        description="Reverse engineering framework (CLI)",
        binaries=("radare2", "r2"),
        delivery="base",
        apt_packages=("radare2",),
        risk_tier=RiskTier.PASSIVE,
        lifecycle=Lifecycle.SUPPORTED,
    ),
    Capability(
        id="binwalk",
        category="reversing",
        description="Firmware analysis and extraction tool",
        binaries=("binwalk",),
        delivery="base",
        apt_packages=("binwalk",),
        risk_tier=RiskTier.PASSIVE,
        lifecycle=Lifecycle.SUPPORTED,
    ),
    # ── Tunneling / pivoting (baked into the base image) ──
    Capability(
        id="chisel",
        category="tunneling",
        description="HTTP-based TCP/UDP tunnel",
        binaries=("chisel",),
        delivery="base",
        apt_packages=("chisel",),
        risk_tier=RiskTier.HIGH_IMPACT,
        phases=("TA0008",),
        lifecycle=Lifecycle.SUPPORTED,
    ),
    Capability(
        id="ligolo-ng",
        category="tunneling",
        description="Layer-3 tun tunnel (no SOCKS required)",
        # Kali's ligolo-ng package ships the proxy (server) + agent as
        # ligolo-proxy / ligolo-agent — there is no ``ligolo-ng`` binary.
        binaries=("ligolo-proxy", "ligolo-agent"),
        delivery="base",
        apt_packages=("ligolo-ng",),
        risk_tier=RiskTier.HIGH_IMPACT,
        phases=("TA0008",),
        lifecycle=Lifecycle.SUPPORTED,
    ),
    # ── Fuzzing (baked into the base image) ──
    Capability(
        id="afl++",
        category="fuzzing",
        description="Coverage-guided fuzzer (american fuzzy lop plus plus)",
        binaries=("afl-fuzz",),
        delivery="base",
        apt_packages=("afl++",),
        risk_tier=RiskTier.INTRUSIVE,
        phases=("TA0002",),
        lifecycle=Lifecycle.SUPPORTED,
    ),
    Capability(
        id="volatility3",
        category="dfir",
        description="Memory forensics framework",
        binaries=("vol",),
        # No apt package in kali-rolling; pip-installed at build time so it
        # is always present and runnable directly via bash.
        delivery="base",
        pip_packages=("volatility3",),
        risk_tier=RiskTier.PASSIVE,
        lifecycle=Lifecycle.SUPPORTED,
    ),
    Capability(
        id="plaso",
        category="dfir",
        description="Super timeline forensic artifact extraction (log2timeline)",
        # Kali prefixes plaso's tools: plaso-log2timeline / plaso-psort / ...
        binaries=("plaso-log2timeline", "plaso-psort", "plaso-pinfo"),
        delivery="base",
        apt_packages=("plaso",),
        risk_tier=RiskTier.PASSIVE,
        lifecycle=Lifecycle.SUPPORTED,
    ),
    # ── Planned (not yet installed — tracked for admission) ──
    Capability(
        id="certipy",
        category="ad",
        description="Active Directory Certificate Services (ADCS) exploitation",
        binaries=("certipy", "certipy-ad"),
        delivery="base",
        apt_packages=("certipy-ad",),
        risk_tier=RiskTier.INTRUSIVE,
        phases=("TA0004", "TA0006"),
        lifecycle=Lifecycle.PLANNED,
    ),
)


# ── Derived indexes ─────────────────────────────────────────────────────


def _build_binary_to_capability() -> dict[str, Capability]:
    """Map every binary name to its owning Capability."""
    index: dict[str, Capability] = {}
    for cap in CAPABILITY_REGISTRY:
        for binary in cap.binaries:
            index[binary] = cap
    return index


BINARY_TO_CAPABILITY: dict[str, Capability] = _build_binary_to_capability()


def capabilities_by_delivery(delivery: str) -> list[Capability]:
    """Return capabilities matching a delivery prefix (e.g. ``base``)."""
    return [c for c in CAPABILITY_REGISTRY if c.delivery.startswith(delivery)]


def capabilities_by_lifecycle(*statuses: Lifecycle) -> list[Capability]:
    """Return capabilities in one or more lifecycle states."""
    allowed = frozenset(statuses)
    return [c for c in CAPABILITY_REGISTRY if c.lifecycle in allowed]


def base_apt_packages() -> list[str]:
    """Return the canonical set of apt packages for the base sandbox image."""
    pkgs: list[str] = []
    for cap in CAPABILITY_REGISTRY:
        if cap.delivery == "base" and cap.lifecycle in (Lifecycle.SUPPORTED, Lifecycle.PREVIEW):
            pkgs.extend(cap.apt_packages)
    return sorted(set(pkgs))


def base_pip_packages() -> list[str]:
    """PyPI packages pip-installed at BUILD time for base-delivery tools.

    These have no apt package, so the sandbox Dockerfile installs them via
    ``pip3 install``. A drift test keeps this in lockstep with that line."""
    pkgs: list[str] = []
    for cap in CAPABILITY_REGISTRY:
        if cap.delivery == "base" and cap.lifecycle in (Lifecycle.SUPPORTED, Lifecycle.PREVIEW):
            pkgs.extend(cap.pip_packages)
    return sorted(set(pkgs))


def base_binaries() -> frozenset[str]:
    """Return every binary name the base image should provide."""
    out: set[str] = set()
    for cap in CAPABILITY_REGISTRY:
        if cap.delivery == "base" and cap.lifecycle in (Lifecycle.SUPPORTED, Lifecycle.PREVIEW):
            out.update(cap.binaries)
    return frozenset(out)


def security_binaries() -> frozenset[str]:
    """Return all security-relevant binaries (any delivery, supported/preview)."""
    out: set[str] = set()
    for cap in CAPABILITY_REGISTRY:
        if cap.lifecycle in (Lifecycle.SUPPORTED, Lifecycle.PREVIEW) and cap.category != "runtime":
            out.update(cap.binaries)
    return frozenset(out)


_RISK_BY_NAME: dict[str, RiskTier] = {tier.name.lower(): tier for tier in RiskTier}


def reach_instruction(cap: Capability) -> str:
    """Human-readable "how do I actually run this" hint for agent discovery.

    Derived from ``lifecycle`` and ``delivery`` so the answer can never
    drift from how the tool is really wired: planned tools are reported as
    not-yet-installed, and installed tools are grouped by delivery (base
    bash binary vs. profile vs. sidecar @tool vs. pip vs. external
    provider), with a base tool's ``requires_service`` surfaced too.
    """
    if cap.lifecycle is Lifecycle.PLANNED:
        return (
            "planned — not pre-installed. Do not assume the binary exists; install "
            "it yourself if the engagement needs it (see the <KALI_ENVIRONMENT> "
            '"Not yet installed" list), then run with bash'
        )
    delivery = cap.delivery
    if delivery == "base":
        if cap.requires_service:
            return (
                f"installed in the sandbox, but needs the '{cap.requires_service}' "
                f"workload running — ask the orchestrator to ops_start it and confirm "
                f"it is running (ops_status) before invoking it with the bash tool"
            )
        return "installed in the sandbox — run it directly with the bash tool"
    if delivery.startswith("profile:"):
        profile = delivery.removeprefix("profile:")
        return (
            f"profile-gated — ask the orchestrator to ops_start the '{profile}' "
            f"profile, then run it with bash"
        )
    if delivery == "sidecar":
        service = cap.requires_service or cap.id
        return (
            f"delivered by the '{service}' sidecar — reach it through the dedicated "
            f"@tool wrappers, NOT bash; request via ops_start first"
        )
    if delivery == "pip":
        return (
            f"not pre-installed — `pip3 install --break-system-packages {cap.id}` "
            f"in the sandbox (externally-managed Python), then run with bash"
        )
    if delivery == "external":
        return "requires an external provider (hardware/GPU/cloud) — not runnable in the sandbox"
    return delivery


def search_capabilities(
    *,
    query: str = "",
    category: str = "",
    phase: str = "",
    max_risk: str | None = None,
    include_planned: bool = False,
    role: str | None = None,
) -> list[Capability]:
    """Query the registry the way an agent would, to find eligible tools.

    All filters are AND-combined and optional:

      * ``query`` — case-insensitive substring over id, category,
        description, and binaries.
      * ``category`` — exact category match (case-insensitive).
      * ``phase`` — MITRE tactic id present in the capability's phases.
      * ``max_risk`` — RiskTier name; excludes anything riskier.
      * ``include_planned`` — also return ``planned`` (not-yet-installed)
        capabilities; by default only ``supported``/``preview`` show.
      * ``role`` — honor a capability's role allowlist when it sets one
        (empty ``roles`` means all roles).

    Raises ``ValueError`` for an unknown ``max_risk`` name.
    """
    allowed = {Lifecycle.SUPPORTED, Lifecycle.PREVIEW}
    if include_planned:
        allowed.add(Lifecycle.PLANNED)

    risk_ceiling: RiskTier | None = None
    if max_risk:
        risk_ceiling = _RISK_BY_NAME.get(max_risk.strip().lower())
        if risk_ceiling is None:
            valid = ", ".join(_RISK_BY_NAME)
            raise ValueError(f"unknown max_risk {max_risk!r}; expected one of: {valid}")

    q = query.strip().lower()
    cat = category.strip().lower()
    ph = phase.strip().lower()

    results: list[Capability] = []
    for cap in CAPABILITY_REGISTRY:
        if cap.lifecycle not in allowed:
            continue
        if cat and cap.category.lower() != cat:
            continue
        if ph and not any(ph == p.lower() for p in cap.phases):
            continue
        if risk_ceiling is not None and cap.risk_tier.value > risk_ceiling.value:
            continue
        if role and cap.roles and role not in cap.roles:
            continue
        if q:
            haystack = " ".join((cap.id, cap.category, cap.description, *cap.binaries)).lower()
            if q not in haystack:
                continue
        results.append(cap)
    return results


@dataclass(frozen=True, slots=True)
class RoleCapabilityPolicy:
    """Per-role discovery defaults for role/phase/risk-aware search.

    ``phases`` are the MITRE tactic ids the role focuses on — used to
    *highlight* (never hide) the tools most relevant to the role.
    ``max_risk`` is the highest risk tier the role reaches for by
    default; discovery applies it as the default ceiling when the agent
    does not pass ``max_risk`` explicitly. It shapes discovery only —
    actual execution stays governed by RoE / HITL, and the agent can
    always widen the search by passing a higher ``max_risk``.
    """

    phases: tuple[str, ...] = ()
    max_risk: RiskTier = RiskTier.HIGH_IMPACT


# Role → discovery policy. Keys match the agent role names in
# ``SLOTS_PER_ROLE``. Roles absent here fall back to no phase highlight
# and no default risk ceiling (the agent sees the full supported set).
ROLE_CAPABILITY_POLICY: dict[str, RoleCapabilityPolicy] = {
    "recon": RoleCapabilityPolicy(phases=("TA0043",), max_risk=RiskTier.BOUNDED_ACTIVE),
    "osint_operator": RoleCapabilityPolicy(phases=("TA0043",), max_risk=RiskTier.PASSIVE),
    "exploit": RoleCapabilityPolicy(phases=("TA0001", "TA0002"), max_risk=RiskTier.INTRUSIVE),
    "postexploit": RoleCapabilityPolicy(
        phases=("TA0004", "TA0006", "TA0008", "TA0011"), max_risk=RiskTier.HIGH_IMPACT
    ),
    "ad_operator": RoleCapabilityPolicy(
        phases=("TA0004", "TA0006", "TA0008"), max_risk=RiskTier.HIGH_IMPACT
    ),
    "cloud_hunter": RoleCapabilityPolicy(phases=("TA0043", "TA0006"), max_risk=RiskTier.INTRUSIVE),
    "reverser": RoleCapabilityPolicy(phases=("TA0002",), max_risk=RiskTier.INTRUSIVE),
    "mobile_operator": RoleCapabilityPolicy(phases=("TA0002",), max_risk=RiskTier.INTRUSIVE),
    "iot_operator": RoleCapabilityPolicy(phases=("TA0002",), max_risk=RiskTier.INTRUSIVE),
    "ics_operator": RoleCapabilityPolicy(phases=("TA0043",), max_risk=RiskTier.BOUNDED_ACTIVE),
    "wireless_operator": RoleCapabilityPolicy(max_risk=RiskTier.INTRUSIVE),
    "phisher": RoleCapabilityPolicy(phases=("TA0001", "TA0006"), max_risk=RiskTier.INTRUSIVE),
    "supply_chain_operator": RoleCapabilityPolicy(
        phases=("TA0043",), max_risk=RiskTier.BOUNDED_ACTIVE
    ),
    "asvs_assessor": RoleCapabilityPolicy(phases=("TA0001",), max_risk=RiskTier.BOUNDED_ACTIVE),
    "forensicator": RoleCapabilityPolicy(max_risk=RiskTier.PASSIVE),
    "analyst": RoleCapabilityPolicy(max_risk=RiskTier.PASSIVE),
    "contract_auditor": RoleCapabilityPolicy(max_risk=RiskTier.INTRUSIVE),
}


def role_capability_policy(role: str | None) -> RoleCapabilityPolicy | None:
    """Return the discovery policy for ``role`` (``None`` if unmapped)."""
    if not role:
        return None
    return ROLE_CAPABILITY_POLICY.get(role)


def prompt_categories() -> dict[str, list[Capability]]:
    """Group supported/preview capabilities by category for prompt generation."""
    groups: dict[str, list[Capability]] = {}
    for cap in CAPABILITY_REGISTRY:
        if cap.lifecycle in (Lifecycle.SUPPORTED, Lifecycle.PREVIEW):
            groups.setdefault(cap.category, []).append(cap)
    return groups


def generate_kali_environment_block() -> str:
    """Generate the ``<KALI_ENVIRONMENT>`` prompt section from the registry.

    The generated block is truthful — it only advertises tools that are
    declared ``supported`` or ``preview`` in the registry, grouped by
    delivery class so agents know what requires a profile activation.
    """
    lines: list[str] = []
    lines.append("<KALI_ENVIRONMENT>")
    lines.append(
        "You are operating inside a Kali Linux sandbox. The following tools are\n"
        "installed and available. You are NOT limited to the tools named in your\n"
        "prompt — if a situation calls for a tool listed here, USE IT.\n"
    )

    # Group by category, base first then profiles
    cats = prompt_categories()
    # Category display names
    cat_labels = {
        "recon": "Recon / enumeration",
        "web": "Web application",
        "vuln": "Vulnerability-specific",
        "credentials": "Credentials / cracking",
        "smb": "SMB / network services",
        "ad": "Active Directory / Kerberos",
        "exploit": "Exploitation frameworks",
        "c2": "Command & Control",
        "tls": "TLS / crypto",
        "secrets": "Secrets / supply chain",
        "network": "Packet capture / network",
        "mobile": "Mobile",
        "dfir": "DFIR / forensics",
        "reversing": "Reverse engineering",
        "tunneling": "Tunneling / pivoting",
        "fuzzing": "Fuzzing",
        "runtime": "Scripting / utilities",
    }

    lines.append("**Base image (always available):**")
    for cat_id in cat_labels:
        caps = [c for c in cats.get(cat_id, []) if c.delivery == "base"]
        if not caps:
            continue
        label = cat_labels.get(cat_id, cat_id)
        tools = ", ".join(sorted({b for c in caps for b in c.binaries}))
        lines.append(f"- **{label}**: {tools}")

    # Profile-gated tools
    profile_caps = [
        c
        for c in CAPABILITY_REGISTRY
        if c.delivery.startswith("profile:")
        and c.lifecycle in (Lifecycle.SUPPORTED, Lifecycle.PREVIEW)
    ]
    if profile_caps:
        lines.append("")
        lines.append("**Profile-gated (request via ops_start before use):**")
        by_profile: dict[str, list[Capability]] = {}
        for c in profile_caps:
            p = c.delivery.removeprefix("profile:")
            by_profile.setdefault(p, []).append(c)
        for profile, caps in sorted(by_profile.items()):
            tools = ", ".join(sorted({b for c in caps for b in c.binaries}))
            lines.append(f"- **{profile}**: {tools}")

    # Sidecar-delivered tools — reachable via dedicated @tool wrappers, NOT bash.
    sidecar_caps = [
        c
        for c in CAPABILITY_REGISTRY
        if c.delivery == "sidecar" and c.lifecycle in (Lifecycle.SUPPORTED, Lifecycle.PREVIEW)
    ]
    if sidecar_caps:
        lines.append("")
        lines.append(
            "**Via dedicated tools (NOT bash — request via ops_start first):** "
            + ", ".join(sorted(c.id for c in sidecar_caps))
        )

    # Planned tools advisory
    planned = capabilities_by_lifecycle(Lifecycle.PLANNED)
    if planned:
        planned_names = ", ".join(sorted(c.id for c in planned))
        lines.append("")
        lines.append(f"**Not yet installed** (use pip/manual install if needed): {planned_names}")

    lines.append("")
    lines.append(
        "**Metasploit is your primary exploit framework.** Before writing custom\n"
        "exploits, ALWAYS check Metasploit for existing modules:\n"
        '  `msfconsole -q -x "search type:exploit <product> <version>; exit"`\n'
        "Use `auxiliary/scanner/*` for deep service enumeration, `exploit/*` for\n"
        "known CVE exploitation, `post/*` for post-exploitation, and `msfvenom`\n"
        "for payload generation. Note: for C2 and persistence, use Sliver.\n"
    )
    lines.append(
        "Be creative. Think like a penetration tester — if the standard approach\n"
        "isn't working, try alternative tools, custom scripts, or chained techniques.\n"
        "You can write and execute Python/Bash scripts on the fly for any task that\n"
        "existing tools don't cover."
    )
    lines.append("</KALI_ENVIRONMENT>")
    return "\n".join(lines)
