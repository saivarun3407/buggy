"""Drift guards binding the capability registry to its consumers.

The registry (:mod:`buggy_core.capabilities`) only prevents the
"prompt promises tools the image lacks" class of bug if the image, the
telemetry allowlist, and the generated prompt are all held in lockstep
with it. These tests are the lockstep:

  * ``base`` apt packages in the registry == the sandbox Dockerfile's
    canonical install block.
  * every registry-shipped security binary is capturable by the
    privacy-preserving telemetry allowlist.
  * the agent prompt's Kali section is registry-generated and truthful.
"""

from __future__ import annotations

import dataclasses
import re
from pathlib import Path

import pytest

from buggy.runtime.programs import KNOWN_PROGRAMS
from buggy_core.capabilities import (
    Capability,
    base_apt_packages,
    base_pip_packages,
    security_binaries,
)

_REPO_ROOT = Path(__file__).resolve().parents[3]
_SANDBOX_DOCKERFILE = _REPO_ROOT / "containers" / "sandbox.Dockerfile"
_SKILLS_ROOT = _REPO_ROOT / "packages" / "buggy" / "buggy" / "skills"


# A Debian package token: starts alphanumeric, then alnum/./+/-.  This
# deliberately excludes shell noise (``&&``, ``;``, ``{}``, sed strings)
# and apt flags (``--no-install-recommends``).
_PKG_TOKEN = re.compile(r"^[a-z0-9][a-z0-9.+-]*$")


def _dockerfile_base_packages() -> set[str]:
    """Parse the canonical apt-install package block from the sandbox
    Dockerfile — the shell-line-continuation run of ``apt-get install``
    that contains ``nmap`` (the bootstrap ``ca-certificates`` block does
    not)."""
    text = _SANDBOX_DOCKERFILE.read_text(encoding="utf-8")
    lines = text.splitlines()

    blocks: list[set[str]] = []
    capturing = False
    pkgs: set[str] = set()

    for raw in lines:
        stripped = raw.strip()
        # Docker strips whole-line ``#`` comments before joining line
        # continuations, so a comment line inside an install list is
        # transparent — neither starts, ends, nor contributes to a list.
        if stripped.startswith("#"):
            continue

        body = raw.split("#", 1)[0]
        if "apt-get install" in body:
            # Start a fresh install list (drops any prior && / ; command).
            capturing = True
            pkgs = set()

        if capturing:
            for token in body.replace("\\", " ").split():
                if token in ("apt-get", "install") or token.startswith("-"):
                    continue
                if _PKG_TOKEN.match(token):
                    pkgs.add(token)

            # A command separator (``&&``/``;``) ends THIS install list even
            # if the shell line continues, and so does a line without a
            # trailing backslash.
            if "&&" in body or ";" in body or not body.rstrip().endswith("\\"):
                blocks.append(pkgs)
                capturing = False

    for candidate in blocks:
        if "nmap" in candidate:
            return candidate
    raise AssertionError("could not locate canonical apt-install block")


def test_registry_base_matches_dockerfile() -> None:
    """The registry's ``base`` apt set must equal the sandbox image's
    canonical install block — no drift in either direction."""
    registry = set(base_apt_packages())
    dockerfile = _dockerfile_base_packages()

    missing_from_image = registry - dockerfile
    missing_from_registry = dockerfile - registry

    assert not missing_from_image, (
        "capabilities declared base but NOT installed in sandbox.Dockerfile: "
        f"{sorted(missing_from_image)}"
    )
    assert not missing_from_registry, (
        "packages installed in sandbox.Dockerfile but NOT in the capability "
        f"registry: {sorted(missing_from_registry)} — add a Capability entry."
    )


def test_shipped_binaries_are_telemetry_capturable() -> None:
    """Every security binary the platform ships must be in the telemetry
    allowlist, or its usage is invisible to under-use analysis.

    ``extract_programs`` lowercases command basenames, so capturability is
    checked against the lowercased binary name (e.g. the camelCase
    impacket-GetNPUsers is stored as impacket-getnpusers)."""
    uncapturable = {b for b in security_binaries() if b.lower() not in KNOWN_PROGRAMS}
    assert not uncapturable, (
        "registry ships these security binaries but runtime/programs.py "
        f"cannot capture them: {sorted(uncapturable)}"
    )


def test_prompt_kali_section_is_registry_generated() -> None:
    """The builder must derive the Kali section from the registry, not the
    old hard-coded 'full Kali' string."""
    from buggy.agents.prompts import builder

    block = builder._KALI_ENVIRONMENT
    assert "<KALI_ENVIRONMENT>" in block
    # The retired false claim must be gone.
    assert "full Kali Linux distribution" not in block
    assert "Every tool in the" not in block
    # A real installed tool from the tranche is advertised.
    assert "nuclei" in block


def test_prompt_does_not_advertise_uninstalled_tools() -> None:
    """No PLANNED/uninstalled tool may appear in the prompt's installed
    section (regression guard for the original prompt/image mismatch)."""
    from buggy.agents.prompts import builder

    block = builder._KALI_ENVIRONMENT
    installed_section = block.split("**Not yet installed**")[0]
    for uninstalled in ("certipy",):
        assert uninstalled not in installed_section, (
            f"{uninstalled} is not installed but appears in the prompt's installed section"
        )


def test_ghidra_not_advertised_as_bash_binary() -> None:
    """Ghidra lives in the ghidra-mcp sidecar, not the bash sandbox. The
    prompt must reach it only through the dedicated-tools section, never as
    an installed base/profile bash command (regression for the review
    finding that profile tools were unreachable)."""
    from buggy.agents.prompts import builder

    block = builder._KALI_ENVIRONMENT
    base_and_profile = block.split("**Via dedicated tools")[0]
    assert "ghidra" not in base_and_profile.lower(), (
        "ghidra is sidecar-delivered and must not appear as a bash binary"
    )
    assert "**Via dedicated tools" in block
    assert "ghidra" in block  # still discoverable via the dedicated-tools line


def test_impacket_prompt_uses_real_executable_names() -> None:
    """The AD section must advertise the real impacket-prefixed commands,
    not the non-existent ``secretsdump.py`` names."""
    from buggy.agents.prompts import builder

    block = builder._KALI_ENVIRONMENT
    assert "impacket-secretsdump" in block
    assert "impacket-ntlmrelayx" in block
    assert "secretsdump.py" not in block


def _dockerfile_build_pip_packages() -> set[str]:
    """Parse every package named in a build-time ``pip3 install`` RUN in the
    sandbox Dockerfile (the baked-pip delivery path)."""
    text = _SANDBOX_DOCKERFILE.read_text(encoding="utf-8")
    lines = text.splitlines()

    pkgs: set[str] = set()
    capturing = False
    for raw in lines:
        stripped = raw.strip()
        if stripped.startswith("#"):
            continue
        body = raw.split("#", 1)[0]
        if "pip3 install" in body or "pip install" in body:
            capturing = True
        if capturing:
            for token in body.replace("\\", " ").split():
                # Strip surrounding quotes and any version specifier so a
                # pin like "volatility3>=2" matches the registry name.
                cleaned = token.strip("'\"")
                name = re.split(r"[<>=!~\[]", cleaned, maxsplit=1)[0]
                if _PKG_TOKEN.match(name) and name not in (
                    "pip",
                    "pip3",
                    "install",
                    "python3",
                    "python",
                ):
                    pkgs.add(name)
            if not body.rstrip().endswith("\\"):
                capturing = False
    return pkgs


def test_registry_base_pip_matches_dockerfile() -> None:
    """Every base tool delivered via a build-time pip install (no apt
    package, e.g. volatility3) must actually be pip-installed in the
    sandbox image — no drift between registry ``pip_packages`` and the
    Dockerfile's ``pip3 install`` lines."""
    registry = set(base_pip_packages())
    dockerfile = _dockerfile_build_pip_packages()
    missing_from_image = registry - dockerfile
    assert not missing_from_image, (
        "capabilities declared base+pip but NOT pip-installed in "
        f"sandbox.Dockerfile: {sorted(missing_from_image)}"
    )


def test_dockerfile_block_parse_sane() -> None:
    """Guard the parser itself — it must find a plausible package set."""
    pkgs = _dockerfile_base_packages()
    assert "nmap" in pkgs
    assert "yara" in pkgs
    assert 30 < len(pkgs) < 80


# ── Skill ↔ registry command-name parity ────────────────────────────────
# When a tool is baked into the base image (Phase B: chisel, ligolo-ng,
# plaso, volatility3), the skills that teach agents how to run it must name
# the ACTUAL binary the image installs — otherwise the promoted tool ships
# but every skill points agents at a command that does not exist, and the
# tool is effectively unusable. These are the pre-promotion invocation
# forms that must never come back.
_FORBIDDEN_SKILL_INVOCATIONS = {
    # Ligolo-ng ships as ligolo-proxy / ligolo-agent on Kali; the old
    # upstream-release names (./proxy, ./agent) are not on PATH.
    r"\./proxy\b": "ligolo-proxy",
    r"\./agent\b": "ligolo-agent",
    # chisel is on PATH — no ./chisel dropped-binary form.
    r"\./chisel\b": "chisel",
    # volatility3 installs the `vol` entrypoint, not a `volatility3` command,
    # and not the `vol3` shorthand some upstream docs use.
    r"\bvolatility3\s+-f\b": "vol -f",
    r"\bvol3\s+-f\b": "vol -f",
    # Kali prefixes plaso commands; the bare backtick-code forms are stale.
    r"`log2timeline`": "plaso-log2timeline",
    r"`psort`": "plaso-psort",
}


def _skill_files() -> list[Path]:
    return sorted(_SKILLS_ROOT.rglob("SKILL.md"))


def test_skills_use_real_baked_in_command_names() -> None:
    """No skill may invoke a promoted base tool under a name the image does
    not install (regression for Phase B making the tools reachable)."""
    offenders: list[str] = []
    for skill in _skill_files():
        text = skill.read_text(encoding="utf-8")
        for pattern, correct in _FORBIDDEN_SKILL_INVOCATIONS.items():
            if re.search(pattern, text):
                rel = skill.relative_to(_REPO_ROOT)
                offenders.append(f"{rel}: {pattern!r} → use {correct!r}")
    assert not offenders, "skills invoke tools under non-installed names:\n" + "\n".join(offenders)


def test_promoted_tool_binaries_are_documented() -> None:
    """The tunneling/DFIR skills that were flagged must now positively name
    the real registry binaries, so the fix can't silently regress to a
    tool-free workflow."""
    lateral = (
        _SKILLS_ROOT / "standard" / "post-exploit" / "lateral-movement" / "SKILL.md"
    ).read_text(encoding="utf-8")
    for binary in ("ligolo-proxy", "ligolo-agent", "chisel server", "chisel client"):
        assert binary in lateral, f"lateral-movement skill no longer documents {binary!r}"

    rootkit = (_SKILLS_ROOT / "standard" / "reverser" / "rootkit-analysis" / "SKILL.md").read_text(
        encoding="utf-8"
    )
    assert "vol -f" in rootkit, "rootkit-analysis skill no longer runs volatility via `vol`"

    dfir = (_SKILLS_ROOT / "standard" / "dfir" / "SKILL.md").read_text(encoding="utf-8")
    assert "plaso-log2timeline" in dfir, "dfir skill no longer names plaso-log2timeline"


def test_capability_pip_packages_is_last_field() -> None:
    """``pip_packages`` must stay the LAST dataclass field so it never
    shifts the positional constructor contract of the pre-existing fields
    (regression for the Phase B review finding that inserting it before
    ``risk_tier`` silently reassigned positional args)."""
    field_names = [f.name for f in dataclasses.fields(Capability)]
    assert field_names[-1] == "pip_packages", (
        "pip_packages must be the last Capability field to preserve the "
        f"positional argument order; got {field_names}"
    )
    # The pre-existing positional contract up to risk_tier must be intact.
    assert field_names[:7] == [
        "id",
        "category",
        "description",
        "binaries",
        "delivery",
        "apt_packages",
        "risk_tier",
    ], f"positional field order changed: {field_names}"


@pytest.mark.parametrize("package", ["volatility3", "fastapi", "curl_cffi"])
def test_sandbox_pip_preserves_distro_owned_packages(package: str) -> None:
    dockerfile = _SANDBOX_DOCKERFILE.read_text(encoding="utf-8")
    commands = re.findall(r"^RUN pip3 install[^\n]+", dockerfile.replace("\\\n", " "), re.MULTILINE)
    install = next(command for command in commands if f'"{package}>=' in command)
    assert "--ignore-installed" in install.split()
