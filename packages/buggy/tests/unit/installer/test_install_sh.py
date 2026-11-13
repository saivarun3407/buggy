"""Behavior tests for the Bash installer."""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

REPO_ROOT = Path(__file__).parents[5]
INSTALL_SCRIPT = REPO_ROOT / "scripts" / "install.sh"


def test_stable_resolver_reads_release_payload_from_curl(tmp_path: Path) -> None:
    script_without_main = INSTALL_SCRIPT.read_text(encoding="utf-8").rsplit('\nmain "$@"', 1)[0]
    releases = [
        {
            "tag_name": "v1.2.3",
            "published_at": "2020-01-01T00:00:00Z",
            "draft": False,
            "prerelease": False,
        }
    ]
    harness = tmp_path / "resolve-stable.sh"
    harness.write_text(
        f"""{script_without_main}
curl() {{
    printf '%s' "$RELEASES_JSON"
}}
resolve_stable_soaked
""",
        encoding="utf-8",
    )
    env = os.environ | {
        "BUGGY_STABLE_SOAK_DAYS": "7",
        "RELEASES_JSON": json.dumps(releases),
    }

    completed = subprocess.run(
        ["bash", str(harness)],
        check=True,
        capture_output=True,
        env=env,
        text=True,
    )

    assert completed.stdout.strip() == "1.2.3"


def test_download_files_fetches_tun_overlay(tmp_path: Path) -> None:
    """download_files must pull docker-compose.tun.yml alongside the base
    compose file.

    The opt-in TUN overlay ships in the repo but is useless to release/
    updated installs unless the installer actually downloads it — without
    this fetch those operators can never enable ligolo-ng Layer-3 pivoting.
    A stub curl records every URL download_files requests so we can assert
    the overlay is among them.
    """
    script_without_main = INSTALL_SCRIPT.read_text(encoding="utf-8").rsplit('\nmain "$@"', 1)[0]
    install_dir = tmp_path / "install"
    install_dir.mkdir()
    url_log = tmp_path / "curl-urls.txt"
    harness = tmp_path / "download.sh"
    harness.write_text(
        f"""{script_without_main}
RAW_BASE="https://raw.example/repo/vX"
BUGGY_VERSION="9.9.9"
# Stub network + manifest verification: record each -o download's URL and
# create the destination file so the (untested here) manifest step is a
# no-op. verify_config_manifest is overridden to skip real hashing.
curl() {{
    local url="" out=""
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -o) out="$2"; shift 2 ;;
            -*) shift ;;
            *) url="$1"; shift ;;
        esac
    done
    printf '%s\\n' "$url" >> "$URL_LOG"
    [[ -n "$out" ]] && printf 'stub' > "$out"
    return 0
}}
verify_config_manifest() {{ :; }}
download_files "{install_dir}"
""",
        encoding="utf-8",
    )
    env = os.environ | {"URL_LOG": str(url_log)}

    subprocess.run(
        ["bash", str(harness)],
        check=True,
        capture_output=True,
        env=env,
        text=True,
    )

    urls = url_log.read_text(encoding="utf-8").splitlines()
    assert "https://raw.example/repo/vX/docker-compose.tun.yml" in urls
    assert (install_dir / "docker-compose.tun.yml").is_file()
