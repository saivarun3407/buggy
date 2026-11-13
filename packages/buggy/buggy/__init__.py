"""Buggy — AI-powered autonomous red team testing framework."""

import os as _os
from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as _version

try:
    # pyproject.toml carries a "0.0.0" sentinel; release.yml stamps the
    # real tag into the package metadata at Docker build time, and
    # importlib.metadata reads it back here. Local checkouts read 0.0.0.
    __version__ = _version("buggy")
except PackageNotFoundError:
    __version__ = "0.0.0"

__package_name__ = "buggy"

# Phase 2 framework boot — register OSS roles with RoleRegistry,
# materialize the PluginRegistry singleton, and surface the legacy
# import paths via the compat shim. All idempotent / opt-out via env.
#
# The sandbox container ships only a subset of buggy (sandbox_kernel
# + sandbox_server + bare __init__.py) without buggy-core installed,
# so it must opt out of the full framework boot. The sandbox.Dockerfile
# sets BUGGY_SKIP_BOOT=1 in its ENV so this import doesn't fail.
if not _os.environ.get("BUGGY_SKIP_BOOT"):
    from buggy import _boot, compat

    _boot.run()
    compat.register_legacy_imports()
