"""Host/endpoint normalization shared by dedupe paths.

Pure string helpers — no buggy imports — so both the report-time
dedupe pass (``tools.research.dedupe``) and the write-time canonical key
(``tools.reporting.kg_adapter``) can share one normalization rule without
an import cycle.
"""

from __future__ import annotations

import re


def normalize_host(raw: str) -> str:
    """Reduce a host-ish string to a bare, comparable hostname.

    Strips a URL scheme, any ``user@`` prefix, a path/query tail, and a
    trailing ``:port`` so ``https://API.example.com:443/x`` and
    ``api.example.com`` collapse to the same token.
    """
    if not raw:
        return ""
    value = raw.strip().lower()
    value = re.sub(r"^[a-z][a-z0-9+.\-]*://", "", value)
    value = value.split("@", 1)[-1]
    value = value.split("/", 1)[0]
    value = value.split("?", 1)[0]
    if value.count(":") == 1:
        value = value.split(":", 1)[0]
    return value.rstrip(".")


def normalize_endpoint(raw: str) -> str:
    """Reduce an endpoint-ish string to ``host/path`` without scheme/port/query.

    Query strings and fragments are dropped (different agents word the same
    endpoint with different parameter values) so the path identity is what
    drives overlap.
    """
    if not raw:
        return ""
    value = raw.strip().lower()
    value = re.sub(r"^[a-z][a-z0-9+.\-]*://", "", value)
    value = value.split("@", 1)[-1]
    value = value.split("?", 1)[0]
    value = value.split("#", 1)[0]
    if "/" in value:
        authority, _, path = value.partition("/")
        if authority.count(":") == 1:
            authority = authority.split(":", 1)[0]
        value = f"{authority}/{path}"
    elif value.count(":") == 1:
        value = value.split(":", 1)[0]
    return value.rstrip("/")


__all__ = ["normalize_endpoint", "normalize_host"]
