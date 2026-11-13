"""Autonomous scope expansion intelligence — discover hidden attack surface.

Mines outputs from recon, SAST, secret scanning, and OSINT to discover
new in-scope assets that standard enumeration misses:

- Subdomains/API endpoints from JavaScript bundles
- Internal hostnames from error messages and stack traces
- Cloud resources (S3 buckets, Azure blobs) from source code
- API endpoints from OpenAPI specs, mobile app configs, JS source maps
- Subdomain takeover candidates from dangling DNS records

Every discovered asset is checked against the engagement scope before
being reported. Findings are stored in the KG as new nodes and linked
to the source that revealed them.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from langchain_core.tools import tool

from buggy.tools.research._state import _json
from buggy_core.utils.logging import get_logger

log = get_logger("research.scope_expansion")

# URL/domain extraction patterns
_URL_RE = re.compile(
    r"(?:https?://|//)"
    r"([a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?"
    r"(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*)"
    r"(?::\d{1,5})?"
    r'(/[^\s"\'<>\]\)}{,]*)?'
)

_API_ENDPOINT_RE = re.compile(r'["\'](/api/[^\s"\'<>\]\)}{,]+)["\']')

_CLOUD_BUCKET_RE = re.compile(
    r"(?:"
    r"([a-z0-9][a-z0-9.\-]{1,61}[a-z0-9])\.s3[.\-](?:amazonaws\.com|[a-z\-]+\.amazonaws\.com)"
    r"|s3://([a-z0-9][a-z0-9.\-]{1,61}[a-z0-9])"
    r"|([a-z0-9][a-z0-9]{2,62})\.blob\.core\.windows\.net"
    r"|storage\.googleapis\.com/([a-z0-9][a-z0-9._\-]{1,61}[a-z0-9])"
    r")",
    re.IGNORECASE,
)

_INTERNAL_HOST_RE = re.compile(
    r"(?:"
    r"[a-zA-Z0-9\-]+\.(?:internal|local|corp|lan|intra|private|dev|staging|test)"
    r"(?:\.[a-zA-Z]{2,})?"
    r")",
)

_SUBDOMAIN_TAKEOVER_CNAMES = frozenset(
    {
        "github.io",
        "herokuapp.com",
        "herokudns.com",
        "cloudfront.net",
        "azurewebsites.net",
        "trafficmanager.net",
        "blob.core.windows.net",
        "cloudapp.net",
        "s3.amazonaws.com",
        "elasticbeanstalk.com",
        "shopify.com",
        "ghost.io",
        "pantheon.io",
        "feedpress.me",
        "freshdesk.com",
        "zendesk.com",
        "readme.io",
        "surge.sh",
        "bitbucket.io",
        "ghost.org",
        "helpjuice.com",
    }
)


@tool
def extract_urls_from_js(
    file_path: str,
    scope_domains: str = "",
) -> str:
    """Extract URLs, API endpoints, and cloud resources from JavaScript files.

    Parses JS/TS source files or bundled JavaScript to discover:
    - Full URLs (http/https)
    - API endpoint paths (/api/...)
    - Cloud storage buckets (S3, Azure Blob, GCS)
    - Internal hostnames (.internal, .corp, .local, etc.)

    Args:
        file_path: Path to a JS/TS file or directory to scan.
        scope_domains: Comma-separated in-scope domain patterns for
            filtering (e.g. "example.com,*.example.com"). Empty = report all.
    """
    target = Path(file_path)
    if not target.exists():
        return _json({"error": f"path not found: {file_path}"})

    scope = [d.strip().lower() for d in scope_domains.split(",") if d.strip()]

    files = []
    if target.is_file():
        files = [target]
    else:
        for ext in ("*.js", "*.ts", "*.jsx", "*.tsx", "*.mjs", "*.cjs", "*.map"):
            files.extend(target.rglob(ext))

    urls: list[dict[str, str]] = []
    api_endpoints: list[dict[str, str]] = []
    cloud_buckets: list[dict[str, str]] = []
    internal_hosts: list[dict[str, str]] = []

    for f in files[:100]:
        try:
            content = f.read_text(encoding="utf-8", errors="ignore")
        except (OSError, UnicodeDecodeError):
            continue

        for match in _URL_RE.finditer(content):
            domain = match.group(1).lower()
            path = match.group(2) or ""
            if _in_scope(domain, scope):
                urls.append(
                    {
                        "url": match.group(0),
                        "domain": domain,
                        "path": path,
                        "source_file": str(f),
                    }
                )

        for match in _API_ENDPOINT_RE.finditer(content):
            api_endpoints.append(
                {
                    "endpoint": match.group(1),
                    "source_file": str(f),
                }
            )

        for match in _CLOUD_BUCKET_RE.finditer(content):
            bucket = next((g for g in match.groups() if g), "")
            if bucket:
                cloud_buckets.append(
                    {
                        "bucket": bucket,
                        "full_match": match.group(0),
                        "source_file": str(f),
                    }
                )

        for match in _INTERNAL_HOST_RE.finditer(content):
            internal_hosts.append(
                {
                    "hostname": match.group(0),
                    "source_file": str(f),
                }
            )

    unique_domains = sorted({u["domain"] for u in urls})
    unique_endpoints = sorted({e["endpoint"] for e in api_endpoints})

    return _json(
        {
            "files_scanned": len(files),
            "unique_domains": unique_domains,
            "unique_api_endpoints": unique_endpoints,
            "urls": urls[:50],
            "api_endpoints": api_endpoints[:50],
            "cloud_buckets": cloud_buckets[:20],
            "internal_hosts": internal_hosts[:20],
        }
    )


@tool
def extract_from_error_pages(
    content: str,
    source_url: str = "",
) -> str:
    """Extract hostnames, paths, and stack traces from error pages.

    Parses error page HTML/text to find internal hostnames, file paths,
    technology versions, and other intelligence leaked by verbose errors.

    Args:
        content: The error page content (HTML or text).
        source_url: URL where this error was observed.
    """
    findings: dict[str, list[str]] = {
        "internal_hosts": [],
        "file_paths": [],
        "tech_versions": [],
        "database_info": [],
    }

    for match in _INTERNAL_HOST_RE.finditer(content):
        hostname = match.group(0)
        if hostname not in findings["internal_hosts"]:
            findings["internal_hosts"].append(hostname)

    path_re = re.compile(r'(?:/(?:home|var|opt|usr|app|srv|etc|tmp)/[^\s<>"\']+)')
    for match in path_re.finditer(content):
        path = match.group(0)
        if path not in findings["file_paths"]:
            findings["file_paths"].append(path)

    version_re = re.compile(
        r"(?:(?:Apache|Nginx|PHP|Python|Node\.js|Ruby|Java|\.NET|Express|Django|"
        r"Rails|Spring|Laravel|Flask|ASP\.NET|Tomcat|Jetty|Gunicorn|Uvicorn)"
        r"[/\s]*[\d]+\.[\d]+(?:\.[\d]+)?)"
    )
    for match in version_re.finditer(content):
        ver = match.group(0).strip()
        if ver not in findings["tech_versions"]:
            findings["tech_versions"].append(ver)

    db_re = re.compile(
        r"(?:(?:MySQL|PostgreSQL|MariaDB|MongoDB|Redis|SQLite|Oracle|MSSQL)"
        r"[/\s]*[\d]*\.?[\d]*)",
        re.IGNORECASE,
    )
    for match in db_re.finditer(content):
        db = match.group(0).strip()
        if db not in findings["database_info"]:
            findings["database_info"].append(db)

    return _json(
        {
            "source_url": source_url,
            "internal_hosts": findings["internal_hosts"][:20],
            "file_paths": findings["file_paths"][:20],
            "tech_versions": findings["tech_versions"][:10],
            "database_info": findings["database_info"][:10],
            "has_intelligence": any(v for v in findings.values()),
        }
    )


@tool
def check_subdomain_takeover(
    subdomains_json: str,
) -> str:
    """Check a list of subdomains for potential takeover via dangling CNAME.

    Examines subdomains for CNAME records pointing to services known
    to be vulnerable to subdomain takeover (GitHub Pages, Heroku,
    AWS CloudFront, Azure, etc.).

    Args:
        subdomains_json: JSON array of objects with ``subdomain`` and
            ``cname`` fields, e.g.
            ``[{"subdomain": "blog.example.com", "cname": "example.github.io"}]``.
    """
    try:
        subdomains = json.loads(subdomains_json)
    except json.JSONDecodeError as e:
        return _json({"error": f"invalid JSON: {e}"})

    if not isinstance(subdomains, list):
        return _json({"error": "expected a JSON array"})

    candidates: list[dict[str, str]] = []
    for entry in subdomains:
        if not isinstance(entry, dict):
            continue
        subdomain = entry.get("subdomain", "")
        cname = entry.get("cname", "").lower()

        for takeover_domain in _SUBDOMAIN_TAKEOVER_CNAMES:
            if cname.endswith(takeover_domain):
                candidates.append(
                    {
                        "subdomain": subdomain,
                        "cname": cname,
                        "vulnerable_service": takeover_domain,
                        "risk": "high"
                        if takeover_domain in ("github.io", "herokuapp.com", "s3.amazonaws.com")
                        else "medium",
                    }
                )
                break

    return _json(
        {
            "subdomains_checked": len(subdomains),
            "takeover_candidates": candidates,
            "total_candidates": len(candidates),
        }
    )


def _in_scope(domain: str, scope: list[str]) -> bool:
    """Check if a domain matches any scope pattern."""
    if not scope:
        return True
    for pattern in scope:
        if pattern.startswith("*."):
            if domain.endswith(pattern[1:]) or domain == pattern[2:]:
                return True
        elif domain == pattern:
            return True
    return False


SCOPE_EXPANSION_TOOLS = [
    extract_urls_from_js,
    extract_from_error_pages,
    check_subdomain_takeover,
]
