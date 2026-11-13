"""Unit tests for the active DAST crawler tools.

No live HTTP calls — httpx is monkeypatched.
"""

from __future__ import annotations

import json
from typing import Any
from unittest.mock import MagicMock, patch

import httpx

from buggy.tools.research import dast_crawler as dc

# ── Helpers ──────────────────────────────────────────────────────────────


def _mock_response(
    text: str = "", status_code: int = 200, content_type: str = "text/html"
) -> MagicMock:
    resp = MagicMock(spec=httpx.Response)
    resp.status_code = status_code
    resp.text = text
    resp.headers = httpx.Headers({"content-type": content_type})
    resp.elapsed = MagicMock()
    resp.elapsed.total_seconds.return_value = 0.1
    return resp


def _mock_client(
    responses: dict[str, MagicMock] | None = None, default_resp: MagicMock | None = None
) -> MagicMock:
    client = MagicMock()
    client.__enter__ = lambda self: client

    def _exit(*a: Any) -> bool:
        return False

    client.__exit__ = _exit

    if responses:

        def _get(url: str, **kw: Any) -> MagicMock:
            return responses.get(url, default_resp or _mock_response())

        def _post(url: str, **kw: Any) -> MagicMock:
            return responses.get(url, default_resp or _mock_response())

        client.get = MagicMock(side_effect=_get)
        client.post = MagicMock(side_effect=_post)
    else:
        client.get.return_value = default_resp or _mock_response()
        client.post.return_value = default_resp or _mock_response()
    return client


# ── Link extraction ──────────────────────────────────────────────────────


class TestExtractLinks:
    def test_basic_links(self) -> None:
        html = '<a href="/about">About</a><a href="/contact">Contact</a>'
        links = dc._extract_links(html, "https://example.com/")
        assert "https://example.com/about" in links
        assert "https://example.com/contact" in links

    def test_external_filtered(self) -> None:
        html = '<a href="https://evil.com/steal">X</a><a href="/safe">S</a>'
        links = dc._extract_links(html, "https://example.com/")
        assert not any("evil.com" in lnk for lnk in links)
        assert "https://example.com/safe" in links

    def test_relative_links(self) -> None:
        html = '<a href="page2.html">Next</a>'
        links = dc._extract_links(html, "https://example.com/docs/")
        assert "https://example.com/docs/page2.html" in links


class TestExtractForms:
    def test_simple_form(self) -> None:
        html = (
            '<form action="/search" method="GET">'
            '<input name="q" type="text">'
            '<input name="page" type="hidden">'
            "</form>"
        )
        forms = dc._extract_forms(html, "https://example.com/")
        assert len(forms) == 1
        assert forms[0]["action"] == "https://example.com/search"
        assert forms[0]["method"] == "GET"
        assert len(forms[0]["inputs"]) == 2


# ── Crawl ────────────────────────────────────────────────────────────────


class TestDastCrawl:
    def test_bad_url(self) -> None:
        result = json.loads(dc.dast_crawl.invoke({"base_url": "not-a-url"}))
        assert result["error"] == "bad_request"

    def test_basic_crawl(self) -> None:
        page1 = _mock_response(
            '<html><a href="/page2">P2</a></html>',
            content_type="text/html",
        )
        page2 = _mock_response(
            "<html><p>End</p></html>",
            content_type="text/html",
        )
        client = _mock_client(
            responses={
                "https://example.com": page1,
                "https://example.com/page2": page2,
            }
        )
        with patch("buggy.tools.research.dast_crawler.httpx.Client", return_value=client):
            result = json.loads(dc.dast_crawl.invoke({"base_url": "https://example.com"}))
        assert result["pages_crawled"] >= 1
        urls = [ep["url"] for ep in result["endpoints"]]
        assert "https://example.com" in urls


# ── Injection testing ────────────────────────────────────────────────────


class TestDastTestEndpoints:
    def test_invalid_json(self) -> None:
        result = json.loads(dc.dast_test_endpoints.invoke({"endpoints_json": "bad"}))
        assert result["error"] == "json_parse_error"

    def test_sqli_detection(self) -> None:
        error_resp = _mock_response(
            "ERROR: You have an error in your SQL syntax near",
            status_code=500,
        )
        client = _mock_client(default_resp=error_resp)
        endpoints = [{"url": "https://example.com/api", "method": "GET", "params": ["id"]}]
        with patch("buggy.tools.research.dast_crawler.httpx.Client", return_value=client):
            result = json.loads(
                dc.dast_test_endpoints.invoke(
                    {
                        "endpoints_json": json.dumps(endpoints),
                        "vuln_types": "sqli",
                    }
                )
            )
        assert result["total_findings"] >= 1
        assert result["findings"][0]["vulnerability_type"] == "sqli"

    def test_xss_reflection(self) -> None:
        reflected_resp = _mock_response(
            "<html>Results for: <script>alert(1)</script></html>",
        )
        client = _mock_client(default_resp=reflected_resp)
        endpoints = [{"url": "https://example.com/search", "method": "GET", "params": ["q"]}]
        with patch("buggy.tools.research.dast_crawler.httpx.Client", return_value=client):
            result = json.loads(
                dc.dast_test_endpoints.invoke(
                    {
                        "endpoints_json": json.dumps(endpoints),
                        "vuln_types": "xss",
                    }
                )
            )
        assert result["total_findings"] >= 1


class TestDastTestSingle:
    def test_bad_url(self) -> None:
        result = json.loads(
            dc.dast_test_single.invoke(
                {
                    "url": "not-a-url",
                    "parameter": "id",
                }
            )
        )
        assert result["error"] == "bad_request"

    def test_no_findings(self) -> None:
        clean_resp = _mock_response("<html>Clean response</html>")
        client = _mock_client(default_resp=clean_resp)
        with patch("buggy.tools.research.dast_crawler.httpx.Client", return_value=client):
            result = json.loads(
                dc.dast_test_single.invoke(
                    {
                        "url": "https://example.com/api",
                        "parameter": "id",
                        "vuln_types": "sqli",
                    }
                )
            )
        assert result["total_findings"] == 0
        assert result["tests_run"] >= 1
