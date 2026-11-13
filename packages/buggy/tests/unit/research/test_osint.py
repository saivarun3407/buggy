"""Unit tests for the OSINT enrichment tool.

Network egress is exercised through ``httpx.MockTransport`` (no real
sockets); synthetic mock/catalog findings require explicit development opt-in.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import httpx
import pytest

from buggy.tools.research import osint
from buggy.tools.research.osint import (
    _is_in_scope,
    _load_mock_catalog,
    _merge_findings,
    _new_findings,
    _normalize_domain,
    _parse_censys,
    _parse_shodan,
    _parse_zoomeye,
    osint_enrich,
)

_CRED_ENV = (
    "SHODAN_API_KEY",
    "CENSYS_API_ID",
    "CENSYS_API_SECRET",
    "ZOOMEYE_API_KEY",
    "BUGGY_OSINT_SCOPE",
    "BUGGY_OSINT_CATALOG",
    "BUGGY_OSINT_ALLOW_MOCK",
)


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Isolate every test from credentials / scope leaking from the host."""
    for name in _CRED_ENV:
        monkeypatch.delenv(name, raising=False)


def _install_async_transport(monkeypatch: pytest.MonkeyPatch, handler: Any) -> None:
    """Wire ``httpx.AsyncClient`` to a ``MockTransport`` so the tool's
    internally constructed client never touches the network."""
    transport = httpx.MockTransport(handler)
    real_client = httpx.AsyncClient

    def _fake(*args: Any, **kwargs: Any) -> httpx.AsyncClient:
        kwargs.pop("timeout", None)
        return real_client(*args, transport=transport, timeout=5.0, **kwargs)

    monkeypatch.setattr(httpx, "AsyncClient", _fake)


def _assert_status_metadata(data: dict[str, Any], status: str) -> None:
    assert data["status"] == status
    assert data["evidence_usable"] is (status == "ok")
    observed_at = datetime.fromisoformat(data["observed_at"])
    assert observed_at.utcoffset() == timedelta(0)
    now = datetime.now(timezone.utc)
    assert now - timedelta(minutes=1) <= observed_at <= now


# ── Domain normalization ─────────────────────────────────────────────────


class TestNormalizeDomain:
    def test_strips_scheme_path_and_port(self) -> None:
        assert _normalize_domain("https://api.example.com:443/path?q=1") == "api.example.com"

    def test_lowercases_and_trims(self) -> None:
        assert _normalize_domain("  Example.COM.  ") == "example.com"

    def test_empty(self) -> None:
        assert _normalize_domain("") == ""


# ── Scope rules ──────────────────────────────────────────────────────────


class TestScope:
    def test_empty_scope_allows_everything(self) -> None:
        assert _is_in_scope("example.com", []) is True

    def test_exact_match(self) -> None:
        assert _is_in_scope("example.com", ["example.com"]) is True

    def test_wildcard_matches_only_direct_subdomain(self) -> None:
        assert _is_in_scope("api.example.com", ["*.example.com"]) is True
        assert _is_in_scope("example.com", ["*.example.com"]) is False
        assert _is_in_scope("a.b.example.com", ["*.example.com"]) is False

    def test_out_of_scope(self) -> None:
        assert _is_in_scope("evil.test", ["*.example.com"]) is False


# ── Findings merge / dedupe ──────────────────────────────────────────────


class TestMerge:
    def test_dedupes_ports_and_dict_records(self) -> None:
        dst = _new_findings()
        _merge_findings(dst, {"open_ports": [{"port": 80}, {"port": 80}, {"port": 443}]})
        _merge_findings(dst, {"open_ports": [{"port": 443}]})
        assert dst["open_ports"] == [{"port": 80}, {"port": 443}]


# ── Parsers ──────────────────────────────────────────────────────────────


class TestParsers:
    def test_parse_shodan(self) -> None:
        host = {
            "matches": [
                {
                    "ip_str": "203.0.113.5",
                    "port": 443,
                    "transport": "tcp",
                    "data": "HTTP/1.1 200 OK",
                    "ssl": {
                        "cert": {
                            "subject": {"CN": "example.com"},
                            "issuer": {"CN": "Let's Encrypt"},
                            "expires": "20301231235959Z",
                            "fingerprint": {"sha256": "deadbeef"},
                        }
                    },
                }
            ]
        }
        dns = {
            "domain": "example.com",
            "data": [{"subdomain": "www", "type": "A", "value": "203.0.113.5"}],
        }
        out = _parse_shodan(host, dns)
        assert {"port": 443, "transport": "tcp"} in out["open_ports"]
        assert out["certificates"][0]["subject_cn"] == "example.com"
        assert out["certificates"][0]["fingerprint_sha256"] == "deadbeef"
        assert out["banners"][0]["banner"] == "HTTP/1.1 200 OK"
        assert out["dns_records"][0]["value"] == "203.0.113.5"

    def test_parse_censys(self) -> None:
        data = {
            "result": {
                "hits": [
                    {
                        "ip": "203.0.113.6",
                        "services": [
                            {
                                "port": 80,
                                "service_name": "HTTP",
                                "banner": "Server: nginx",
                                "transport_protocol": "TCP",
                            }
                        ],
                        "dns": {"names": ["example.com"]},
                    }
                ]
            }
        }
        out = _parse_censys(data)
        assert {"port": 80, "transport": "tcp"} in out["open_ports"]
        assert out["banners"][0]["service"] == "HTTP"
        assert out["dns_records"][0]["name"] == "example.com"

    def test_parse_zoomeye(self) -> None:
        data = {
            "matches": [
                {
                    "ip": "203.0.113.7",
                    "portinfo": {"port": 22, "service": "ssh", "banner": "SSH-2.0-OpenSSH"},
                }
            ]
        }
        out = _parse_zoomeye(data)
        assert {"port": 22, "transport": "tcp"} in out["open_ports"]
        assert out["banners"][0]["service"] == "ssh"


# ── Mock catalog ─────────────────────────────────────────────────────────


class TestMockCatalog:
    @pytest.mark.parametrize("catalog_path", [None, "unused-catalog.json"])
    def test_disabled_catalog_has_no_findings(
        self, monkeypatch: pytest.MonkeyPatch, catalog_path: str | None
    ) -> None:
        if catalog_path is not None:
            monkeypatch.setenv("BUGGY_OSINT_CATALOG", catalog_path)

        def _no_read(*_args: Any, **_kwargs: Any) -> Any:
            raise AssertionError("mock catalogs must not be read without explicit opt-in")

        monkeypatch.setattr(osint.Path, "read_text", _no_read)
        assert _load_mock_catalog("example.com") == _new_findings()

    def test_default_is_deterministic(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("BUGGY_OSINT_ALLOW_MOCK", "true")
        a = _load_mock_catalog("example.com")
        b = _load_mock_catalog("example.com")
        assert a == b
        assert {"port": 443, "transport": "tcp"} in a["open_ports"]
        assert a["certificates"][0]["subject_cn"] == "example.com"

    def test_catalog_file_override(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        monkeypatch.setenv("BUGGY_OSINT_ALLOW_MOCK", "true")
        catalog = {
            "target.test": {
                "open_ports": [{"port": 8080, "transport": "tcp"}],
                "dns_records": [{"type": "A", "name": "target.test", "value": "198.51.100.9"}],
            }
        }
        f = tmp_path / "catalog.json"
        f.write_text(json.dumps(catalog), encoding="utf-8")
        monkeypatch.setenv("BUGGY_OSINT_CATALOG", str(f))
        out = _load_mock_catalog("target.test")
        assert out["open_ports"] == [{"port": 8080, "transport": "tcp"}]
        assert out["dns_records"][0]["value"] == "198.51.100.9"

    def test_catalog_file_unusable_falls_back(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        monkeypatch.setenv("BUGGY_OSINT_ALLOW_MOCK", "true")
        monkeypatch.setattr(logging.getLogger("buggy"), "propagate", True)
        f = tmp_path / "broken.json"
        f.write_text("{not json", encoding="utf-8")
        monkeypatch.setenv("BUGGY_OSINT_CATALOG", str(f))
        with caplog.at_level("WARNING", logger="buggy"):
            out = _load_mock_catalog("example.com")
        # Falls back to the deterministic synthesized catalog.
        assert {"port": 443, "transport": "tcp"} in out["open_ports"]
        assert str(f) not in caplog.text


# ── Tool: offline / mock path ────────────────────────────────────────────


class TestToolOffline:
    @pytest.mark.parametrize("allow_mock", [None, "", "0", "false", "FALSE", "no", "off", "other"])
    async def test_no_credentials_reports_unavailable(
        self, monkeypatch: pytest.MonkeyPatch, allow_mock: str | None
    ) -> None:
        if allow_mock is not None:
            monkeypatch.setenv("BUGGY_OSINT_ALLOW_MOCK", allow_mock)
        monkeypatch.setenv("BUGGY_OSINT_CATALOG", "unused-catalog.json")

        def _no_egress(*_args: Any, **_kwargs: Any) -> Any:
            raise AssertionError("unconfigured sources must not use network or mock catalogs")

        monkeypatch.setattr(httpx, "AsyncClient", _no_egress)
        monkeypatch.setattr(osint, "_load_mock_catalog", _no_egress)
        before = datetime.now(timezone.utc)
        data = json.loads(await osint_enrich.ainvoke({"domain": "example.com"}))

        assert data["sources"] == []
        assert data["domain"] == "example.com"
        assert data["in_scope"] is True
        assert data["status"] == "unavailable"
        assert data["evidence_usable"] is False
        assert {key: data[key] for key in _new_findings()} == _new_findings()
        assert data["source_status"] == {
            name: {"configured": False, "status": "unavailable"}
            for name in ("shodan", "censys", "zoomeye")
        }
        observed_at = datetime.fromisoformat(data["observed_at"])
        assert observed_at.utcoffset() == timedelta(0)
        assert before <= observed_at <= datetime.now(timezone.utc)
        assert "errors" not in data

    @pytest.mark.parametrize("allow_mock", ["1", "true", "TRUE", " yes ", "on", " On "])
    async def test_no_credentials_uses_mock_catalog(
        self, monkeypatch: pytest.MonkeyPatch, allow_mock: str
    ) -> None:
        monkeypatch.setenv("BUGGY_OSINT_ALLOW_MOCK", allow_mock)
        raw = await osint_enrich.ainvoke({"domain": "example.com"})
        data = json.loads(raw)
        _assert_status_metadata(data, "mock")
        assert data["in_scope"] is True
        assert data["sources"] == ["mock"]
        assert data["source_status"] == {
            "shodan": {"configured": False, "status": "unavailable"},
            "censys": {"configured": False, "status": "unavailable"},
            "zoomeye": {"configured": False, "status": "unavailable"},
            "mock": {"configured": True, "status": "mock"},
        }
        assert data["open_ports"]
        assert data["certificates"]
        assert data["dns_records"]
        assert data["banners"]
        assert "errors" not in data

    async def test_catalog_override_is_labeled_mock(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        catalog = tmp_path / "catalog.json"
        findings = _new_findings()
        findings["open_ports"] = [{"port": 8080, "transport": "tcp"}]
        catalog.write_text(json.dumps({"example.com": findings}), encoding="utf-8")
        monkeypatch.setenv("BUGGY_OSINT_CATALOG", str(catalog))
        monkeypatch.setenv("BUGGY_OSINT_ALLOW_MOCK", "true")

        data = json.loads(await osint_enrich.ainvoke({"domain": "example.com"}))

        _assert_status_metadata(data, "mock")
        assert data["sources"] == ["mock"]
        assert {key: data[key] for key in findings} == findings

    @pytest.mark.parametrize("credential", ["CENSYS_API_ID", "CENSYS_API_SECRET"])
    async def test_partial_censys_credentials_are_unavailable(
        self, monkeypatch: pytest.MonkeyPatch, credential: str
    ) -> None:
        monkeypatch.setenv(credential, "sentinel-incomplete-credential")

        def _no_egress(*_args: Any, **_kwargs: Any) -> Any:
            raise AssertionError("incomplete credentials must not cause network egress")

        monkeypatch.setattr(httpx, "AsyncClient", _no_egress)
        raw = await osint_enrich.ainvoke({"domain": "example.com"})
        data = json.loads(raw)

        _assert_status_metadata(data, "unavailable")
        assert data["sources"] == []
        assert {key: data[key] for key in _new_findings()} == _new_findings()
        assert data["source_status"]["censys"] == {"configured": False, "status": "unavailable"}
        assert "sentinel-incomplete-credential" not in raw

    def test_tool_arguments_do_not_offer_a_mock_switch(self) -> None:
        assert set(osint_enrich.args) == {"domain"}

    async def test_normalizes_domain_in_output(self) -> None:
        raw = await osint_enrich.ainvoke({"domain": "https://example.com:443/x"})
        assert json.loads(raw)["domain"] == "example.com"

    async def test_empty_domain_errors(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("SHODAN_API_KEY", "test-key")
        monkeypatch.setenv("BUGGY_OSINT_ALLOW_MOCK", "true")

        def _no_egress(*_args: Any, **_kwargs: Any) -> Any:
            raise AssertionError("empty targets must not use network or mock catalogs")

        monkeypatch.setattr(httpx, "AsyncClient", _no_egress)
        monkeypatch.setattr(osint, "_load_mock_catalog", _no_egress)
        data = json.loads(await osint_enrich.ainvoke({"domain": "   "}))

        assert data["error"] == "no domain provided"
        _assert_status_metadata(data, "error")
        assert data["domain"] == ""
        assert data["in_scope"] is False
        assert data["sources"] == []
        assert {key: data[key] for key in _new_findings()} == _new_findings()
        assert data["errors"] == ["no domain provided"]
        assert data["source_status"] == {
            "shodan": {"configured": True, "status": "unavailable"},
            "censys": {"configured": False, "status": "unavailable"},
            "zoomeye": {"configured": False, "status": "unavailable"},
        }


# ── Tool: scope enforcement ──────────────────────────────────────────────


class TestToolScope:
    async def test_out_of_scope_refused_without_egress(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("SHODAN_API_KEY", "test-key")
        monkeypatch.setenv("BUGGY_OSINT_ALLOW_MOCK", "true")
        monkeypatch.setenv("BUGGY_OSINT_SCOPE", "*.example.com")

        def _explode(*_a: Any, **_k: Any) -> Any:
            raise AssertionError("no network egress allowed for out-of-scope target")

        monkeypatch.setattr(httpx, "AsyncClient", _explode)
        monkeypatch.setattr(osint, "_load_mock_catalog", _explode)
        raw = await osint_enrich.ainvoke({"domain": "evil.test"})
        data = json.loads(raw)
        assert data["in_scope"] is False
        assert "out of scope" in data["error"]
        assert data["scope_patterns"] == ["*.example.com"]
        _assert_status_metadata(data, "error")
        assert data["sources"] == []
        assert {key: data[key] for key in _new_findings()} == _new_findings()
        assert data["errors"] == [data["error"]]
        assert data["source_status"] == {
            "shodan": {"configured": True, "status": "unavailable"},
            "censys": {"configured": False, "status": "unavailable"},
            "zoomeye": {"configured": False, "status": "unavailable"},
        }

    async def test_in_scope_wildcard_allowed(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("BUGGY_OSINT_ALLOW_MOCK", "true")
        monkeypatch.setenv("BUGGY_OSINT_SCOPE", "*.example.com")
        raw = await osint_enrich.ainvoke({"domain": "api.example.com"})
        data = json.loads(raw)
        assert data["in_scope"] is True
        assert data["sources"] == ["mock"]

    async def test_refusal_is_logged(
        self, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
    ) -> None:
        monkeypatch.setenv("BUGGY_OSINT_SCOPE", "example.com")
        # The "buggy" root logger sets propagate=False, so let caplog's
        # handler see records by re-enabling propagation for the duration.
        monkeypatch.setattr(logging.getLogger("buggy"), "propagate", True)
        with caplog.at_level("WARNING", logger="buggy"):
            await osint_enrich.ainvoke({"domain": "evil.test"})
        assert any("out of target scope" in r.getMessage() for r in caplog.records)


# ── Tool: live source path (mocked transport) ────────────────────────────


def _shodan_handler(request: httpx.Request) -> httpx.Response:
    if "/dns/domain/" in request.url.path:
        return httpx.Response(
            200,
            json={
                "domain": "example.com",
                "data": [{"subdomain": "www", "type": "A", "value": "203.0.113.5"}],
            },
        )
    return httpx.Response(
        200,
        json={
            "matches": [
                {
                    "ip_str": "203.0.113.5",
                    "port": 443,
                    "transport": "tcp",
                    "data": "HTTP/1.1 200 OK",
                    "ssl": {
                        "cert": {"subject": {"CN": "example.com"}, "fingerprint": {"sha256": "abc"}}
                    },
                }
            ]
        },
    )


class TestToolLive:
    async def test_all_configured_sources_fail_without_fabricated_findings(
        self, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
    ) -> None:
        credentials = {
            "SHODAN_API_KEY": "sentinel-shodan-key",
            "CENSYS_API_ID": "sentinel-censys-id",
            "CENSYS_API_SECRET": "sentinel-censys-secret",
            "ZOOMEYE_API_KEY": "sentinel-zoomeye-key",
        }
        for name, value in credentials.items():
            monkeypatch.setenv(name, value)
        monkeypatch.setattr(logging.getLogger("buggy"), "propagate", True)
        requests = []

        def _fail(request: httpx.Request) -> httpx.Response:
            requests.append(request)
            return httpx.Response(503, json={"error": "sensitive-response-body"})

        _install_async_transport(monkeypatch, _fail)
        with caplog.at_level("WARNING", logger="buggy"):
            raw = await osint_enrich.ainvoke({"domain": "example.com"})
        data = json.loads(raw)

        _assert_status_metadata(data, "error")
        assert data["sources"] == []
        assert {key: data[key] for key in _new_findings()} == _new_findings()
        assert len(requests) == 3
        for credential in credentials.values():
            assert credential not in raw + caplog.text
        assert "sensitive-response-body" not in raw + caplog.text
        assert "key=" not in raw + caplog.text
        assert data["source_status"] == {
            name: {"configured": True, "status": "error", "error": f"{name}: HTTP 503"}
            for name in ("shodan", "censys", "zoomeye")
        }
        assert data["errors"] == ["shodan: HTTP 503", "censys: HTTP 503", "zoomeye: HTTP 503"]

    @pytest.mark.parametrize(
        ("failure", "message"),
        [
            (httpx.ReadTimeout, "request timed out"),
            (httpx.ConnectError, "request failed"),
            (ValueError, "invalid response"),
            (KeyError, "invalid response"),
            (TypeError, "invalid response"),
            (AttributeError, "invalid response"),
        ],
    )
    async def test_source_errors_are_safe_strings(
        self,
        monkeypatch: pytest.MonkeyPatch,
        caplog: pytest.LogCaptureFixture,
        failure: type[Exception],
        message: str,
    ) -> None:
        monkeypatch.setenv("SHODAN_API_KEY", "sentinel-shodan-key")
        monkeypatch.setattr(logging.getLogger("buggy"), "propagate", True)

        def _fail(request: httpx.Request) -> httpx.Response:
            raise failure(f"sensitive-response-body from {request.url}")

        _install_async_transport(monkeypatch, _fail)
        with caplog.at_level("WARNING", logger="buggy"):
            raw = await osint_enrich.ainvoke({"domain": "example.com"})
        data = json.loads(raw)

        _assert_status_metadata(data, "error")
        assert data["sources"] == []
        assert {key: data[key] for key in _new_findings()} == _new_findings()
        assert "sentinel-shodan-key" not in raw + caplog.text
        assert "sensitive-response-body" not in raw + caplog.text
        assert data["errors"] == [f"shodan: {message}"]
        assert data["source_status"] == {
            "shodan": {"configured": True, "status": "error", "error": f"shodan: {message}"},
            "censys": {"configured": False, "status": "unavailable"},
            "zoomeye": {"configured": False, "status": "unavailable"},
        }

    @pytest.mark.parametrize("allow_mock", ["0", "1"])
    async def test_empty_responses_are_not_mock_evidence(
        self, monkeypatch: pytest.MonkeyPatch, allow_mock: str
    ) -> None:
        monkeypatch.setenv("BUGGY_OSINT_ALLOW_MOCK", allow_mock)
        for name in _CRED_ENV[:4]:
            monkeypatch.setenv(name, "test-credential")

        _install_async_transport(monkeypatch, lambda request: httpx.Response(200, json={}))
        data = json.loads(await osint_enrich.ainvoke({"domain": "example.com"}))

        _assert_status_metadata(data, "empty")
        assert data["sources"] == ["shodan", "censys", "zoomeye"]
        assert {key: data[key] for key in _new_findings()} == _new_findings()
        assert data["source_status"] == {
            name: {"configured": True, "status": "empty"}
            for name in ("shodan", "censys", "zoomeye")
        }
        assert "errors" not in data

    @pytest.mark.parametrize("allow_mock", ["0", "1"])
    async def test_mixed_provider_outcomes_preserve_only_real_findings(
        self, monkeypatch: pytest.MonkeyPatch, allow_mock: str
    ) -> None:
        monkeypatch.setenv("BUGGY_OSINT_ALLOW_MOCK", allow_mock)
        for name in _CRED_ENV[:4]:
            monkeypatch.setenv(name, "test-credential")

        def _mixed(request: httpx.Request) -> httpx.Response:
            if request.url.host == "api.shodan.io":
                return _shodan_handler(request)
            if request.url.host == "search.censys.io":
                return httpx.Response(200, json={"result": {"hits": []}})
            return httpx.Response(403, json={"error": "denied"})

        _install_async_transport(monkeypatch, _mixed)
        data = json.loads(await osint_enrich.ainvoke({"domain": "example.com"}))

        _assert_status_metadata(data, "ok")
        assert data["sources"] == ["shodan", "censys"]
        assert data["open_ports"] == [{"port": 443, "transport": "tcp"}]
        assert data["certificates"][0]["subject_cn"] == "example.com"
        assert len(data["certificates"]) == len(data["dns_records"]) == len(data["banners"]) == 1
        assert data["source_status"] == {
            "shodan": {"configured": True, "status": "ok"},
            "censys": {"configured": True, "status": "empty"},
            "zoomeye": {"configured": True, "status": "error", "error": "zoomeye: HTTP 403"},
        }
        assert data["errors"] == ["zoomeye: HTTP 403"]

    async def test_empty_success_with_failure_reports_partial_empty(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("SHODAN_API_KEY", "test-key")
        monkeypatch.setenv("CENSYS_API_ID", "test-id")
        monkeypatch.setenv("CENSYS_API_SECRET", "test-secret")

        def _partial(request: httpx.Request) -> httpx.Response:
            status = 503 if request.url.host == "api.shodan.io" else 200
            return httpx.Response(status, json={})

        _install_async_transport(monkeypatch, _partial)
        data = json.loads(await osint_enrich.ainvoke({"domain": "example.com"}))

        _assert_status_metadata(data, "empty")
        assert data["sources"] == ["censys"]
        assert {key: data[key] for key in _new_findings()} == _new_findings()
        assert data["source_status"] == {
            "shodan": {"configured": True, "status": "error", "error": "shodan: HTTP 503"},
            "censys": {"configured": True, "status": "empty"},
            "zoomeye": {"configured": False, "status": "unavailable"},
        }
        assert data["errors"] == ["shodan: HTTP 503"]

    async def test_shodan_live_path(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("SHODAN_API_KEY", "secret")
        _install_async_transport(monkeypatch, _shodan_handler)
        raw = await osint_enrich.ainvoke({"domain": "example.com"})
        data = json.loads(raw)
        _assert_status_metadata(data, "ok")
        assert data["sources"] == ["shodan"]
        assert data["source_status"] == {
            "shodan": {"configured": True, "status": "ok"},
            "censys": {"configured": False, "status": "unavailable"},
            "zoomeye": {"configured": False, "status": "unavailable"},
        }
        assert {"port": 443, "transport": "tcp"} in data["open_ports"]
        assert data["certificates"][0]["subject_cn"] == "example.com"
        assert data["dns_records"][0]["value"] == "203.0.113.5"
        assert "errors" not in data

    async def test_live_failure_captured_and_falls_back_to_mock(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("BUGGY_OSINT_ALLOW_MOCK", "true")
        monkeypatch.setenv("SHODAN_API_KEY", "secret")

        def _fail(_request: httpx.Request) -> httpx.Response:
            return httpx.Response(500, json={"error": "boom"})

        _install_async_transport(monkeypatch, _fail)
        raw = await osint_enrich.ainvoke({"domain": "example.com"})
        data = json.loads(raw)
        # Shodan errored, so no live source succeeded -> mock fallback.
        assert data["sources"] == ["mock"]
        assert data["errors"]
        assert "shodan" in data["errors"][0]
        _assert_status_metadata(data, "mock")
        assert data["source_status"] == {
            "shodan": {"configured": True, "status": "error", "error": "shodan: HTTP 500"},
            "censys": {"configured": False, "status": "unavailable"},
            "zoomeye": {"configured": False, "status": "unavailable"},
            "mock": {"configured": True, "status": "mock"},
        }
        assert data["errors"] == ["shodan: HTTP 500"]

    async def test_fetch_shodan_direct(self) -> None:
        transport = httpx.MockTransport(_shodan_handler)
        async with httpx.AsyncClient(transport=transport) as client:
            out = await osint._fetch_shodan(client, "example.com", "key")
        assert {"port": 443, "transport": "tcp"} in out["open_ports"]
        assert out["dns_records"][0]["value"] == "203.0.113.5"
