from __future__ import annotations

import importlib
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

app_module = importlib.import_module("buggy.sandbox_server.app")


def test_defensive_workflow_route_requires_the_daemon_token(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(app_module, "_required_token", "workflow-fixture")
    response = TestClient(app_module.app).post(
        "/workflows",
        json={"workspace_path": "/workspace/client-one", "action": "catalog", "payload": {}},
    )
    assert response.status_code == 401


def test_capability_inspection_requires_the_daemon_token(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(app_module, "_required_token", "capability-fixture")
    with TestClient(app_module.app, backend="asyncio") as client:
        monkeypatch.setattr(app_module, "_required_token", "capability-fixture")
        assert client.get("/capabilities").status_code == 401


@pytest.mark.parametrize(
    "workflow",
    ["network-inventory", "dns-inventory", "tls-inspection", "http-capture-review", "sarif-review"],
)
def test_defensive_workflow_artifacts_round_trip_through_authenticated_http(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    workflow: str,
) -> None:
    import json

    asset = "https://api.example.test/"
    stamp = "2025-01-02T03:04:05Z"
    artifacts = {
        "network-inventory": '<?xml version="1.0"?><nmaprun scanner="nmap" version="7.95"><host><status state="up"/><address addr="192.0.2.10" addrtype="ipv4"/><hostnames><hostname name="api.example.test" type="user"/></hostnames><ports><port protocol="tcp" portid="443"><state state="open"/><service name="https"/></port></ports></host><runstats><finished exit="success"/><hosts up="1" down="0" total="1"/></runstats></nmaprun>',
        "dns-inventory": {
            "schema_version": 1,
            "kind": "dns-observation",
            "asset": asset,
            "observed_at": stamp,
            "queries": [
                {
                    "name": "api.example.test",
                    "type": "A",
                    "status": "NOERROR",
                    "answers": [
                        {"name": "api.example.test", "type": "A", "value": "192.0.2.10", "ttl": 60}
                    ],
                }
            ],
        },
        "tls-inspection": {
            "schema_version": 1,
            "kind": "tls-observation",
            "asset": asset,
            "observed_at": stamp,
            "peer_ip": "192.0.2.10",
            "server_name": "api.example.test",
            "port": 443,
            "handshake": "completed",
            "certificate_validation": "valid",
            "protocol": "TLSv1.3",
            "cipher": "TLS_AES_256_GCM_SHA384",
            "certificate_sha256": "a" * 64,
            "not_before": "2024-01-01T00:00:00Z",
            "not_after": "2026-01-01T00:00:00Z",
        },
        "http-capture-review": {
            "source": "capture",
            "url": asset,
            "method": "GET",
            "captured_at": stamp,
            "status_code": 200,
            "headers": {"X-Content-Type-Options": "nosniff"},
        },
        "sarif-review": {
            "version": "2.1.0",
            "properties": {"asset": asset},
            "runs": [
                {
                    "tool": {"driver": {"name": "fixture-scanner"}},
                    "invocations": [{"executionSuccessful": True, "exitCode": 0}],
                    "results": [],
                }
            ],
        },
    }
    workspace = tmp_path / "workflow-fixture"
    workspace.mkdir()
    value = artifacts[workflow]
    (workspace / "input.txt").write_text(value if isinstance(value, str) else json.dumps(value))
    monkeypatch.setenv("SANDBOX_ROOT_DIR", str(tmp_path))
    monkeypatch.setattr(app_module, "_required_token", "workflow-fixture-token")
    client = TestClient(app_module.app)
    headers = {"Authorization": "Bearer workflow-fixture-token"}
    capabilities = client.get("/capabilities", headers=headers)
    assert capabilities.status_code == 200
    assert len(capabilities.json()["capabilities"]) == 5
    response = client.post(
        "/workflows",
        headers=headers,
        json={
            "workspace_path": "/workspace/workflow-fixture",
            "action": "run",
            "payload": {
                "workflow_id": workflow,
                "url": asset,
                "artifact_path": "input.txt",
                "observe": False,
            },
        },
    )
    assert response.status_code == 200, response.text
    result = response.json()
    assert result["workflow_id"] == workflow
    assert result["status"] in {"observed", "inconclusive"}
    assert result["baseline_coverage_updated"] is False
    report = client.post(
        "/workflows",
        headers=headers,
        json={
            "workspace_path": "/workspace/workflow-fixture",
            "action": "report",
            "payload": {"run_id": result["run_id"]},
        },
    )
    assert report.status_code == 200
    assert report.json()["run_id"] == result["run_id"]
    client.close()


def test_assessment_initialization_persists_in_the_selected_workspace(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SANDBOX_ROOT_DIR", str(tmp_path))
    monkeypatch.setattr(app_module, "_required_token", "assessment-fixture")
    client = TestClient(app_module.app)
    response = client.post(
        "/assessment",
        headers={"Authorization": "Bearer assessment-fixture"},
        json={
            "workspace_path": "/workspace/client-one",
            "action": "initialize",
            "payload": {
                "engagement_name": "client-one",
                "profile": "external",
                "allowed_hosts": ["app.example.test"],
            },
        },
    )
    assert response.status_code == 200
    assert (tmp_path / "client-one" / "assessment" / "coverage.sqlite3").is_file()
    report = client.post(
        "/assessment",
        headers={"Authorization": "Bearer assessment-fixture"},
        json={"workspace_path": "/workspace/client-one", "action": "report", "payload": {}},
    )
    assert report.status_code == 200
    assert report.json()["complete"] is False


@pytest.mark.parametrize(
    "workspace", ["", "/tmp", "/workspace/../elsewhere", "/workspace/a/../../b", "/workspace/a\\b"]
)
def test_assessment_rejects_invalid_workspaces_without_creating_state(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, workspace: str
) -> None:
    monkeypatch.setenv("SANDBOX_ROOT_DIR", str(tmp_path))
    monkeypatch.setattr(app_module, "_required_token", None)
    client = TestClient(app_module.app)
    response = client.post(
        "/assessment", json={"workspace_path": workspace, "action": "initialize", "payload": {}}
    )
    assert response.status_code == 422
    assert not list(tmp_path.iterdir())


def test_assessment_requires_the_daemon_bearer_token(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SANDBOX_ROOT_DIR", str(tmp_path))
    monkeypatch.setattr(app_module, "_required_token", "assessment-fixture")
    response = TestClient(app_module.app).post(
        "/assessment",
        json={"workspace_path": "/workspace/client-one", "action": "initialize", "payload": {}},
    )
    assert response.status_code == 401
    assert not list(tmp_path.iterdir())


def test_assessment_rejects_symlinked_workspace_escapes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "sandbox"
    outside = tmp_path / "outside"
    root.mkdir()
    outside.mkdir()
    (root / "client-one").symlink_to(outside, target_is_directory=True)
    monkeypatch.setenv("SANDBOX_ROOT_DIR", str(root))
    monkeypatch.setattr(app_module, "_required_token", None)
    response = TestClient(app_module.app).post(
        "/assessment",
        json={"workspace_path": "/workspace/client-one", "action": "initialize", "payload": {}},
    )
    assert response.status_code == 422
    assert not list(outside.iterdir())


def test_missing_assessment_is_an_error_not_an_empty_success(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SANDBOX_ROOT_DIR", str(tmp_path))
    monkeypatch.setattr(app_module, "_required_token", None)
    response = TestClient(app_module.app).post(
        "/assessment", json={"workspace_path": "/workspace", "action": "report", "payload": {}}
    )
    assert response.status_code == 422
    assert not list(tmp_path.iterdir())


def test_assessment_endpoint_refuses_arbitrary_action_names(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(app_module, "_required_token", None)
    response = TestClient(app_module.app).post(
        "/assessment", json={"workspace_path": "/workspace", "action": "execute", "payload": {}}
    )
    assert response.status_code == 422
