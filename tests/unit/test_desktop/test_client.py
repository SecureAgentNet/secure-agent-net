import json
from unittest.mock import MagicMock

import pytest

from secureagentnet.desktop.client import DaemonClient


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("SAN_DATA_DIR", str(tmp_path))
    return DaemonClient(host="127.0.0.1", port=17541)


def test_status(client, monkeypatch):
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"status": "ok", "agents_total": 2, "threats_blocked": 1}
    mock_resp.raise_for_status.return_value = None
    monkeypatch.setattr(client._session, "get", lambda *args, **kwargs: mock_resp)

    status = client.status()
    assert status["agents_total"] == 2
    assert status["threats_blocked"] == 1


def test_agent_contracts(client, monkeypatch):
    mock_resp = MagicMock()
    mock_resp.json.return_value = [{
        "agent_id": "finance-001", "framework": "langchain",
        "project_name": "FinanceOps",
    }]
    mock_resp.raise_for_status.return_value = None
    monkeypatch.setattr(client._session, "get", lambda *args, **kwargs: mock_resp)

    contracts = client.agent_contracts()

    assert contracts[0]["project_name"] == "FinanceOps"


def test_intercept_success(client, monkeypatch):
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "status": "blocked",
        "correlation_id": "abc-123",
        "reason": "blocked by policy",
    }
    mock_resp.raise_for_status.return_value = None
    monkeypatch.setattr(client._session, "post", lambda *args, **kwargs: mock_resp)

    result = client.intercept("agent-1", "execute", "shell", "run command", {"command": "ls"})
    assert result["status"] == "blocked"
    assert result["correlation_id"] == "abc-123"


def test_is_alive_failure(client, monkeypatch):
    def raise_exc(*args, **kwargs):
        raise Exception("connection refused")
    monkeypatch.setattr(client._session, "get", raise_exc)
    assert client.is_alive() is False


def test_session_is_pooled_and_reused(client):
    """Every call must go through one keep-alive session, not a fresh connection."""
    import requests

    assert isinstance(client._session, requests.Session)
    adapter = client._session.get_adapter("http://127.0.0.1:17541")
    assert adapter.poolmanager.connection_pool_kw.get("maxsize") == 8
    assert client._session.headers["Connection"] == "keep-alive"


def test_recent_events_backfill(client, monkeypatch):
    mock_resp = MagicMock()
    mock_resp.json.return_value = [
        {"timestamp": "2026-08-31T10:25:57", "agent_id": "a-1", "phase": "IDENTIFY",
         "event_type": "capability_denied", "severity": "WARNING", "detail": "denied"},
    ]
    mock_resp.raise_for_status.return_value = None
    monkeypatch.setattr(client._session, "get", lambda *a, **k: mock_resp)

    events = client.recent_events(50)
    assert events[0]["event_type"] == "capability_denied"


def test_recent_events_returns_empty_when_daemon_is_down(client, monkeypatch):
    def raise_exc(*args, **kwargs):
        raise Exception("connection refused")
    monkeypatch.setattr(client._session, "get", raise_exc)
    assert client.recent_events() == []
