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
    monkeypatch.setattr("requests.get", lambda *args, **kwargs: mock_resp)

    status = client.status()
    assert status["agents_total"] == 2
    assert status["threats_blocked"] == 1


def test_intercept_success(client, monkeypatch):
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "status": "blocked",
        "correlation_id": "abc-123",
        "reason": "blocked by policy",
    }
    mock_resp.raise_for_status.return_value = None
    monkeypatch.setattr("requests.post", lambda *args, **kwargs: mock_resp)

    result = client.intercept("agent-1", "execute", "shell", "run command", {"command": "ls"})
    assert result["status"] == "blocked"
    assert result["correlation_id"] == "abc-123"


def test_is_alive_failure(client, monkeypatch):
    def raise_exc(*args, **kwargs):
        raise Exception("connection refused")
    monkeypatch.setattr("requests.get", raise_exc)
    assert client.is_alive() is False
