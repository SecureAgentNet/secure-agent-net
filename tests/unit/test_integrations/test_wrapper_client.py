from unittest.mock import MagicMock

from secureagentnet.integrations.wrappers.client import InterceptClient, secureagentnet_intercept


def test_intercept_client_success(tmp_path, monkeypatch):
    monkeypatch.setenv("SAN_DATA_DIR", str(tmp_path))
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"status": "success", "correlation_id": "corr-1"}
    mock_resp.raise_for_status.return_value = None
    monkeypatch.setattr("requests.post", lambda *args, **kwargs: mock_resp)

    client = InterceptClient(host="127.0.0.1", port=17541)
    result = client.intercept("agent-1", "read_file", "/tmp/x", "read file")
    assert result["status"] == "success"


def test_secureagentnet_intercept_helper(tmp_path, monkeypatch):
    monkeypatch.setenv("SAN_DATA_DIR", str(tmp_path))
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"status": "blocked", "correlation_id": "corr-2", "reason": "unauthorized"}
    mock_resp.raise_for_status.return_value = None
    monkeypatch.setattr("requests.post", lambda *args, **kwargs: mock_resp)

    result = secureagentnet_intercept("agent-1", "execute", "shell", "run shell")
    assert result["status"] == "blocked"
