import hvac
import pytest
from unittest.mock import MagicMock, patch
from src.track.vault_client import VaultAuditClient


class TestVaultAuditClient:
    @pytest.fixture
    def mock_hvac(self, monkeypatch):
        mock_client = MagicMock()
        mock_client.is_authenticated.return_value = True
        mock_client.secrets.transit.read_key.return_value = {"data": {"name": "audit-log-key"}}
        mock_client.secrets.transit.generate_hmac.return_value = {
            "data": {"hmac": "hmac:sha256:abc123def456"}
        }
        mock_client.secrets.kv.v2.create_or_update_secret.return_value = {
            "data": {"version": 3}
        }
        monkeypatch.setattr("hvac.Client", lambda url=None, token=None: mock_client)
        monkeypatch.setattr("src.track.vault_client.hvac.Client", lambda url=None, token=None: mock_client)
        return mock_client

    @pytest.fixture
    def client(self, mock_hvac):
        return VaultAuditClient()

    def test_secure_log(self, client, mock_hvac):
        log_data = {
            "log_id": "log-001",
            "agent_id": "agent-1",
            "action": "read_file",
            "decision": "APPROVE",
        }
        receipt = client.secure_log(log_data)
        assert receipt is not None
        assert receipt.startswith("vault-")
        assert "v3" in receipt
        mock_hvac.secrets.kv.v2.create_or_update_secret.assert_called_once()

    def test_secure_log_kwargs(self, client, mock_hvac):
        log_data = {
            "log_id": "log-002",
            "agent_id": "agent-2",
            "action": "execute_sql",
        }
        client.secure_log(log_data)
        call_kwargs = mock_hvac.secrets.kv.v2.create_or_update_secret.call_args
        assert call_kwargs[1]["path"] == "audit/agents/agent-2/log-002"
        assert call_kwargs[1]["secret"]["log_id"] == "log-002"
        assert call_kwargs[1]["secret"]["agent_id"] == "agent-2"
        assert call_kwargs[1]["secret"]["action"] == "execute_sql"
        assert call_kwargs[1]["secret"]["_hmac"] == "hmac:sha256:abc123def456"

    def test_secure_log_no_client(self):
        with patch("src.track.vault_client.VaultAuditClient.__init__", return_value=None):
            client = VaultAuditClient.__new__(VaultAuditClient)
            client.client = None
            client.settings = MagicMock()
            log_data = {"log_id": "log-003", "agent_id": "agent-3"}
            result = client.secure_log(log_data)
            assert result is None

    @patch("src.track.vault_client.hvac.Client")
    def test_secure_log_client_init_failure(self, mock_hvac_class):
        mock_hvac_class.side_effect = Exception("Connection refused")
        client = VaultAuditClient()
        assert client.client is None
        result = client.secure_log({"log_id": "x", "agent_id": "y"})
        assert result is None

    def test_secure_log_api_error(self, client, mock_hvac):
        mock_hvac.secrets.kv.v2.create_or_update_secret.side_effect = Exception("API error")
        log_data = {"log_id": "log-004", "agent_id": "agent-4"}
        result = client.secure_log(log_data)
        assert result is None

    def test_secure_log_unknown_agent_default(self, client, mock_hvac):
        log_data = {"log_id": "log-005"}
        client.secure_log(log_data)
        call_kwargs = mock_hvac.secrets.kv.v2.create_or_update_secret.call_args
        assert call_kwargs[1]["path"] == "audit/agents/unknown_agent/log-005"
        assert call_kwargs[1]["secret"]["_hmac"] == "hmac:sha256:abc123def456"

    def test_secure_log_returns_version_receipt(self, client, mock_hvac):
        log_data = {"log_id": "log-006", "agent_id": "agent-6"}
        receipt = client.secure_log(log_data)
        assert receipt == "vault-audit/agents/agent-6/log-006-v3"

    def test_sign_log(self, client, mock_hvac):
        log_data = {"log_id": "log-007", "agent_id": "agent-7"}
        hmac = client.sign_log(log_data)
        assert hmac == "hmac:sha256:abc123def456"
        mock_hvac.secrets.transit.generate_hmac.assert_called_once()

    def test_sign_log_no_transit(self, client, mock_hvac):
        client._transit_ready = False
        result = client.sign_log({"test": "data"})
        assert result is None

    def test_verify_log_valid(self, client, mock_hvac):
        mock_hvac.secrets.transit.verify_hmac.return_value = {
            "data": {"valid": True}
        }
        result = client.verify_log({"test": "data"}, "hmac:sha256:abc123")
        assert result is True
        mock_hvac.secrets.transit.verify_hmac.assert_called_once()

    def test_verify_log_invalid(self, client, mock_hvac):
        mock_hvac.secrets.transit.verify_hmac.return_value = {
            "data": {"valid": False}
        }
        result = client.verify_log({"test": "data"}, "hmac:sha256:badhmac")
        assert result is False

    def test_verify_log_no_transit(self, client, mock_hvac):
        client._transit_ready = False
        result = client.verify_log({"test": "data"}, "hmac:abc")
        assert result is False

    def test_retrieve_log(self, client, mock_hvac):
        mock_hvac.secrets.kv.v2.read_secret_version.return_value = {
            "data": {"data": {"log_id": "log-008", "_hmac": "hmac:abc"}}
        }
        result = client.retrieve_log("vault-audit/agents/agent-8/log-008-v1")
        assert result == {"log_id": "log-008", "_hmac": "hmac:abc"}

    def test_retrieve_log_bad_receipt(self, client, mock_hvac):
        result = client.retrieve_log("bad-receipt")
        assert result is None

    def test_verify_receipt_valid(self, client, mock_hvac):
        mock_hvac.secrets.kv.v2.read_secret_version.return_value = {
            "data": {"data": {"test": "data", "_hmac": "hmac:sha256:abc123"}}
        }
        mock_hvac.secrets.transit.verify_hmac.return_value = {
            "data": {"valid": True}
        }
        result = client.verify_receipt("vault-path-v1")
        assert result["valid"] is True
        assert result["log"] == {"test": "data"}

    def test_verify_receipt_invalid(self, client, mock_hvac):
        mock_hvac.secrets.kv.v2.read_secret_version.return_value = {
            "data": {"data": {"test": "data", "_hmac": "hmac:sha256:badhmac"}}
        }
        mock_hvac.secrets.transit.verify_hmac.return_value = {
            "data": {"valid": False}
        }
        result = client.verify_receipt("vault-path-v1")
        assert result["valid"] is False

    def test_verify_receipt_no_hmac(self, client, mock_hvac):
        mock_hvac.secrets.kv.v2.read_secret_version.return_value = {
            "data": {"data": {"test": "data"}}
        }
        result = client.verify_receipt("vault-path-v1")
        assert result["valid"] is False
        assert "No HMAC" in result["error"]

    def test_verify_receipt_not_found(self, client, mock_hvac):
        mock_hvac.secrets.kv.v2.read_secret_version.side_effect = Exception("not found")
        result = client.verify_receipt("vault-path-v1")
        assert result["valid"] is False
        assert "not found" in result["error"]

    def test_ensure_transit_key_creates_when_missing(self, monkeypatch):
        mock_client = MagicMock()
        mock_client.is_authenticated.return_value = True
        mock_client.secrets.transit.read_key.side_effect = hvac.exceptions.InvalidPath("not found")
        monkeypatch.setattr("hvac.Client", lambda url=None, token=None: mock_client)
        monkeypatch.setattr("src.track.vault_client.hvac.Client", lambda url=None, token=None: mock_client)
        c = VaultAuditClient()
        assert c._transit_ready is True
        mock_client.secrets.transit.create_key.assert_called_once_with(
            name="audit-log-key", key_type="hmac", key_size=0,
        )
