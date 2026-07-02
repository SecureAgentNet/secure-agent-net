import pytest
from unittest.mock import MagicMock, patch
from secureagentnet.contain.secret_injector import DynamicSecretInjector, get_secret_injector


class TestDynamicSecretInjector:
    def setup_method(self):
        self.injector = DynamicSecretInjector()
        self.injector._injected_secrets.clear()

    def test_is_available_without_vault(self, monkeypatch):
        monkeypatch.setattr(
            "secureagentnet.contain.secret_injector.VaultAuditClient",
            lambda: (_ for _ in ()).throw(RuntimeError("no vault")),
        )
        inj = DynamicSecretInjector()
        assert inj.is_available() is False

    def test_fetch_secrets_returns_empty_when_unavailable(self):
        inj = DynamicSecretInjector()
        inj._vault = None
        secrets = inj.fetch_secrets("agent-1")
        assert secrets == {}

    def test_fetch_secrets_returns_data(self):
        inj = DynamicSecretInjector()
        mock_client = MagicMock()
        mock_client.secrets.kv.v2.read_secret_version.return_value = {
            "data": {"data": {"API_KEY": "sk-123", "DB_PASS": "pw"}}
        }
        inj._vault = MagicMock()
        inj._vault.client = mock_client

        secrets = inj.fetch_secrets("agent-1", secret_paths=["secret/agents/agent-1"])
        assert secrets == {"API_KEY": "sk-123", "DB_PASS": "pw"}

    def test_inject_into_environment_merges(self):
        inj = DynamicSecretInjector()
        mock_client = MagicMock()
        mock_client.secrets.kv.v2.read_secret_version.return_value = {
            "data": {"data": {"VAULT_KEY": "from_vault"}}
        }
        inj._vault = MagicMock()
        inj._vault.client = mock_client

        existing = {"AGENT_ID": "agent-1", "EXISTING": "keep_me", "VAULT_KEY": "override"}
        merged = inj.inject_into_environment(
            "agent-1", existing, secret_paths=["secret/test"]
        )
        assert merged["VAULT_KEY"] == "override"
        assert merged["EXISTING"] == "keep_me"
        assert merged["AGENT_ID"] == "agent-1"

    def test_revoke_secrets_clears_tracking(self):
        inj = DynamicSecretInjector()
        inj._injected_secrets["agent-1:sandbox-1"] = {"keys": ["A", "B"]}
        inj.revoke_secrets("agent-1", "sandbox-1")
        assert "agent-1:sandbox-1" not in inj._injected_secrets

    def test_revoke_nonexistent_does_not_crash(self):
        inj = DynamicSecretInjector()
        inj.revoke_secrets("ghost", "ghost-sandbox")

    def test_get_injection_summary(self):
        inj = DynamicSecretInjector()
        inj._vault = MagicMock()
        inj._vault.settings.vault_addr = "http://vault:8200"
        inj._vault.client = MagicMock()
        summary = inj.get_injection_summary()
        assert summary["vault_available"] is True
        assert summary["vault_addr"] == "http://vault:8200"

    def test_singleton(self):
        i1 = get_secret_injector()
        i2 = get_secret_injector()
        assert i1 is i2

    def test_fetch_secrets_empty_path_falls_back(self, monkeypatch):
        inj = DynamicSecretInjector()
        mock_client = MagicMock()
        mock_client.secrets.kv.v2.read_secret_version.return_value = {
            "data": {"data": {"TOKEN": "abc"}}
        }
        inj._vault = MagicMock()
        inj._vault.client = mock_client

        secrets = inj.fetch_secrets("agent-99")
        assert secrets == {"TOKEN": "abc"}
