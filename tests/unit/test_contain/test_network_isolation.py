import pytest
from src.contain.network_isolation import (
    NetworkIsolationConfig,
    get_network_isolation_profile,
    create_isolated_network,
    DEFAULT_DNS_WHITELIST,
    DEFAULT_ALLOWED_DOMAINS,
)


class TestNetworkIsolation:
    def test_network_isolation_strict(self):
        config = get_network_isolation_profile("strict")
        assert config.egress_only is True
        assert config.block_inbound is True
        assert config.block_raw_sockets is True
        assert config.dns_whitelist == DEFAULT_DNS_WHITELIST
        assert config.allowed_domains == DEFAULT_ALLOWED_DOMAINS

    def test_network_isolation_moderate(self):
        config = get_network_isolation_profile("moderate")
        assert config.egress_only is True
        assert config.block_inbound is True
        assert config.block_raw_sockets is True
        assert config.allowed_domains == DEFAULT_ALLOWED_DOMAINS

    def test_network_isolation_permissive(self):
        config = get_network_isolation_profile("permissive")
        assert config.egress_only is False
        assert config.block_inbound is False
        assert config.block_raw_sockets is False

    def test_get_network_isolation_profile_unknown_level_defaults_to_strict(self):
        config = get_network_isolation_profile("nonexistent")
        assert config.egress_only is True
        assert config.block_inbound is True
        assert config.block_raw_sockets is True

    def test_default_dns_whitelist(self):
        assert "8.8.8.8" in DEFAULT_DNS_WHITELIST
        assert "1.1.1.1" in DEFAULT_DNS_WHITELIST

    def test_default_allowed_domains(self):
        assert "*.python.org" in DEFAULT_ALLOWED_DOMAINS
        assert "*.pypi.org" in DEFAULT_ALLOWED_DOMAINS
        assert "*.github.com" in DEFAULT_ALLOWED_DOMAINS
        assert "*.docker.com" in DEFAULT_ALLOWED_DOMAINS

    def test_network_isolation_config_to_docker_kwargs(self):
        config = get_network_isolation_profile("strict")
        kwargs = config.to_docker_kwargs()
        assert kwargs["network_disabled"] is False
        assert kwargs["network_mode"] == "bridge"
        assert kwargs["ports"] == {}

    def test_network_isolation_config_to_docker_kwargs_permissive(self):
        config = get_network_isolation_profile("permissive")
        kwargs = config.to_docker_kwargs()
        assert "network_mode" not in kwargs
        assert "ports" not in kwargs

    def test_network_isolation_config_to_dict(self):
        config = NetworkIsolationConfig(
            egress_only=True,
            block_inbound=True,
            block_raw_sockets=True,
        )
        d = config.to_dict()
        assert d["egress_only"] is True
        assert d["block_inbound"] is True
        assert d["block_raw_sockets"] is True
        assert "dns_whitelist" in d
        assert "allowed_domains" in d

    def test_network_isolation_config_custom(self):
        config = NetworkIsolationConfig(
            egress_only=False,
            dns_whitelist=["10.0.0.1"],
            allowed_domains=["*.example.com"],
            block_inbound=False,
            block_raw_sockets=False,
        )
        assert config.egress_only is False
        assert config.dns_whitelist == ["10.0.0.1"]
        assert config.allowed_domains == ["*.example.com"]
        assert config.block_inbound is False
        assert config.block_raw_sockets is False

    @pytest.fixture
    def mock_docker(self, mocker):
        mock_client = mocker.MagicMock()
        mock_network = mocker.MagicMock()
        mock_client.networks.get.return_value = mock_network
        mock_docker_from_env = mocker.patch("src.contain.network_isolation.docker.from_env")
        mock_docker_from_env.return_value = mock_client
        return mock_client

    def test_create_isolated_network_uses_existing(self, mock_docker):
        result = create_isolated_network("test-network")
        assert result == "test-network"
        mock_docker.networks.get.assert_called_once_with("test-network")
        mock_docker.networks.create.assert_not_called()

    def test_create_isolated_network_creates_new(self, mock_docker):
        from docker.errors import NotFound
        mock_docker.networks.get.side_effect = NotFound("not found")
        result = create_isolated_network("test-network")
        assert result == "test-network"
        mock_docker.networks.create.assert_called_once_with(
            "test-network",
            driver="bridge",
            internal=True,
            attachable=True,
            labels={"managed_by": "secureagentnet"},
        )

    def test_create_isolated_network_default_name(self, mock_docker):
        result = create_isolated_network()
        assert result == "securenet_isolated"

    def test_create_isolated_network_docker_unavailable(self, mocker):
        mocker.patch("src.contain.network_isolation.docker.from_env", side_effect=Exception("no docker"))
        result = create_isolated_network()
        assert result is None
