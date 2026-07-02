import pytest
from secureagentnet.contain.network_whitelist import (
    NetworkWhitelist,
    create_domain_whitelist_for_agent,
)


class TestNetworkWhitelist:
    def test_create_empty_whitelist(self):
        wl = NetworkWhitelist()
        assert wl.is_allowed("github.com") is False
        assert wl.is_allowed("https://api.github.com") is False

    def test_whitelist_exact_domain(self):
        wl = NetworkWhitelist(allowed_domains=["github.com"])
        assert wl.is_allowed("github.com") is True
        assert wl.is_allowed("api.github.com") is False
        assert wl.is_allowed("gitlab.com") is False

    def test_whitelist_wildcard_domain(self):
        wl = NetworkWhitelist(allowed_domains=["*.github.com"])
        assert wl.is_allowed("api.github.com") is True
        assert wl.is_allowed("raw.github.com") is True
        assert wl.is_allowed("images.github.com") is True
        assert wl.is_allowed("github.com") is True
        assert wl.is_allowed("gitlab.com") is False
        assert wl.is_allowed("githubusercontent.com") is False

    def test_whitelist_multiple_domains(self):
        wl = NetworkWhitelist(allowed_domains=["github.com", "pypi.org", "*.python.org"])
        assert wl.is_allowed("github.com") is True
        assert wl.is_allowed("pypi.org") is True
        assert wl.is_allowed("docs.python.org") is True
        assert wl.is_allowed("evil.com") is False

    def test_url_extraction(self):
        wl = NetworkWhitelist(allowed_domains=["api.example.com"])
        assert wl.is_allowed("https://api.example.com/v1/data") is True
        assert wl.is_allowed("http://api.example.com:8080") is True
        assert wl.is_allowed("https://other.example.com") is False

    def test_non_blocking_mode(self):
        wl = NetworkWhitelist(block_all_by_default=False)
        assert wl.is_allowed("anything.evil.com") is True

    def test_allow_and_deny_methods(self):
        wl = NetworkWhitelist(allowed_domains=["github.com"])
        assert wl.is_allowed("github.com") is True
        wl.deny("github.com")
        assert wl.is_allowed("github.com") is False
        wl.allow("gitlab.com")
        assert wl.is_allowed("gitlab.com") is True

    def test_blocked_count(self):
        wl = NetworkWhitelist(allowed_domains=["safe.com"])
        wl.check_and_log("evil.com")
        wl.check_and_log("bad.com")
        assert wl.get_blocked_count() == 2
        wl.check_and_log("safe.com")
        assert wl.get_blocked_count() == 2

    def test_get_allowed_domains(self):
        wl = NetworkWhitelist(allowed_domains=["*.b.com", "a.com", "c.org"])
        assert wl.get_allowed_domains() == ["*.b.com", "a.com", "c.org"]

    def test_to_docker_config(self):
        wl = NetworkWhitelist(allowed_domains=["github.com", "*.pypi.org"])
        config = wl.to_docker_config()
        assert config["network_mode"] == "bridge"
        assert "8.8.8.8" in config["dns"]
        assert "pypi.org" in config["dns_search"]
        assert "github.com" in config["dns_search"]

    def test_from_agent_capabilities(self):
        wl = NetworkWhitelist.from_agent_capabilities(
            {"allowed_domains": ["slack.com", "*.openai.com"]}
        )
        assert wl.is_allowed("slack.com") is True
        assert wl.is_allowed("api.openai.com") is True

    def test_empty_capabilities_blocks_all(self):
        wl = NetworkWhitelist.from_agent_capabilities({})
        assert wl.is_allowed("anything.com") is False

    def test_case_insensitive(self):
        wl = NetworkWhitelist(allowed_domains=["GiThUb.CoM"])
        assert wl.is_allowed("GITHUB.COM") is True
        assert wl.is_allowed("github.com") is True
