import logging
import re
from typing import List, Set, Optional

logger = logging.getLogger(__name__)


class NetworkWhitelist:
    """Granular domain-based network filtering for sandboxed agents.

    Maintains a per-agent whitelist of allowed domains for egress traffic.
    Integrates with Docker container creation via extra_hosts and DNS config.
    """

    def __init__(
        self,
        allowed_domains: Optional[List[str]] = None,
        block_all_by_default: bool = True,
    ):
        self._allowed: Set[str] = set()
        self._blocked_count: int = 0
        self._block_all_by_default = block_all_by_default

        if allowed_domains:
            for domain in allowed_domains:
                self.allow(domain)

    def allow(self, domain: str):
        """Add a domain pattern to the whitelist (supports wildcards like *.github.com)."""
        self._allowed.add(domain.lower().strip())

    def deny(self, domain: str):
        self._allowed.discard(domain.lower().strip())

    def is_allowed(self, domain_or_url: str) -> bool:
        if not self._block_all_by_default:
            return True
        if not self._allowed:
            return False

        target = self._extract_domain(domain_or_url).lower()

        for pattern in self._allowed:
            if self._domain_matches(pattern, target):
                return True
        return False

    def check_and_log(self, domain_or_url: str, agent_id: str = "") -> bool:
        allowed = self.is_allowed(domain_or_url)
        if not allowed:
            self._blocked_count += 1
            logger.warning(
                "NETWORK BLOCKED: agent=%s domain=%s (blocked_count=%d)",
                agent_id or "unknown",
                self._extract_domain(domain_or_url),
                self._blocked_count,
            )
        else:
            logger.debug(
                "NETWORK ALLOWED: agent=%s domain=%s",
                agent_id or "unknown",
                domain_or_url,
            )
        return allowed

    def get_allowed_domains(self) -> List[str]:
        return sorted(self._allowed)

    def get_blocked_count(self) -> int:
        return self._blocked_count

    def to_docker_config(self) -> dict:
        """Generate Docker container config for network isolation based on whitelist.

        Returns DNS and extra_hosts configuration that restricts outbound
        traffic to only allowed domains.
        """
        config = {
            "network_mode": "bridge",
        }

        if self._block_all_by_default and self._allowed:
            dns_servers = ["8.8.8.8", "1.1.1.1"]
            config["dns"] = dns_servers
            config["dns_search"] = []

            for domain in self._allowed:
                clean = domain.replace("*.", "")
                if not clean.startswith("*"):
                    config["dns_search"].append(clean)

        config["labels"] = {
            "san.network.whitelist": ",".join(sorted(self._allowed)),
            "san.network.blocked_count": str(self._blocked_count),
        }
        return config

    @staticmethod
    def _extract_domain(domain_or_url: str) -> str:
        """Extract the domain from a URL or hostname string."""
        cleaned = domain_or_url.strip()
        if cleaned.startswith(("http://", "https://")):
            import urllib.parse
            parsed = urllib.parse.urlparse(cleaned)
            return parsed.hostname or cleaned
        if ":" in cleaned:
            return cleaned.split(":")[0]
        return cleaned.split("/")[0]

    @staticmethod
    def _domain_matches(pattern: str, target: str) -> bool:
        """Check if a target domain matches a whitelist pattern.

        Supports exact match: 'github.com' matches 'github.com'
        Supports wildcards: '*.github.com' matches 'api.github.com'
        """
        if pattern.startswith("*."):
            suffix = pattern[2:]
            return target == suffix or target.endswith("." + suffix)
        return pattern == target

    @classmethod
    def from_agent_capabilities(cls, capabilities: dict) -> "NetworkWhitelist":
        """Create a NetworkWhitelist from an agent's capabilities dict.

        Expects capabilities['allowed_domains'] as a list of domain strings.
        """
        domains = capabilities.get("allowed_domains", [])
        if not domains and isinstance(capabilities, list):
            domains = capabilities
        return cls(allowed_domains=domains)


def create_domain_whitelist_for_agent(
    agent_id: str,
    default_domains: Optional[List[str]] = None,
) -> NetworkWhitelist:
    """Create a NetworkWhitelist for a specific agent.

    Reads the agent's capabilities from IdentityRegistry.
    Falls back to default_domains if agent has none configured.
    """
    from secureagentnet.identify.identity_registry import IdentityRegistry

    agent = IdentityRegistry.get_agent(agent_id)
    capabilities = agent.get("capabilities", {}) if agent else {}

    domains = capabilities.get("allowed_domains", [])
    if not domains and default_domains:
        domains = default_domains

    return NetworkWhitelist(allowed_domains=domains)
