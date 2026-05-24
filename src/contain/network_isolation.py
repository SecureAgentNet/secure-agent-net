import logging
import docker
from docker.errors import NotFound
from typing import List, Optional, Dict

logger = logging.getLogger("SecureAgentNet.Contain.NetworkIsolation")


DEFAULT_DNS_WHITELIST = [
    "8.8.8.8",
    "8.8.4.4",
    "1.1.1.1",
]

DEFAULT_ALLOWED_DOMAINS = [
    "*.python.org",
    "*.pypi.org",
    "*.github.com",
    "*.docker.com",
]


class NetworkIsolationConfig:
    def __init__(
        self,
        egress_only: bool = True,
        dns_whitelist: Optional[List[str]] = None,
        allowed_domains: Optional[List[str]] = None,
        block_inbound: bool = True,
        block_raw_sockets: bool = True,
    ):
        self.egress_only = egress_only
        self.dns_whitelist = dns_whitelist or DEFAULT_DNS_WHITELIST
        self.allowed_domains = allowed_domains or DEFAULT_ALLOWED_DOMAINS
        self.block_inbound = block_inbound
        self.block_raw_sockets = block_raw_sockets

    def to_docker_kwargs(self) -> Dict:
        kwargs = {
            "network_disabled": False,
        }
        if self.egress_only:
            kwargs["network_mode"] = "bridge"
        if self.block_inbound:
            kwargs["ports"] = {}
        return kwargs

    def to_dict(self) -> Dict:
        return {
            "egress_only": self.egress_only,
            "dns_whitelist": self.dns_whitelist,
            "allowed_domains": self.allowed_domains,
            "block_inbound": self.block_inbound,
            "block_raw_sockets": self.block_raw_sockets,
        }


def create_isolated_network(name: str = "securenet_isolated") -> Optional[str]:
    """Creates an isolated Docker network with no internet access (internal=True).
    Returns the network name on success, or None if Docker is unavailable."""
    try:
        client = docker.from_env()
        try:
            existing = client.networks.get(name)
            logger.info(f"Using existing isolated network: {name}")
            return name
        except NotFound:
            client.networks.create(
                name,
                driver="bridge",
                internal=True,
                attachable=True,
                labels={"managed_by": "secureagentnet"},
            )
            logger.info(f"Created isolated network: {name}")
            return name
    except Exception as e:
        logger.warning(f"Failed to create isolated network: {e}")
        return None


def get_network_isolation_profile(level: str = "strict") -> NetworkIsolationConfig:
    profiles = {
        "strict": NetworkIsolationConfig(
            egress_only=True,
            block_inbound=True,
            block_raw_sockets=True,
        ),
        "moderate": NetworkIsolationConfig(
            egress_only=True,
            block_inbound=True,
            block_raw_sockets=True,
            allowed_domains=DEFAULT_ALLOWED_DOMAINS,
        ),
        "permissive": NetworkIsolationConfig(
            egress_only=False,
            block_inbound=False,
            block_raw_sockets=False,
        ),
    }
    return profiles.get(level, profiles["strict"])
