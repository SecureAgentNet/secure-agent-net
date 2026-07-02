import logging
import os
from datetime import datetime, timezone
from typing import Dict, Any, Optional

from secureagentnet.track.vault_client import VaultAuditClient

logger = logging.getLogger(__name__)


class DynamicSecretInjector:
    """Injects ephemeral credentials from HashiCorp Vault into sandbox containers.

    Secrets are fetched just-in-time during the CONTAIN phase, injected as
    environment variables, and automatically tracked for revocation after
    the container completes.
    """

    def __init__(self):
        self._vault: Optional[VaultAuditClient] = None
        self._injected_secrets: Dict[str, Dict[str, Any]] = {}

        try:
            self._vault = VaultAuditClient()
            if self._vault.client:
                logger.info("DynamicSecretInjector initialized with Vault at %s",
                           self._vault.settings.vault_addr)
        except Exception as e:
            logger.warning("Vault not available — dynamic secrets disabled: %s", e)
            self._vault = None

    def is_available(self) -> bool:
        return self._vault is not None and self._vault.client is not None

    def fetch_secrets(
        self,
        agent_id: str,
        secret_paths: Optional[list] = None,
    ) -> Dict[str, str]:
        """Fetch secrets from Vault for a specific agent.

        Args:
            agent_id: The agent ID to fetch secrets for.
            secret_paths: Optional list of Vault paths to read. Defaults to
                          the agent's configured paths from IdentityRegistry.

        Returns:
            Dict of env_var_name -> secret_value
        """
        if not self.is_available():
            logger.debug("Vault unavailable — returning empty secrets for %s", agent_id)
            return {}

        if secret_paths is None:
            secret_paths = self._get_agent_secret_paths(agent_id)

        secrets: Dict[str, str] = {}
        for path in secret_paths:
            try:
                data = self._read_secret(path)
                if data:
                    secrets.update(data)
                    logger.info(
                        "Fetched %d secret(s) from Vault path '%s' for agent %s",
                        len(data), path, agent_id,
                    )
            except Exception as e:
                logger.error("Failed to fetch secret at '%s': %s", path, e)

        self._track_injection(agent_id, secrets)
        return secrets

    def inject_into_environment(
        self,
        agent_id: str,
        existing_env: Dict[str, str],
        secret_paths: Optional[list] = None,
    ) -> Dict[str, str]:
        """Merge fetched secrets into existing environment variables.

        Returns a new dict with secrets injected. Original env vars take
        precedence over secrets of the same name.
        """
        secrets = self.fetch_secrets(agent_id, secret_paths)
        merged = dict(secrets)
        merged.update(existing_env)
        return merged

    def revoke_secrets(self, agent_id: str, sandbox_id: str = ""):
        """Mark secrets as used for an agent/sandbox run.

        Secrets are ephemeral — they're only injected for the lifetime
        of a single container execution. This method tracks the revocation
        and clears the local copy.
        """
        key = f"{agent_id}:{sandbox_id}" if sandbox_id else agent_id
        entry = self._injected_secrets.pop(key, None)
        if entry:
            logger.info(
                "Secrets for agent=%s sandbox=%s revoked — %d keys cleared",
                agent_id, sandbox_id, len(entry.get("keys", [])),
            )

    def get_injection_summary(self) -> Dict[str, Any]:
        return {
            "active_injections": len(self._injected_secrets),
            "vault_available": self.is_available(),
            "vault_addr": self._vault.settings.vault_addr if self._vault else None,
        }

    def _track_injection(self, agent_id: str, secrets: Dict[str, str]):
        key = agent_id
        self._injected_secrets[key] = {
            "agent_id": agent_id,
            "keys": list(secrets.keys()),
            "injected_at": datetime.now(timezone.utc).isoformat(),
            "secret_count": len(secrets),
        }

    def _read_secret(self, path: str) -> Dict[str, str]:
        """Read a Vault KV v2 secret and flatten key-value data."""
        if not self._vault or not self._vault.client:
            return {}
        try:
            response = self._vault.client.secrets.kv.v2.read_secret_version(
                path=path,
            )
            data = response.get("data", {}).get("data", {})
            return {str(k): str(v) for k, v in data.items() if v is not None}
        except Exception:
            return {}

    @staticmethod
    def _get_agent_secret_paths(agent_id: str) -> list:
        """Get configured Vault secret paths for an agent from IdentityRegistry."""
        try:
            from secureagentnet.identify.identity_registry import IdentityRegistry
            agent = IdentityRegistry.get_agent(agent_id)
            if agent:
                metadata = agent.get("metadata", {})
                return metadata.get("vault_secret_paths", [f"secret/agents/{agent_id}"])
        except Exception:
            pass
        return [f"secret/agents/{agent_id}"]


_secret_injector: Optional[DynamicSecretInjector] = None


def get_secret_injector() -> DynamicSecretInjector:
    global _secret_injector
    if _secret_injector is None:
        _secret_injector = DynamicSecretInjector()
    return _secret_injector
