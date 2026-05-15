import hvac
import json
import logging
from typing import Optional, Dict, Any
from src.core.config import get_settings


logger = logging.getLogger(__name__)

class VaultAuditClient:
    """
    Client for interacting with HashiCorp Vault.
    Used to write tamper-proof audit logs of agent actions.
    """
    
    def __init__(self):
        self.settings = get_settings()
        try:
            self.client = hvac.Client(
                url=self.settings.vault_addr,
                token=self.settings.vault_token
            )
            # In a real environment, we'd verify the client is authenticated here.
            # self.client.is_authenticated()
        except Exception as e:
            logger.error(f"Failed to initialize Vault client: {e}")
            self.client = None

    def secure_log(self, log_data: Dict[str, Any]) -> Optional[str]:
        """
        Writes a structured log entry into Vault's Key-Value store (V2).
        In production, this would use Vault's Transit engine for hashing 
        or an Audit device, but KV V2 provides immutable versions for prototyping.
        """
        if not self.client:
            logger.warning("Vault client not connected. Skipping secure log.")
            return None

        try:
            log_id = log_data.get("log_id")
            
            # Write to a specific agent auditing path
            agent_id = log_data.get("agent_id", "unknown_agent")
            path = f"audit/agents/{agent_id}/{log_id}"
            
            response = self.client.secrets.kv.v2.create_or_update_secret(
                path=path,
                secret=log_data
            )
            
            # Return the specific version of the secret to act as a receipt
            version = response.get('data', {}).get('version', 1)
            return f"vault-{path}-v{version}"
            
        except Exception as e:
            logger.error(f"Failed to write audit log to Vault: {e}")
            return None
