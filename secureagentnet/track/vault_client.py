import base64
import hvac
import json
import logging
from typing import Optional, Dict, Any
from secureagentnet.core.config import get_settings


logger = logging.getLogger(__name__)

TRANSIT_KEY_NAME = "audit-log-key"


class VaultAuditClient:
    def __init__(self):
        self.settings = get_settings()
        self._transit_ready = False
        try:
            self.client = hvac.Client(
                url=self.settings.vault_addr,
                token=self.settings.vault_token
            )
            if self.client.is_authenticated():
                self._ensure_transit_key()
            else:
                # Expected degraded state when Vault isn't running (dev/demo):
                # the system falls back gracefully. Keep the CLI clean — surface
                # Vault status via the banner / `doctor`, not as per-command noise.
                logger.debug("Vault client not authenticated; running without Vault-signed receipts.")
                self.client = None
        except Exception as e:
            logger.error(f"Failed to initialize Vault client: {e}")
            self.client = None

    def _ensure_transit_key(self):
        try:
            existing = self.client.secrets.transit.read_key(TRANSIT_KEY_NAME)
            if existing:
                self._transit_ready = True
                return
        except hvac.exceptions.InvalidPath:
            pass
        except Exception:
            pass

        if self._create_transit_key():
            return

        # The transit secrets engine may not be mounted yet (common on a fresh
        # dev Vault). Try to enable it, then create the key once more.
        try:
            self.client.sys.enable_secrets_engine(backend_type="transit")
            logger.info("Enabled Vault transit secrets engine")
        except hvac.exceptions.InvalidRequest:
            # Path already in use — engine is mounted, fall through to retry.
            pass
        except Exception as e:
            logger.debug("Could not enable Vault transit engine: %s", e)
            return

        self._create_transit_key()

    def _create_transit_key(self) -> bool:
        try:
            self.client.secrets.transit.create_key(
                name=TRANSIT_KEY_NAME,
                key_type="aes256-gcm96",
            )
            self._transit_ready = True
            logger.info("Created Transit key '%s'", TRANSIT_KEY_NAME)
            return True
        except Exception as e:
            logger.debug("Could not create Transit key '%s': %s", TRANSIT_KEY_NAME, e)
            return False

    def _canonical_json(self, data: dict) -> bytes:
        return json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def sign_log(self, log_data: Dict[str, Any]) -> Optional[str]:
        if not self.client or not self._transit_ready:
            return None
        try:
            raw = self._canonical_json(log_data)
            b64_input = base64.b64encode(raw).decode("ascii")
            result = self.client.secrets.transit.generate_hmac(
                name=TRANSIT_KEY_NAME,
                hash_input=b64_input,
            )
            hmac_value = result.get("data", {}).get("hmac")
            return hmac_value
        except Exception as e:
            logger.error("Failed to sign log with Transit: %s", e)
            return None

    def verify_log(self, log_data: Dict[str, Any], hmac_value: str) -> bool:
        if not self.client or not self._transit_ready:
            return False
        try:
            raw = self._canonical_json(log_data)
            b64_input = base64.b64encode(raw).decode("ascii")
            verify_fn = getattr(self.client.secrets.transit, "verify_hmac", None)
            if verify_fn is None:
                verify_fn = self.client.secrets.transit.verify_signed_data
            result = verify_fn(
                name=TRANSIT_KEY_NAME,
                hash_input=b64_input,
                hmac=hmac_value,
            )
            return result.get("data", {}).get("valid", False)
        except Exception as e:
            logger.error("Failed to verify log with Transit: %s", e)
            return False

    def secure_log(self, log_data: Dict[str, Any]) -> Optional[str]:
        if not self.client:
            logger.warning("Vault client not connected. Skipping secure log.")
            return None

        try:
            hmac_value = self.sign_log(log_data)
            entry = dict(log_data)
            entry["_hmac"] = hmac_value

            log_id = log_data.get("log_id")
            agent_id = log_data.get("agent_id", "unknown_agent")
            path = f"audit/agents/{agent_id}/{log_id}"

            response = self.client.secrets.kv.v2.create_or_update_secret(
                path=path,
                secret=entry,
            )
            version = response.get("data", {}).get("version", 1)
            return f"vault-{path}-v{version}"

        except Exception as e:
            logger.error(f"Failed to write audit log to Vault: {e}")
            return None

    def retrieve_log(self, receipt: str) -> Optional[Dict[str, Any]]:
        if not self.client:
            return None
        try:
            parts = receipt.split("-v")
            if len(parts) != 2:
                return None
            path = parts[0].removeprefix("vault-")
            version = int(parts[1])
            response = self.client.secrets.kv.v2.read_secret_version(
                path=path,
                version=version,
            )
            return response.get("data", {}).get("data", {})
        except Exception as e:
            logger.error(f"Failed to retrieve log from Vault: {e}")
            return None

    def verify_receipt(self, receipt: str) -> Dict[str, Any]:
        stored = self.retrieve_log(receipt)
        if not stored:
            return {"valid": False, "error": "Log not found in Vault"}
        hmac_value = stored.pop("_hmac", None)
        if not hmac_value:
            return {"valid": False, "error": "No HMAC signature found in stored log"}
        valid = self.verify_log(stored, hmac_value)
        return {"valid": valid, "log": stored}
