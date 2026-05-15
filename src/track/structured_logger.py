import json
import logging
from typing import Any
from src.track.models import CapturedLog
from src.track.vault_client import VaultAuditClient

# Set up local file/console logging
logger = logging.getLogger("SecureAgentNet.Track")
handler = logging.StreamHandler()
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)
logger.setLevel(logging.INFO)


class AgentAuditor:
    """
    Coordinates logging. Saves to standard output, Vault (for immutability),
    and eventually PostgreSQL for dashboard indexing.
    """

    def __init__(self):
        self.vault_client = VaultAuditClient()

    def capture(self, log_event: CapturedLog) -> CapturedLog:
        """
        Processes a CapturedLog event.
        1. Prints to stdout (for container logs)
        2. Sends to Vault (Tamper-proof)
        3. Updates the event with the Vault Receipt
        """
        # Convert Pydantic model to dict, handling datetimes
        log_dict = json.loads(log_event.model_dump_json())

        # 1. Standard Logging
        logger.info(f"Agent {log_event.agent_id} requested {log_event.action_request.action_name}")

        # 2. Vault Tamper-proof Logging
        vault_receipt = self.vault_client.secure_log(log_dict)

        if vault_receipt:
            log_event.vault_receipt_id = vault_receipt
            logger.info(f"Log secured in Vault. Receipt: {vault_receipt}")
        else:
            logger.warning("Failed to secure log in Vault. Proceeding with caution.")

        # 3. TODO: In a production app, here is where we would use SQLAlchemy
        # to write to the `audit_logs` table for fast querying.

        return log_event
