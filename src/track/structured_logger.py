import json
import logging

from src.track.models import CapturedLog
from src.track.vault_client import VaultAuditClient

logger = logging.getLogger("SecureAgentNet.Track")
handler = logging.StreamHandler()
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
if not logger.handlers:
    logger.addHandler(handler)
logger.setLevel(logging.INFO)


class StructuredLogger:
    def log(self, level: str, message: str, **kwargs):
        log_method = getattr(logger, level.lower(), logger.info)
        log_method(message, extra=kwargs)

    def debug(self, message: str, **kwargs):
        logger.debug(message, extra=kwargs)

    def info(self, message: str, **kwargs):
        logger.info(message, extra=kwargs)

    def warning(self, message: str, **kwargs):
        logger.warning(message, extra=kwargs)

    def error(self, message: str, **kwargs):
        logger.error(message, extra=kwargs)

    def critical(self, message: str, **kwargs):
        logger.critical(message, extra=kwargs)


class AgentAuditor:
    def __init__(self):
        self.vault_client = VaultAuditClient()
        self.structured_logger = StructuredLogger()

    def capture(self, log_event: CapturedLog) -> CapturedLog:
        log_dict = json.loads(log_event.model_dump_json())
        self.structured_logger.info(f"Agent {log_event.agent_id} requested {log_event.action_request.action_name}")

        vault_receipt = self.vault_client.secure_log(log_dict)
        if vault_receipt:
            log_event.vault_receipt_id = vault_receipt
            self.structured_logger.info(f"Log secured in Vault. Receipt: {vault_receipt}")
        else:
            self.structured_logger.warning("Failed to secure log in Vault.")

        return log_event
