import logging
import time
from typing import Dict, Optional
from threading import Lock

from secureagentnet.core.constants import DEFAULT_KILL_SWITCH_DENIAL_THRESHOLD, DEFAULT_KILL_SWITCH_BLOCK_DURATION_S
from secureagentnet.core.exceptions import KillSwitchActiveError
from secureagentnet.database.repositories import KillSwitchRepository

logger = logging.getLogger("SecureAgentNet.Decide.KillSwitch")


class KillSwitchController:
    def __init__(self):
        self._armed: bool = True
        self._active: bool = False
        self._trigger_count: int = 0
        self._last_triggered_at: Optional[float] = None
        self._last_reset_at: Optional[float] = None
        self._denial_counts: Dict[str, int] = {}
        self._denial_threshold: int = DEFAULT_KILL_SWITCH_DENIAL_THRESHOLD
        self._block_duration: int = DEFAULT_KILL_SWITCH_BLOCK_DURATION_S
        self._lock: Lock = Lock()
        self._load()
        logger.info("KillSwitchController initialized.")

    @property
    def is_active(self) -> bool:
        return self._active

    @property
    def is_armed(self) -> bool:
        return self._armed

    def _persist(self):
        data = {
            "_armed": self._armed,
            "_active": self._active,
            "_trigger_count": self._trigger_count,
            "_last_triggered_at": self._last_triggered_at,
            "_last_reset_at": self._last_reset_at,
            "_denial_counts": dict(self._denial_counts),
            "_denial_threshold": self._denial_threshold,
            "_block_duration": self._block_duration,
        }
        KillSwitchRepository.save(data)

    def _load(self):
        data = KillSwitchRepository.load()
        if data:
            self._armed = data.get("_armed", True)
            self._active = data.get("_active", False)
            self._trigger_count = data.get("_trigger_count", 0)
            self._last_triggered_at = data.get("_last_triggered_at")
            self._last_reset_at = data.get("_last_reset_at")
            self._denial_counts = data.get("_denial_counts", {})
            self._denial_threshold = data.get("_denial_threshold", DEFAULT_KILL_SWITCH_DENIAL_THRESHOLD)
            self._block_duration = data.get("_block_duration", DEFAULT_KILL_SWITCH_BLOCK_DURATION_S)

    def arm(self):
        with self._lock:
            self._armed = True
            self._persist()
            logger.info("Kill-switch armed.")

    def disarm(self):
        with self._lock:
            self._armed = False
            self._persist()
            logger.warning("Kill-switch DISARMED!")

    def record_denial(self, agent_id: str) -> bool:
        with self._lock:
            if not self._armed or self._active:
                return self._active

            self._denial_counts[agent_id] = self._denial_counts.get(agent_id, 0) + 1
            count = self._denial_counts[agent_id]

            logger.debug(f"Agent {agent_id} denial count: {count}/{self._denial_threshold}")

            if count >= self._denial_threshold:
                self._activate()
                self._persist()
                return True

            total_denials = sum(self._denial_counts.values())
            if total_denials >= self._denial_threshold * 3:
                self._activate()
                self._persist()
                return True

            self._persist()
            return False

    def _activate(self):
        self._active = True
        self._trigger_count += 1
        self._last_triggered_at = time.time()
        logger.critical(
            f"KILL-SWITCH ACTIVATED! Trigger count: {self._trigger_count}. "
            f"All agent operations halted."
        )

    def activate(self, triggered_by: str = "operator"):
        """Manually engage the kill-switch (operator emergency stop)."""
        with self._lock:
            self._activate()
            self._persist()
            logger.critical("Kill-switch manually ACTIVATED by %s.", triggered_by)

    def deactivate(self, reset_by: str = "admin"):
        with self._lock:
            self._active = False
            self._denial_counts.clear()
            self._last_reset_at = time.time()
            self._persist()
            logger.warning(f"Kill-switch deactivated by {reset_by}.")

    def check(self) -> bool:
        if self._active:
            raise KillSwitchActiveError(
                "Kill-switch is active. All agent operations are halted."
            )
        return True

    def get_status(self) -> Dict:
        return {
            "armed": self._armed,
            "active": self._active,
            "trigger_count": self._trigger_count,
            "last_triggered_at": self._last_triggered_at,
            "last_reset_at": self._last_reset_at,
            "denial_threshold": self._denial_threshold,
            "agent_denial_counts": dict(self._denial_counts),
        }

    def reset_agent_counters(self, agent_id: str):
        with self._lock:
            self._denial_counts.pop(agent_id, None)
            self._persist()
