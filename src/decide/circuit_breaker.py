import time
import logging
from typing import Dict, Tuple
from src.database.repositories import CircuitBreakerRepository

logger = logging.getLogger("SecureAgentNet.CircuitBreaker")

class CircuitBreaker:
    """
    Monitors agent failure rates. If an agent gets blocked too many times 
    within a specific time window, the circuit "trips" (opens), 
    temporarily suspending the agent from making further requests.
    """
    
    def __init__(self, failure_threshold: int = 3, time_window_seconds: int = 60, reset_timeout_seconds: int = 120):
        self.failure_threshold = failure_threshold
        self.time_window = time_window_seconds
        self.reset_timeout = reset_timeout_seconds
        
        # Format: {agent_id: {"failures": [timestamp1, timestamp2], "state": "CLOSED", "tripped_at": None}}
        # State: CLOSED = Normal operation, OPEN = Suspended
        self._state_store: Dict[str, dict] = {}
        self._load()

    def _persist(self):
        CircuitBreakerRepository.save_all(self._state_store)

    def _load(self):
        data = CircuitBreakerRepository.load_all()
        if data:
            self._state_store = data

    def _get_agent_state(self, agent_id: str) -> dict:
        if agent_id not in self._state_store:
            self._state_store[agent_id] = {
                "failures": [],
                "state": "CLOSED",
                "tripped_at": None
            }
        return self._state_store[agent_id]

    def record_failure(self, agent_id: str):
        """Records a blocked action. Trips the circuit if threshold is exceeded."""
        agent_state = self._get_agent_state(agent_id)
        now = time.time()
        
        # Add new failure
        agent_state["failures"].append(now)
        
        # Clean up old failures outside the time window
        agent_state["failures"] = [
            t for t in agent_state["failures"] 
            if now - t <= self.time_window
        ]
        
        self._persist()
        # Check if threshold is reached
        if len(agent_state["failures"]) >= self.failure_threshold and agent_state["state"] == "CLOSED":
            agent_state["state"] = "OPEN"
            agent_state["tripped_at"] = now
            logger.warning(f"CIRCUIT TRIPPED for Agent {agent_id}. Too many blocked actions.")

    def check_access(self, agent_id: str) -> Tuple[bool, str]:
        """
        Checks if the agent is allowed to proceed.
        Returns (is_allowed, reason).
        """
        agent_state = self._get_agent_state(agent_id)
        
        if agent_state["state"] == "OPEN":
            now = time.time()
            # Check if reset timeout has elapsed
            if now - agent_state["tripped_at"] > self.reset_timeout:
                logger.info(f"CIRCUIT RESET for Agent {agent_id}. Resuming normal operations.")
                agent_state["state"] = "CLOSED"
                agent_state["failures"] = []
                agent_state["tripped_at"] = None
                self._persist()
                return True, "Circuit closed."
            else:
                remaining = int(self.reset_timeout - (now - agent_state["tripped_at"]))
                return False, f"Agent suspended by Circuit Breaker. Try again in {remaining} seconds."
                
        return True, "Circuit closed."
