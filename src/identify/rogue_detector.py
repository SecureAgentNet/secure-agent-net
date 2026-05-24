import logging
import time
from typing import Dict, List, Optional, Tuple
from collections import defaultdict, deque
from dataclasses import dataclass, field
from src.utils.persistence import PersistenceStore

logger = logging.getLogger("SecureAgentNet.Identify.RogueDetector")


@dataclass
class AgentBehaviorProfile:
    agent_id: str
    request_timestamps: deque = field(default_factory=lambda: deque(maxlen=1000))
    action_counts: Dict[str, int] = field(default_factory=lambda: defaultdict(int))
    resource_accesses: Dict[str, int] = field(default_factory=lambda: defaultdict(int))
    failure_count: int = 0
    capability_escalation_attempts: int = 0
    anomaly_score: float = 0.0
    last_check_time: float = field(default_factory=time.time)


class RogueDetector:
    def __init__(self):
        self._profiles: Dict[str, AgentBehaviorProfile] = {}
        self._anomaly_threshold = 0.8
        self._failure_threshold = 10
        self._time_window = 60.0
        self._rate_limit = 100
        self._load()
        logger.info("RogueDetector initialized.")

    def _persist(self):
        data = {}
        for agent_id, profile in self._profiles.items():
            data[agent_id] = {
                "agent_id": profile.agent_id,
                "request_timestamps": list(profile.request_timestamps),
                "action_counts": dict(profile.action_counts),
                "resource_accesses": dict(profile.resource_accesses),
                "failure_count": profile.failure_count,
                "capability_escalation_attempts": profile.capability_escalation_attempts,
                "anomaly_score": profile.anomaly_score,
                "last_check_time": profile.last_check_time,
            }
        PersistenceStore.save("rogue_detector", data)

    def _load(self):
        data = PersistenceStore.load("rogue_detector", None)
        if data:
            self._profiles = {}
            for agent_id, d in data.items():
                profile = AgentBehaviorProfile(agent_id=agent_id)
                profile.request_timestamps = deque(d.get("request_timestamps", []), maxlen=1000)
                profile.action_counts = defaultdict(int, d.get("action_counts", {}))
                profile.resource_accesses = defaultdict(int, d.get("resource_accesses", {}))
                profile.failure_count = d.get("failure_count", 0)
                profile.capability_escalation_attempts = d.get("capability_escalation_attempts", 0)
                profile.anomaly_score = d.get("anomaly_score", 0.0)
                profile.last_check_time = d.get("last_check_time", time.time())
                self._profiles[agent_id] = profile

    def _get_profile(self, agent_id: str) -> AgentBehaviorProfile:
        if agent_id not in self._profiles:
            self._profiles[agent_id] = AgentBehaviorProfile(agent_id=agent_id)
        return self._profiles[agent_id]

    def record_request(self, agent_id: str, action: str, resource: Optional[str] = None):
        profile = self._get_profile(agent_id)
        now = time.time()
        profile.request_timestamps.append(now)
        profile.action_counts[action] += 1
        if resource:
            profile.resource_accesses[resource] += 1
        self._persist()

    def record_failure(self, agent_id: str):
        profile = self._get_profile(agent_id)
        profile.failure_count += 1
        self._persist()

    def record_capability_escalation_attempt(self, agent_id: str):
        profile = self._get_profile(agent_id)
        profile.capability_escalation_attempts += 1
        self._persist()
        logger.warning(f"Capability escalation attempt by agent {agent_id}")

    def check_rate_limit(self, agent_id: str) -> bool:
        profile = self._get_profile(agent_id)
        now = time.time()
        recent = [t for t in profile.request_timestamps if now - t <= self._time_window]
        return len(recent) <= self._rate_limit

    def compute_anomaly_score(self, agent_id: str) -> float:
        profile = self._get_profile(agent_id)
        score = 0.0
        now = time.time()

        recent_requests = [t for t in profile.request_timestamps if now - t <= self._time_window]

        request_rate = len(recent_requests) / self._time_window if self._time_window > 0 else 0
        if request_rate > self._rate_limit * 0.8:
            score += 0.3

        if profile.failure_count > self._failure_threshold:
            score += 0.3

        if profile.capability_escalation_attempts > 2:
            score += 0.3

        action_diversity = len(profile.action_counts)
        if action_diversity > 20 and request_rate > 10:
            score += 0.2

        score = min(1.0, score)
        profile.anomaly_score = score
        profile.last_check_time = now
        return score

    def is_suspicious(self, agent_id: str) -> Tuple[bool, float, str]:
        score = self.compute_anomaly_score(agent_id)
        if score >= self._anomaly_threshold:
            return True, score, f"Anomaly score {score:.2f} exceeds threshold"
        if not self.check_rate_limit(agent_id):
            return True, 0.7, f"Rate limit exceeded for agent {agent_id}"
        return False, score, "Behavior appears normal"

    def get_profile_summary(self, agent_id: str) -> Dict:
        profile = self._get_profile(agent_id)
        return {
            "agent_id": profile.agent_id,
            "total_requests": len(profile.request_timestamps),
            "action_counts": dict(profile.action_counts),
            "failure_count": profile.failure_count,
            "capability_escalation_attempts": profile.capability_escalation_attempts,
            "anomaly_score": profile.anomaly_score,
            "last_check": profile.last_check_time,
        }

    def reset_profile(self, agent_id: str):
        if agent_id in self._profiles:
            del self._profiles[agent_id]
            self._persist()
            logger.info(f"Reset behavior profile for agent {agent_id}")

    def get_all_anomaly_scores(self) -> Dict[str, float]:
        scores = {}
        for agent_id in self._profiles:
            scores[agent_id] = self.compute_anomaly_score(agent_id)
        return scores
