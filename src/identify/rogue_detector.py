import logging
import time
from typing import Dict, List, Optional, Tuple, Set
from collections import defaultdict, deque
from dataclasses import dataclass, field
from src.utils.persistence import PersistenceStore

logger = logging.getLogger("SecureAgentNet.Identify.RogueDetector")


# --- Markov Chain Transition Graph ---

class BehaviorTransitionGraph:
    """Tracks action sequences as a Markov chain for anomaly detection.

    Each agent's behavior is modeled as a graph where nodes are actions
    and edges are transitions between actions. Anomalous sequences that
    deviate from learned patterns trigger alerts.
    """

    INTRINSIC_SUSPICIOUS_SEQUENCES = [
        ["read_file", "network_access", "write_file"],
        ["read_file", "execute_code", "network_access"],
        ["read_file", "network_access", "execute_code"],
        ["read_file", "network_access"],
        ["execute_code", "network_access"],
        ["network_access", "execute_code"],
        ["execute_sql", "network_access", "write_file"],
        ["read_file", "execute_sql", "network_access"],
    ]

    def __init__(self, history_depth: int = 3):
        self._transitions: Dict[str, Dict[Tuple, int]] = {}
        self._action_counts: Dict[str, int] = defaultdict(int)
        self._history_depth = history_depth
        self._agent_histories: Dict[str, deque] = {}

    def record_transition(self, agent_id: str, action: str, resource: str = ""):
        if agent_id not in self._agent_histories:
            self._agent_histories[agent_id] = deque(maxlen=self._history_depth)

        history = self._agent_histories[agent_id]
        if history:
            prev_seq = tuple(history)
            key = (prev_seq, action)
            if agent_id not in self._transitions:
                self._transitions[agent_id] = {}
            self._transitions[agent_id][key] = self._transitions[agent_id].get(key, 0) + 1

        history.append(action)
        self._action_counts[action] += 1

    def get_transition_probability(
        self, agent_id: str, sequence: List[str], next_action: str
    ) -> float:
        if agent_id not in self._transitions:
            return 0.5
        transitions = self._transitions[agent_id]
        key = (tuple(sequence), next_action)
        total = sum(v for k, v in transitions.items() if k[0] == tuple(sequence))
        if total == 0:
            return 0.5
        return transitions.get(key, 0) / total

    def is_suspicious_sequence(
        self, agent_id: str, sequence: List[str], next_action: str
    ) -> Tuple[bool, float, str]:
        for malicious in self.INTRINSIC_SUSPICIOUS_SEQUENCES:
            if len(sequence) >= len(malicious) - 1:
                check = list(sequence[-(len(malicious) - 1):])
            else:
                check = list(sequence)
            check.append(next_action)
            if len(check) >= len(malicious):
                recent = check[-len(malicious):]
                if recent == malicious:
                    return True, 0.95, (
                        f"Suspicious sequence detected: {' → '.join(malicious)}"
                    )

        prob = self.get_transition_probability(agent_id, list(sequence), next_action)
        if prob < 0.1 and len(sequence) > 0:
            transitions = self._transitions.get(agent_id, {})
            total = sum(v for k, v in transitions.items() if k[0] == tuple(sequence))
            if total >= 5:
                return True, 0.7, (
                    f"Low-probability transition ({prob:.2f}): "
                    f"{' → '.join(sequence)} → {next_action}"
                )
        return False, 0.0, "Normal transition"

    def get_action_distribution(self) -> Dict[str, int]:
        return dict(self._action_counts)

    def reset_agent(self, agent_id: str):
        self._agent_histories.pop(agent_id, None)
        self._transitions.pop(agent_id, None)


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
        self._transition_graph = BehaviorTransitionGraph(history_depth=3)
        self._load()
        logger.info("RogueDetector initialized with Markov chain behavior graph.")

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
        self._transition_graph.record_transition(agent_id, action, resource or "")
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

        hist_deque = self._transition_graph._agent_histories.get(agent_id, deque(maxlen=3))
        hist_list = list(hist_deque)

        if len(hist_list) >= 2:
            prev_sequence = hist_list[:-1]
            last_action = hist_list[-1]
            seq_suspicious, seq_score, seq_reason = self._transition_graph.is_suspicious_sequence(
                agent_id, prev_sequence, last_action
            )
            if seq_suspicious:
                return True, max(score, seq_score), seq_reason

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
            self._transition_graph.reset_agent(agent_id)
            self._persist()
            logger.info(f"Reset behavior profile for agent {agent_id}")

    def get_transition_graph(self) -> BehaviorTransitionGraph:
        return self._transition_graph

    def get_all_anomaly_scores(self) -> Dict[str, float]:
        scores = {}
        for agent_id in self._profiles:
            scores[agent_id] = self.compute_anomaly_score(agent_id)
        return scores


_rogue_detector_instance = None

def get_rogue_detector() -> RogueDetector:
    global _rogue_detector_instance
    if _rogue_detector_instance is None:
        _rogue_detector_instance = RogueDetector()
    return _rogue_detector_instance
