import pytest
from secureagentnet.identify.rogue_detector import BehaviorTransitionGraph, RogueDetector
from collections import deque


class TestMarkovSequenceBugFix:
    """Verify the full-history Markov chain check, not just last-2 elements."""

    def setup_method(self):
        self.detector = RogueDetector()

    def test_3_step_suspicious_sequence_detected(self):
        d = self.detector
        d.record_request("agent-3x", "read_file", "/etc/passwd")
        d.record_request("agent-3x", "network_access", "attacker.com")
        d.record_request("agent-3x", "write_file", "/tmp/backdoor")

        suspicious, score, reason = d.is_suspicious("agent-3x")
        assert suspicious is True
        assert "sequence" in reason.lower() or "suspicious" in reason.lower()

    def test_3_step_read_exec_network_detected(self):
        d = self.detector
        d.record_request("agent-rxn", "read_file", "/etc/shadow")
        d.record_request("agent-rxn", "execute_code", "reverse shell")
        d.record_request("agent-rxn", "network_access", "evil.com")

        suspicious, score, reason = d.is_suspicious("agent-rxn")
        assert suspicious is True

    def test_2_step_exec_network_detected(self):
        d = self.detector
        d.record_request("agent-2s", "execute_code", "run script")
        d.record_request("agent-2s", "network_access", "curl evil.com")

        suspicious, score, reason = d.is_suspicious("agent-2s")
        assert suspicious is True

    def test_sql_network_write_3_step(self):
        d = self.detector
        d.record_request("agent-sql", "execute_sql", "database")
        d.record_request("agent-sql", "network_access", "exfil.com")
        d.record_request("agent-sql", "write_file", "/tmp/export")

        suspicious, score, reason = d.is_suspicious("agent-sql")
        assert suspicious is True

    def test_normal_sequence_passes(self):
        d = self.detector
        for _ in range(10):
            d.record_request("normal", "read_file", "/tmp/data")
        for _ in range(5):
            d.record_request("normal", "read_file", "/tmp/other")

        suspicious, _, _ = d.is_suspicious("normal")
        assert suspicious is False

    def test_history_depth_respected(self):
        d = self.detector
        for _ in range(5):
            d.record_request("deep", "read_file", "/tmp/x")
        d.record_request("deep", "network_access", "evil.com")

        history = d._transition_graph._agent_histories.get("deep", deque(maxlen=3))
        assert len(history) <= 3

    def test_full_history_used_for_3_step_check(self):
        graph = BehaviorTransitionGraph(history_depth=3)
        graph.record_transition("full", "read_file", "/etc")
        graph.record_transition("full", "execute_code", "malware")
        graph.record_transition("full", "network_access", "exfil")

        hist = graph._agent_histories.get("full", deque(maxlen=3))
        hist_list = list(hist)
        assert len(hist_list) == 3

        prev = hist_list[:-1]
        last = hist_list[-1]
        assert prev == ["read_file", "execute_code"]
        assert last == "network_access"

        suspicious, _, _ = graph.is_suspicious_sequence("full", prev, last)
        assert suspicious is True
