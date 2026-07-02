import pytest
from secureagentnet.identify.rogue_detector import BehaviorTransitionGraph, RogueDetector


class TestBehaviorTransitionGraph:
    def setup_method(self):
        self.graph = BehaviorTransitionGraph(history_depth=3)

    def test_record_transition(self):
        self.graph.record_transition("agent-1", "read_file", "/tmp/x")
        self.graph.record_transition("agent-1", "write_file", "/tmp/x")
        assert "agent-1" in self.graph._transitions
        assert len(self.graph._transitions["agent-1"]) == 1

    def test_suspicious_sequence_read_network_write(self):
        g = BehaviorTransitionGraph(history_depth=3)
        g.record_transition("a", "read_file", "/etc/passwd")
        g.record_transition("a", "network_access", "attacker.com")
        suspicious, score, reason = g.is_suspicious_sequence(
            "a", ["read_file", "network_access"], "write_file"
        )
        assert suspicious is True
        assert score >= 0.9

    def test_suspicious_sequence_exec_code_network(self):
        g = BehaviorTransitionGraph(history_depth=3)
        suspicious, score, reason = g.is_suspicious_sequence(
            "a", ["execute_code"], "network_access"
        )
        assert suspicious is True

    def test_normal_sequence_not_suspicious(self):
        g = BehaviorTransitionGraph(history_depth=3)
        for _ in range(10):
            g.record_transition("a", "read_file", "/tmp/x")
        suspicious, score, reason = g.is_suspicious_sequence(
            "a", ["read_file"], "read_file"
        )
        assert suspicious is False

    def test_transition_probability(self):
        g = BehaviorTransitionGraph(history_depth=3)
        for _ in range(9):
            g.record_transition("a", "read_file", "/tmp/x")
            g.record_transition("a", "write_file", "/tmp/x")
        g.record_transition("a", "read_file", "/tmp/x")
        g.record_transition("a", "network_access", "evil.com")
        prob = g.get_transition_probability("a", ["read_file"], "network_access")
        assert prob < 0.3

    def test_reset_agent(self):
        g = BehaviorTransitionGraph(history_depth=3)
        g.record_transition("a", "read_file")
        g.record_transition("a", "write_file")
        g.record_transition("a", "read_file")
        g.reset_agent("a")
        prob = g.get_transition_probability("a", ["read_file"], "write_file")
        assert prob == 0.5

    def test_intrinsic_suspicious_sequences_not_empty(self):
        assert len(BehaviorTransitionGraph.INTRINSIC_SUSPICIOUS_SEQUENCES) > 0

    def test_get_action_distribution(self):
        g = BehaviorTransitionGraph(history_depth=3)
        g.record_transition("a", "read_file")
        g.record_transition("a", "write_file")
        g.record_transition("a", "read_file")
        dist = g.get_action_distribution()
        assert dist["read_file"] >= 2
        assert dist["write_file"] >= 1


class TestRogueDetectorWithMarkov:
    def setup_method(self):
        self.detector = RogueDetector()

    def test_record_request_builds_transition_graph(self):
        self.detector.record_request("agent-m", "read_file", "/x")
        self.detector.record_request("agent-m", "network_access", "evil.com")
        graph = self.detector.get_transition_graph()
        assert graph is not None

    def test_is_suspicious_detects_bad_sequence(self):
        d = self.detector
        d.record_request("bad-agent", "read_file", "/etc/shadow")
        d.record_request("bad-agent", "network_access", "attacker.com")
        d.record_request("bad-agent", "execute_code", "reverse shell")
        suspicious, score, reason = d.is_suspicious("bad-agent")
        assert suspicious is True

    def test_is_suspicious_normal_sequence_passes(self):
        d = self.detector
        for _ in range(20):
            d.record_request("good-agent", "read_file", "/tmp/x")
        suspicious, _, _ = d.is_suspicious("good-agent")
        assert suspicious is False
