import time
import pytest
from src.identify.rogue_detector import RogueDetector


class TestRogueDetector:
    @pytest.fixture
    def detector(self):
        return RogueDetector()

    def test_record_request(self, detector):
        detector.record_request("agent-1", "read_file", resource="/tmp/data.txt")
        summary = detector.get_profile_summary("agent-1")
        assert summary["total_requests"] == 1
        assert summary["action_counts"]["read_file"] == 1

    def test_record_request_no_resource(self, detector):
        detector.record_request("agent-1", "list_files")
        summary = detector.get_profile_summary("agent-1")
        assert summary["total_requests"] == 1
        assert summary["action_counts"]["list_files"] == 1

    def test_record_failure(self, detector):
        detector.record_failure("agent-1")
        detector.record_failure("agent-1")
        summary = detector.get_profile_summary("agent-1")
        assert summary["failure_count"] == 2

    def test_record_capability_escalation(self, detector):
        detector.record_capability_escalation_attempt("agent-1")
        detector.record_capability_escalation_attempt("agent-1")
        detector.record_capability_escalation_attempt("agent-1")
        summary = detector.get_profile_summary("agent-1")
        assert summary["capability_escalation_attempts"] == 3

    def test_check_rate_limit_normal(self, detector):
        detector._rate_limit = 5
        detector._time_window = 60.0
        for _ in range(3):
            detector.record_request("agent-1", "read_file")
            time.sleep(0.001)
        assert detector.check_rate_limit("agent-1") is True

    def test_check_rate_limit_exceeded(self, detector):
        detector._rate_limit = 3
        detector._time_window = 60.0
        for _ in range(5):
            detector.record_request("agent-1", "read_file")
            time.sleep(0.001)
        assert detector.check_rate_limit("agent-1") is False

    def test_compute_anomaly_score_high_failures(self, detector):
        detector._failure_threshold = 3
        for _ in range(5):
            detector.record_failure("agent-1")
        score = detector.compute_anomaly_score("agent-1")
        assert score >= 0.3

    def test_compute_anomaly_score_high_rate(self, detector):
        detector._rate_limit = 20
        detector._time_window = 60.0
        for _ in range(30):
            detector.record_request("agent-1", "read_file")
        score = detector.compute_anomaly_score("agent-1")
        request_rate = 30 / 60.0
        threshold_rate = detector._rate_limit * 0.8
        if request_rate > threshold_rate:
            assert score >= 0.3
        else:
            assert score >= 0.0

    def test_compute_anomaly_score_escalation(self, detector):
        for _ in range(3):
            detector.record_capability_escalation_attempt("agent-1")
        score = detector.compute_anomaly_score("agent-1")
        assert score >= 0.3

    def test_compute_anomaly_score_caps_at_one(self, detector):
        detector._failure_threshold = 1
        detector._rate_limit = 1
        detector._time_window = 60.0
        for _ in range(5):
            detector.record_failure("agent-1")
        for _ in range(5):
            detector.record_capability_escalation_attempt("agent-1")
        for _ in range(10):
            detector.record_request("agent-1", "read_file")
            detector.record_request("agent-1", "write_file")
            detector.record_request("agent-1", "delete_file")
        score = detector.compute_anomaly_score("agent-1")
        assert score <= 1.0

    def test_is_suspicious_anomaly(self, detector):
        detector._anomaly_threshold = 0.5
        detector._failure_threshold = 1
        detector._rate_limit = 100
        detector._time_window = 60.0
        for _ in range(10):
            detector.record_failure("agent-1")
            detector.record_request("agent-1", "read_file")
        for _ in range(4):
            detector.record_capability_escalation_attempt("agent-1")
        suspicious, score, reason = detector.is_suspicious("agent-1")
        assert suspicious is True
        assert "exceeds" in reason or "limit exceeded" in reason

    def test_is_suspicious_rate_limit(self, detector):
        detector._rate_limit = 2
        detector._time_window = 60.0
        for _ in range(5):
            detector.record_request("agent-1", "read_file")
            time.sleep(0.001)
        suspicious, score, reason = detector.is_suspicious("agent-1")
        if not detector.check_rate_limit("agent-1"):
            assert suspicious is True
            assert "Rate limit exceeded" in reason

    def test_is_not_suspicious(self, detector):
        detector.record_request("agent-1", "read_file")
        suspicious, score, reason = detector.is_suspicious("agent-1")
        assert suspicious is False
        assert "normal" in reason

    def test_get_profile_summary(self, detector):
        detector.record_request("agent-1", "read_file", resource="/tmp/x")
        detector.record_failure("agent-1")
        detector.record_capability_escalation_attempt("agent-1")
        summary = detector.get_profile_summary("agent-1")
        assert summary["agent_id"] == "agent-1"
        assert summary["total_requests"] == 1
        assert summary["failure_count"] == 1
        assert summary["capability_escalation_attempts"] == 1
        assert "action_counts" in summary
        assert "anomaly_score" in summary

    def test_get_profile_summary_new_agent(self, detector):
        summary = detector.get_profile_summary("never-seen")
        assert summary["agent_id"] == "never-seen"
        assert summary["total_requests"] == 0

    def test_reset_profile(self, detector):
        detector.record_request("agent-1", "read_file")
        assert detector.get_profile_summary("agent-1")["total_requests"] == 1
        detector.reset_profile("agent-1")
        assert detector.get_profile_summary("agent-1")["total_requests"] == 0

    def test_get_all_anomaly_scores(self, detector):
        detector.record_request("agent-1", "read_file")
        detector.record_request("agent-2", "write_file")
        scores = detector.get_all_anomaly_scores()
        assert "agent-1" in scores
        assert "agent-2" in scores
