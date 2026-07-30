"""Per-agent resource attribution: a sandbox's container counters are attributed
to its agent, so an egress/CPU/OOM anomaly raises that agent's rogue score."""
import pytest

from secureagentnet.identify.rogue_detector import RogueDetector


@pytest.fixture
def detector():
    return RogueDetector()


def test_egress_spike_flags_agent(detector):
    flagged, reason = detector.record_resource_usage(
        "ra-egress", {"network_tx_bytes": 50_000_000, "cpu_usage_percent": 5})
    assert flagged is True
    assert "exfiltration" in reason
    assert detector.get_profile_summary("ra-egress").get("resource_anomaly_count", 0) == 1 \
        or detector._get_profile("ra-egress").resource_anomaly_count == 1


def test_normal_egress_not_flagged(detector):
    flagged, _ = detector.record_resource_usage(
        "ra-normal", {"network_tx_bytes": 1_000_000, "cpu_usage_percent": 12})
    assert flagged is False


def test_cpu_saturation_flags_agent(detector):
    flagged, reason = detector.record_resource_usage(
        "ra-cpu", {"network_tx_bytes": 0, "cpu_usage_percent": 99})
    assert flagged is True
    assert "CPU" in reason


def test_oom_flags_agent(detector):
    flagged, reason = detector.record_resource_usage(
        "ra-oom", {"network_tx_bytes": 0, "cpu_usage_percent": 10}, oom_killed=True)
    assert flagged is True
    assert "OOM" in reason


def test_consistent_chatty_agent_not_repeatedly_flagged(detector):
    # A steady ~15 MB/run agent: above the floor but no spike vs its own baseline.
    aid = "ra-chatty"
    flagged_any = False
    for _ in range(10):
        f, _ = detector.record_resource_usage(aid, {"network_tx_bytes": 15_000_000})
        flagged_any = flagged_any or f
    # First sample (>2x floor is 20MB; 15MB<20MB) is not a cold-start spike, and
    # once the baseline settles at 15MB it stays quiet.
    assert flagged_any is False
    # ...but a sudden 80 MB burst after the baseline IS a spike.
    flagged, reason = detector.record_resource_usage(aid, {"network_tx_bytes": 80_000_000})
    assert flagged is True
    assert "exfiltration" in reason


def test_resource_anomaly_raises_anomaly_score(detector):
    aid = "ra-score"
    detector.record_resource_usage(aid, {"network_tx_bytes": 50_000_000})
    detector.record_resource_usage(aid, {"cpu_usage_percent": 99})
    score = detector.compute_anomaly_score(aid)
    assert score >= 0.4  # two resource anomalies contribute 0.2 each (capped 0.4)


def test_resource_anomalies_contribute_to_rogue_verdict(detector):
    aid = "ra-rogue"
    # Resource anomalies are one signal among several (defence in depth): two
    # sandbox anomalies (0.4) + capability escalation (0.3) + repeated failures
    # (0.3) combine to push the agent over the rogue threshold.
    detector.record_resource_usage(aid, {"network_tx_bytes": 90_000_000})
    detector.record_resource_usage(aid, {"cpu_usage_percent": 99})
    for _ in range(3):
        detector.record_capability_escalation_attempt(aid)
    for _ in range(11):
        detector.record_failure(aid)
    suspicious, score, _ = detector.is_suspicious(aid)
    assert suspicious is True
    assert score >= 0.8
    # And without the resource signal the same agent would score lower.
    other = "ra-rogue-noresource"
    for _ in range(3):
        detector.record_capability_escalation_attempt(other)
    for _ in range(11):
        detector.record_failure(other)
    assert detector.compute_anomaly_score(other) < score
