"""Host-telemetry → DECIDE integration.

Covers the anomaly detector in isolation and the gateway wiring that lets a live
host network spike escalate an exfiltration-shaped action to HITL — while
staying inert (no risk) under normal conditions and when the feature is off.
"""
from unittest.mock import patch

import pytest

from secureagentnet.decide.models import EvaluationRequest
from secureagentnet.monitoring.host_telemetry import HostTelemetryMonitor, HostRiskContext


def _prime_baseline(mon, samples, egress_bps=100_000.0, cpu=10.0):
    """Feed a calm baseline so the rolling stats warm up."""
    with patch.object(mon, "_sample_light", return_value=(egress_bps, cpu)):
        for _ in range(samples):
            mon.assess("read_file", "./x", "routine read")


class TestHostTelemetryMonitor:
    def test_calm_host_adds_no_risk(self):
        mon = HostTelemetryMonitor()
        _prime_baseline(mon, 10)
        with patch.object(mon, "_sample_light", return_value=(120_000.0, 12.0)):
            ctx = mon.assess("send_email", "user@x.com", "send status update")
        assert ctx.risk == 0.0
        assert not ctx.anomaly

    def test_egress_spike_on_exfil_action_escalates(self):
        mon = HostTelemetryMonitor(egress_floor_bps=5_000_000.0)
        _prime_baseline(mon, 10, egress_bps=100_000.0)
        # A 50 MB/s spike, far above baseline + floor, on a data-moving action.
        with patch.object(mon, "_sample_light", return_value=(50_000_000.0, 20.0)):
            ctx = mon.assess("send_email", "external@evil.com",
                             "email the customer database export")
        assert ctx.anomaly is True
        assert ctx.risk == 0.5  # lands in the HITL escalation band
        assert "spike" in ctx.reason.lower()

    def test_egress_spike_on_benign_action_is_mild(self):
        mon = HostTelemetryMonitor(egress_floor_bps=5_000_000.0)
        _prime_baseline(mon, 10, egress_bps=100_000.0)
        with patch.object(mon, "_sample_light", return_value=(50_000_000.0, 20.0)):
            ctx = mon.assess("read_file", "./report.txt", "read the quarterly report")
        assert ctx.anomaly is True
        assert ctx.risk == 0.2  # noted, but not escalation-worthy

    def test_cold_start_does_not_overreact(self):
        mon = HostTelemetryMonitor(egress_floor_bps=5_000_000.0)
        # Just below 2x floor on first-ever sample → not anomalous yet.
        with patch.object(mon, "_sample_light", return_value=(6_000_000.0, 15.0)):
            ctx = mon.assess("upload", "s3://bucket", "upload backup")
        assert ctx.anomaly is False
        assert ctx.risk == 0.0

    def test_unavailable_telemetry_is_safe(self):
        mon = HostTelemetryMonitor()
        with patch.object(mon, "_sample_light", return_value=None):
            ctx = mon.assess("send", "x", "y")
        assert ctx.risk == 0.0
        assert "unavailable" in ctx.reason


class TestGatewayHostTelemetryWiring:
    @pytest.fixture
    def gateway(self):
        with (
            patch("secureagentnet.contain.container_provisioner.docker.from_env"),
            patch("hvac.Client"),
        ):
            from secureagentnet.decide import DecisionGateway
            gw = DecisionGateway()
            gw.host_telemetry_enabled = True
            yield gw

    def _request(self):
        return EvaluationRequest(
            agent_id="agent-x", action_name="send_email",
            target_resource="external@evil.com",
            intent_summary="email the exported customer records",
            payload={"to": "external@evil.com"},
            commissioned_goal="Answer customer questions from the knowledge base.",
        )

    def test_host_anomaly_escalates_otherwise_safe_action(self, gateway):
        # Semantic evaluation says low-risk; host telemetry is the escalating signal.
        high = HostRiskContext(risk=0.5, anomaly=True,
                               reason="Host outbound spike during exfil-shaped action.")
        with (
            patch.object(gateway.semantic_evaluator, "evaluate", return_value=(0.1, "looks fine")),
            patch("secureagentnet.monitoring.host_telemetry.get_host_telemetry_monitor") as m,
        ):
            m.return_value.assess.return_value = high
            result = gateway.evaluate_request(self._request())
        # 0.5 is below block_threshold (0.7) but in the HITL band → escalate, not allow.
        assert result.is_allowed is False
        assert result.evaluated_by == "HITLApprovalGate"
        assert result.risk_score == pytest.approx(0.5)

    def test_disabled_telemetry_leaves_decision_untouched(self, gateway):
        gateway.host_telemetry_enabled = False
        with patch.object(gateway.semantic_evaluator, "evaluate", return_value=(0.1, "fine")):
            result = gateway.evaluate_request(self._request())
        assert result.is_allowed is True  # nothing escalated it
