"""Feed host telemetry into the DECIDE pipeline as environmental risk context.

The endpoint watches the machine it protects (see :mod:`host_metrics`). This
module turns that stream into a *risk signal* the gateway can consult: if the
host shows an anomalous outbound-network spike while an agent requests an
exfiltration-shaped action, that coincidence is suspicious even when the action
looks benign in isolation — classic data-exfil (OWASP LLM06 / MITRE AML.T0025).

Design constraints, because this runs inside the request hot path and next to a
heavily-tested gateway:

* **Cheap.** A *light* psutil read (network counters + CPU) only — no process
  iteration, no connection enumeration.
* **Additive & bounded.** It can only *raise* risk toward the HITL escalation
  band; it never denies outright and never lowers a score.
* **Off by default.** Enabled via ``DECIDE_HOST_TELEMETRY`` so it changes no
  existing behaviour until a deployment opts in.
"""
from __future__ import annotations

import logging
import statistics
import threading
import time
from collections import deque
from dataclasses import dataclass
from typing import Optional

try:
    import psutil
    _HAS_PSUTIL = True
except Exception:  # pragma: no cover
    psutil = None  # type: ignore
    _HAS_PSUTIL = False

logger = logging.getLogger("SecureAgentNet.Decide.HostTelemetry")

# Action shapes that could move data off the host — the ones a network-egress
# spike is relevant to.
_EXFIL_SHAPED = (
    "send", "email", "upload", "post", "transfer", "exfil", "export",
    "curl", "wget", "http", "download", "sync", "push", "webhook", "fetch",
)


@dataclass
class HostRiskContext:
    """The risk contribution host telemetry adds to one decision."""
    risk: float = 0.0            # 0..1 contribution (max-merged into final score)
    anomaly: bool = False        # was the host itself anomalous?
    reason: str = ""             # human-readable explanation
    egress_bps: float = 0.0
    cpu_percent: float = 0.0

    def to_dict(self) -> dict:
        return {
            "risk": round(self.risk, 3), "anomaly": self.anomaly,
            "reason": self.reason, "egress_bps": round(self.egress_bps, 1),
            "cpu_percent": round(self.cpu_percent, 1),
        }


class HostTelemetryMonitor:
    """Maintains a rolling baseline of outbound throughput and flags spikes.

    ``assess`` returns a :class:`HostRiskContext`. The egress baseline needs a
    few samples to warm up; until then only the absolute floor can trip, so the
    monitor never over-reacts on a cold start.
    """

    def __init__(self, window: int = 30, sigma: float = 4.0,
                 egress_floor_bps: float = 5_000_000.0, cpu_ceiling: float = 96.0):
        self._egress: deque = deque(maxlen=window)
        self._prev_sent: Optional[float] = None
        self._prev_t = 0.0
        self._sigma = sigma
        self._egress_floor = egress_floor_bps
        self._cpu_ceiling = cpu_ceiling
        self._lock = threading.Lock()

    def _sample_light(self) -> Optional[tuple]:
        """(egress_bps, cpu_percent) from cheap counters, or None if unavailable."""
        if not _HAS_PSUTIL:
            return None
        now = time.time()
        try:
            net = psutil.net_io_counters()
            cpu = psutil.cpu_percent(interval=None)
        except Exception:  # noqa: BLE001
            return None
        egress = 0.0
        if self._prev_sent is not None:
            dt = max(now - self._prev_t, 1e-6)
            egress = max(0.0, (net.bytes_sent - self._prev_sent) / dt)
        self._prev_sent, self._prev_t = net.bytes_sent, now
        return egress, cpu

    def _egress_is_anomalous(self, egress_bps: float) -> bool:
        """Spike detection: above the absolute floor AND far above the rolling
        baseline (mean + sigma·stdev once enough history exists)."""
        if egress_bps < self._egress_floor:
            return False
        if len(self._egress) >= 8:
            mean = statistics.mean(self._egress)
            stdev = statistics.pstdev(self._egress) or 1.0
            return egress_bps > mean + self._sigma * stdev
        # Cold start: floor alone must be clearly exceeded.
        return egress_bps > self._egress_floor * 2

    def observe_egress(self, egress_bps: float) -> bool:
        """Update the baseline with one outbound-throughput sample and return
        whether it is anomalous. Used by the UI to show a live spike indicator
        with the same logic the gateway uses to escalate."""
        with self._lock:
            anomalous = self._egress_is_anomalous(egress_bps)
            self._egress.append(egress_bps)
        return anomalous

    @staticmethod
    def _is_exfil_shaped(action_name: str, target_resource: str, intent: str) -> bool:
        blob = f"{action_name} {target_resource} {intent}".lower()
        return any(k in blob for k in _EXFIL_SHAPED)

    def assess(self, action_name: str, target_resource: str,
               intent: str) -> HostRiskContext:
        with self._lock:
            sample = self._sample_light()
            if sample is None:
                return HostRiskContext(reason="host telemetry unavailable")
            egress_bps, cpu = sample
            anomalous = self._egress_is_anomalous(egress_bps)
            # Record AFTER the anomaly check so a spike doesn't poison its own
            # baseline on the very sample that detects it.
            self._egress.append(egress_bps)

        exfil = self._is_exfil_shaped(action_name, target_resource, intent)
        risk, reason = 0.0, ""
        if anomalous and exfil:
            # Strong coincidence: push into the HITL escalation band for review.
            risk = 0.5
            reason = (f"Host outbound-network spike ({egress_bps/1e6:.1f} MB/s) during "
                      f"an exfiltration-shaped action — escalating for review.")
        elif anomalous:
            risk = 0.2
            reason = f"Host outbound-network spike ({egress_bps/1e6:.1f} MB/s) noted."
        elif cpu >= self._cpu_ceiling and exfil:
            risk = 0.2
            reason = f"Host CPU saturated ({cpu:.0f}%) during a data-moving action."

        if risk:
            logger.warning("Host telemetry raised decision risk to %.2f: %s", risk, reason)
        return HostRiskContext(risk=risk, anomaly=anomalous, reason=reason,
                               egress_bps=egress_bps, cpu_percent=cpu)


_monitor: Optional[HostTelemetryMonitor] = None
_monitor_lock = threading.Lock()


def get_host_telemetry_monitor() -> HostTelemetryMonitor:
    """Process-wide singleton so the egress baseline persists across requests."""
    global _monitor
    if _monitor is None:
        with _monitor_lock:
            if _monitor is None:
                _monitor = HostTelemetryMonitor()
    return _monitor
