"""Host telemetry for SecureAgentNet's endpoint agent.

`host_metrics` reads the machine the agent runs on — CPU, memory, disk, live
network throughput, and the top processes — so the desktop, CLI, and console can
all present a Webroot-style view of the protected host. Pure psutil; no UI
dependency.
"""
from secureagentnet.monitoring.host_metrics import HostSampler, sample_once

__all__ = ["HostSampler", "sample_once"]
