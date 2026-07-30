"""Read live telemetry from the host the agent is running on.

This is the endpoint-agent's view of the machine it protects: CPU, memory, swap,
disk, network throughput, open connections, and the busiest processes. It is
pure ``psutil`` with no UI dependency so the desktop app, the CLI, and the
console can all render the same numbers.

Network throughput and per-process CPU are *rates*, which require two samples to
compute. Use :class:`HostSampler` for a live view (it remembers the previous
counters between calls); use :func:`sample_once` for a one-shot snapshot.
"""
from __future__ import annotations

import socket
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List

try:
    import psutil
    _HAS_PSUTIL = True
except Exception:  # pragma: no cover - psutil is a declared dep, guard anyway
    psutil = None  # type: ignore
    _HAS_PSUTIL = False


def psutil_available() -> bool:
    return _HAS_PSUTIL


def _fmt_bytes(n: float) -> str:
    """Human-readable bytes (e.g. 1.4 GB)."""
    step = 1024.0
    for unit in ("B", "KB", "MB", "GB", "TB", "PB"):
        if abs(n) < step:
            return f"{n:.1f} {unit}" if unit != "B" else f"{int(n)} B"
        n /= step
    return f"{n:.1f} EB"


def _fmt_rate(bytes_per_sec: float) -> str:
    """Human-readable throughput (e.g. 240.5 KB/s)."""
    return f"{_fmt_bytes(bytes_per_sec)}/s"


def _fmt_duration(seconds: float) -> str:
    seconds = int(seconds)
    d, rem = divmod(seconds, 86400)
    h, rem = divmod(rem, 3600)
    m, _ = divmod(rem, 60)
    if d:
        return f"{d}d {h}h {m}m"
    if h:
        return f"{h}h {m}m"
    return f"{m}m"


@dataclass
class HostSampler:
    """Stateful sampler that computes network throughput and per-process CPU
    between successive :meth:`sample` calls."""

    top_n: int = 6
    _prev_net: Any = field(default=None, repr=False)
    _prev_t: float = field(default=0.0, repr=False)
    _proc_primed: bool = field(default=False, repr=False)

    def sample(self) -> Dict[str, Any]:
        """Return a full metrics snapshot. Network/proc rates are 0 on the first
        call (no previous sample to diff against) and correct thereafter."""
        if not _HAS_PSUTIL:
            return {"available": False, "error": "psutil not installed"}

        now = time.time()

        # ---- CPU ----
        cpu_percent = psutil.cpu_percent(interval=None)
        per_cpu = psutil.cpu_percent(interval=None, percpu=True)
        cpu_count = psutil.cpu_count(logical=True) or len(per_cpu)
        try:
            load1, load5, load15 = psutil.getloadavg()
        except (AttributeError, OSError):
            load1 = load5 = load15 = 0.0

        # ---- Memory ----
        vm = psutil.virtual_memory()
        sm = psutil.swap_memory()

        # ---- Disk ----
        du = psutil.disk_usage("/")

        # ---- Network throughput (rate over the inter-sample interval) ----
        net = psutil.net_io_counters()
        up_bps = down_bps = 0.0
        if self._prev_net is not None:
            dt = max(now - self._prev_t, 1e-6)
            up_bps = max(0.0, (net.bytes_sent - self._prev_net.bytes_sent) / dt)
            down_bps = max(0.0, (net.bytes_recv - self._prev_net.bytes_recv) / dt)
        self._prev_net, self._prev_t = net, now

        try:
            conn_count = len(psutil.net_connections(kind="inet"))
        except (psutil.AccessDenied, PermissionError, OSError):
            conn_count = -1  # not permitted (e.g. macOS without privileges)

        # ---- Top processes ----
        procs = self._top_processes()

        # ---- System info ----
        boot = psutil.boot_time()
        try:
            hostname = socket.gethostname()
        except OSError:
            hostname = "unknown"

        return {
            "available": True,
            "timestamp": now,
            "cpu": {
                "percent": round(cpu_percent, 1),
                "per_cpu": [round(c, 1) for c in per_cpu],
                "count": cpu_count,
                "load_avg": [round(load1, 2), round(load5, 2), round(load15, 2)],
            },
            "memory": {
                "percent": vm.percent,
                "used": vm.used, "total": vm.total,
                "used_h": _fmt_bytes(vm.used), "total_h": _fmt_bytes(vm.total),
            },
            "swap": {"percent": sm.percent, "used_h": _fmt_bytes(sm.used),
                     "total_h": _fmt_bytes(sm.total)},
            "disk": {
                "percent": du.percent,
                "used_h": _fmt_bytes(du.used), "total_h": _fmt_bytes(du.total),
            },
            "network": {
                "up_bps": up_bps, "down_bps": down_bps,
                "up_h": _fmt_rate(up_bps), "down_h": _fmt_rate(down_bps),
                "sent_total_h": _fmt_bytes(net.bytes_sent),
                "recv_total_h": _fmt_bytes(net.bytes_recv),
                "connections": conn_count,
            },
            "processes": procs,
            "system": {
                "hostname": hostname,
                "boot_time": boot,
                "uptime": _fmt_duration(now - boot),
                "process_count": len(psutil.pids()),
            },
        }

    def _top_processes(self) -> List[Dict[str, Any]]:
        rows = []
        for p in psutil.process_iter(["pid", "name", "cpu_percent", "memory_percent"]):
            try:
                info = p.info
                rows.append({
                    "pid": info["pid"],
                    "name": (info["name"] or "?")[:28],
                    "cpu": round(info.get("cpu_percent") or 0.0, 1),
                    "mem": round(info.get("memory_percent") or 0.0, 1),
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        # First pass primes cpu_percent (psutil returns 0 until the 2nd read),
        # so rank by memory on the very first sample, then by CPU thereafter.
        key = "mem" if not self._proc_primed else "cpu"
        self._proc_primed = True
        rows.sort(key=lambda r: (r[key], r["mem"]), reverse=True)
        return rows[: self.top_n]


def sample_once() -> Dict[str, Any]:
    """One-shot snapshot (network/CPU rates read once, so throughput is 0)."""
    return HostSampler().sample()
