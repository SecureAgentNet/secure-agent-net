"""Real-time alert broadcast for the SecureAgentNet daemon.

The daemon pushes every blocked/critical action to:
  - an on-disk JSONL alert history file,
  - all connected WebSocket subscribers (e.g. the desktop GUI),
  - native desktop notifications when available.
"""
from __future__ import annotations

import asyncio
import json
import logging
import platform
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from secureagentnet.daemon.config import DaemonSettings, get_daemon_settings

logger = logging.getLogger("SecureAgentNet.Daemon.Alerts")


class AlertManager:
    """Manages security alert broadcast, persistence, and desktop notifications."""

    def __init__(self, settings: Optional[DaemonSettings] = None):
        self.settings = settings or get_daemon_settings()
        self._subscribers: List[asyncio.Queue] = []
        self._lock = asyncio.Lock()
        self._ensure_files()

    def _ensure_files(self) -> None:
        self.settings.data_dir.mkdir(parents=True, exist_ok=True)
        self.settings.alerts_file.touch(exist_ok=True)

    async def subscribe(self) -> asyncio.Queue:
        """Return a queue that receives new alerts as they are emitted."""
        queue: asyncio.Queue = asyncio.Queue(maxsize=128)
        async with self._lock:
            self._subscribers.append(queue)
        return queue

    async def unsubscribe(self, queue: asyncio.Queue) -> None:
        async with self._lock:
            if queue in self._subscribers:
                self._subscribers.remove(queue)

    async def emit(
        self,
        severity: str,
        title: str,
        message: str,
        metadata: Optional[Dict[str, Any]] = None,
        notify_desktop: bool = True,
        phase: Optional[str] = None,
    ) -> None:
        """Persist, broadcast, and optionally show a desktop notification.

        ``phase`` is the ITCD phase the alert belongs to. Alerts that omit it
        used to be rendered as DECIDE by the desktop, so an agent-discovery
        notice appeared in the operator's activity table as though a decision
        had been made about it.
        """
        alert = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "severity": severity,
            "title": title,
            "message": message,
            "phase": phase,
            "metadata": metadata or {},
        }

        # Persist to disk.
        await asyncio.to_thread(self._append_alert_file, alert)

        # Broadcast to subscribers.
        dead: List[asyncio.Queue] = []
        async with self._lock:
            for queue in self._subscribers:
                try:
                    queue.put_nowait(alert)
                except asyncio.QueueFull:
                    dead.append(queue)
            for queue in dead:
                self._subscribers.remove(queue)

        # Native desktop notification.
        if notify_desktop and self.settings.desktop_notifications:
            await asyncio.to_thread(self._desktop_notify, title, message, severity)

        logger.warning("Alert emitted: %s - %s", severity, title)

    def _append_alert_file(self, alert: Dict[str, Any]) -> None:
        try:
            with open(self.settings.alerts_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(alert, default=str) + "\n")
        except Exception as exc:
            logger.error("Failed to write alert file: %s", exc)

    def _desktop_notify(self, title: str, message: str, severity: str) -> None:
        system = platform.system()
        try:
            if system == "Linux":
                self._linux_notify(title, message, severity)
            elif system == "Windows":
                self._windows_notify(title, message, severity)
            elif system == "Darwin":
                self._macos_notify(title, message, severity)
        except Exception as exc:
            logger.debug("Desktop notification unavailable: %s", exc)

    def _linux_notify(self, title: str, message: str, severity: str) -> None:
        if not shutil.which("notify-send"):
            return
        icon = "dialog-warning" if severity in ("WARNING", "ERROR", "CRITICAL") else "dialog-information"
        subprocess.run(
            ["notify-send", "-i", icon, "-u", "normal", title, message],
            check=False,
            capture_output=True,
        )

    def _windows_notify(self, title: str, message: str, severity: str) -> None:
        # Use PowerShell/BurntToast if available; silently skip otherwise.
        try:
            subprocess.run(
                [
                    "powershell.exe",
                    "-Command",
                    f"Add-Type -AssemblyName System.Windows.Forms; "
                    f"[System.Windows.Forms.MessageBox]::Show('{message}', '{title}')",
                ],
                check=False,
                capture_output=True,
            )
        except Exception:
            pass

    def _macos_notify(self, title: str, message: str, severity: str) -> None:
        if not shutil.which("osascript"):
            return
        script = f'display notification "{message}" with title "{title}"'
        subprocess.run(["osascript", "-e", script], check=False, capture_output=True)

    def recent_alerts(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Read the most recent alerts from disk."""
        alerts: List[Dict[str, Any]] = []
        if not self.settings.alerts_file.exists():
            return alerts
        try:
            with open(self.settings.alerts_file, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        alerts.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
        except Exception as exc:
            logger.error("Failed to read alert file: %s", exc)
        return alerts[-limit:]
