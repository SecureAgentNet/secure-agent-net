"""Process management helpers for the SecureAgentNet daemon."""
from __future__ import annotations

import os
import signal
import subprocess
import sys
import time
from pathlib import Path
from typing import Optional, Tuple

import psutil

from secureagentnet.daemon.config import DaemonSettings, get_daemon_settings


def read_pid(pid_file: Path) -> Optional[int]:
    if not pid_file.exists():
        return None
    try:
        return int(pid_file.read_text().strip())
    except Exception:
        return None


def remove_pid_file(pid_file: Path) -> None:
    """Best-effort cleanup; status must still work on read-only installs."""
    try:
        pid_file.unlink(missing_ok=True)
    except OSError:
        pass


def is_running(pid: Optional[int]) -> bool:
    if pid is None:
        return False
    try:
        return psutil.pid_exists(pid) and psutil.Process(pid).status() != psutil.STATUS_ZOMBIE
    except Exception:
        return False


def start_daemon(settings: Optional[DaemonSettings] = None, daemonize: bool = True) -> Tuple[bool, str]:
    settings = settings or get_daemon_settings()
    pid = read_pid(settings.pid_file)
    if is_running(pid):
        return False, f"Daemon already running (PID: {pid})"

    # Clean up stale PID file if any.
    settings.pid_file.unlink(missing_ok=True)

    cmd = [
        sys.executable,
        "-m",
        "secureagentnet.daemon.daemon",
    ]
    if daemonize and sys.platform != "win32":
        cmd.append("--daemonize")

    try:
        if daemonize and sys.platform != "win32":
            subprocess.Popen(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True,
            )
        else:
            subprocess.Popen(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0,
            )

        # Wait briefly for PID file to be written.
        for _ in range(20):
            time.sleep(0.1)
            pid = read_pid(settings.pid_file)
            if is_running(pid):
                return True, f"Daemon started (PID: {pid})"
        return False, "Daemon started but PID file not detected"
    except Exception as exc:
        return False, f"Failed to start daemon: {exc}"


def stop_daemon(settings: Optional[DaemonSettings] = None) -> Tuple[bool, str]:
    settings = settings or get_daemon_settings()
    pid = read_pid(settings.pid_file)
    if not is_running(pid):
        settings.pid_file.unlink(missing_ok=True)
        return False, "Daemon not running"

    try:
        if sys.platform == "win32":
            psutil.Process(pid).terminate()
        else:
            os.kill(pid, signal.SIGTERM)

        # Wait for process to exit.
        for _ in range(30):
            if not is_running(pid):
                settings.pid_file.unlink(missing_ok=True)
                return True, f"Daemon stopped (PID: {pid})"
            time.sleep(0.2)

        # Force kill if still running.
        if sys.platform == "win32":
            psutil.Process(pid).kill()
        else:
            os.kill(pid, signal.SIGKILL)
        settings.pid_file.unlink(missing_ok=True)
        return True, f"Daemon killed (PID: {pid})"
    except Exception as exc:
        return False, f"Failed to stop daemon: {exc}"


def restart_daemon(settings: Optional[DaemonSettings] = None, daemonize: bool = True) -> Tuple[bool, str]:
    stop_daemon(settings=settings)
    return start_daemon(settings=settings, daemonize=daemonize)


def daemon_status(settings: Optional[DaemonSettings] = None) -> Tuple[bool, str]:
    settings = settings or get_daemon_settings()
    pid = read_pid(settings.pid_file)
    if is_running(pid):
        return True, f"Daemon running (PID: {pid})"
    if pid is not None:
        remove_pid_file(settings.pid_file)
        return False, "Daemon not running (stale PID file detected)"
    return False, "Daemon not running"
