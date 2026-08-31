"""Daemon-specific configuration for the SecureAgentNet desktop engine."""
from __future__ import annotations

import os
from pathlib import Path
from typing import Optional

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class DaemonSettings(BaseSettings):
    """Settings for the background engine / middleware daemon."""

    model_config = SettingsConfigDict(
        env_prefix="SAN_",
        env_file=str(Path.home() / ".secureagentnet" / ".env"),
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # Host / port for the local middleware API. We default to loopback only so
    # the daemon is not exposed to the network.
    daemon_host: str = Field(default="127.0.0.1")
    daemon_port: int = Field(default=17541)

    # Unix socket path on Linux. If set and the platform supports it, the SDK
    # will prefer the socket over TCP for lower latency and no port conflicts.
    daemon_socket_path: Optional[str] = Field(default=None)

    # Discovery scheduler interval (seconds)
    discovery_interval_seconds: int = Field(default=300)

    # Data / runtime directories
    data_dir: Path = Field(default_factory=lambda: Path.home() / ".secureagentnet")

    # Notification behavior
    desktop_notifications: bool = Field(default=True)
    alert_history_limit: int = Field(default=1000)

    # Cloud scanning
    cloud_scan_url: Optional[str] = Field(default=None)
    cloud_scan_api_key: Optional[str] = Field(default=None)
    cloud_scan_timeout_seconds: int = Field(default=10)
    cloud_scan_demo_mode: bool = Field(default=False)

    # Cloud Console reporting (central Webroot-style console). Enrollment creds
    # live in <data_dir>/cloud.json, written by `san cloud enroll`.
    cloud_report_interval_seconds: int = Field(default=15)

    @property
    def pid_file(self) -> Path:
        return self.data_dir / "daemon.pid"

    @property
    def alerts_file(self) -> Path:
        return self.data_dir / "alerts.jsonl"

    @property
    def database_url(self) -> str:
        """The database the daemon reads — delegated, never resolved separately.

        This used to compute its own answer from os.environ plus a default beside
        the daemon's data dir. Nothing consumed it: every read and write goes
        through database.connection, which asks core.config. So the two could
        disagree, and the value reported here was not the database in use.
        One resolver means they cannot drift apart again.
        """
        from secureagentnet.core.config import get_settings
        return get_settings().database_url


_daemon_settings: Optional[DaemonSettings] = None


def get_daemon_settings() -> DaemonSettings:
    global _daemon_settings
    if _daemon_settings is None:
        _daemon_settings = DaemonSettings()
    return _daemon_settings
