"""Configuration for the SecureAgentNet Cloud Console backend.

Defaults to a local SQLite database so the whole console runs on a laptop for
development and the presentation demo; set ``SAN_CLOUD_DATABASE_URL`` to a
PostgreSQL URL for the VPS deployment.
"""
from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class CloudSettings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="SAN_CLOUD_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # Bind address for the console API/dashboard.
    host: str = Field(default="0.0.0.0")
    port: int = Field(default=8800)

    # Where local state lives when running on SQLite.
    data_dir: Path = Field(default_factory=lambda: Path.home() / ".secureagentnet-cloud")

    # Empty → derived SQLite path under data_dir. Set to a postgresql:// URL in prod.
    database_url: str = Field(default="")

    # Session/JWT signing for the admin console.
    secret_key: str = Field(default="dev-cloud-secret-change-me")

    # Optional seed admin (created on startup if both are set and no admin exists).
    admin_email: str = Field(default="")
    admin_password: str = Field(default="")

    # An endpoint is considered offline if no heartbeat within this window.
    heartbeat_timeout_seconds: int = Field(default=60)

    @property
    def resolved_database_url(self) -> str:
        if self.database_url:
            return self.database_url
        return f"sqlite:///{self.data_dir / 'console.db'}"


@lru_cache
def get_cloud_settings() -> CloudSettings:
    return CloudSettings()
