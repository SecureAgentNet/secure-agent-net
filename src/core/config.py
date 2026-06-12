from functools import lru_cache
from pathlib import Path
import sys
import yaml
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field


class Settings(BaseSettings):
    environment: str = Field(default="development", alias="ENVIRONMENT")
    deploy_mode: str = Field(default="docker", alias="DEPLOY_MODE")

    database_url: str = Field(
        default=f"sqlite:///{Path.home() / '.secureagentnet' / 'data' / 'securenet.db'}",
        alias="DATABASE_URL"
    )

    vault_addr: str = Field(default="http://127.0.0.1:8200", alias="VAULT_ADDR")
    vault_token: str = Field(default="", alias="VAULT_TOKEN")

    ollama_api_url: str = Field(default="http://127.0.0.1:11434/api/generate", alias="OLLAMA_API_URL")
    ollama_model: str = Field(default="llama3.2:7b", alias="OLLAMA_MODEL")
    ollama_timeout: int = Field(default=30, alias="OLLAMA_TIMEOUT")
    ollama_retry_count: int = Field(default=2, alias="OLLAMA_RETRY_COUNT")
    # TTL (seconds) for cached Tier-3 verdicts; 0 disables caching.
    semantic_cache_ttl: int = Field(default=300, alias="SEMANTIC_CACHE_TTL")

    secret_key: str = Field(default="", alias="SECRET_KEY")
    agent_jwt_algorithm: str = Field(default="HS256", alias="AGENT_JWT_ALGORITHM")

    database_pool_size: int = Field(default=20, alias="DATABASE_POOL_SIZE")
    database_max_overflow: int = Field(default=10, alias="DATABASE_MAX_OVERFLOW")

    redis_host: str = Field(default="127.0.0.1", alias="REDIS_HOST")
    redis_port: int = Field(default=6379, alias="REDIS_PORT")
    redis_password: str = Field(default="", alias="REDIS_PASSWORD")

    mcp_port: int = Field(default=8443, alias="MCP_PORT")
    container_cpu_limit: float = Field(default=1.0, alias="CONTAINER_CPU_LIMIT")
    container_memory_limit: str = Field(default="512m", alias="CONTAINER_MEMORY_LIMIT")
    container_timeout_seconds: int = Field(default=60, alias="CONTAINER_TIMEOUT_SECONDS")

    presidio_score_threshold: float = Field(default=0.4, alias="PRESIDIO_SCORE_THRESHOLD")
    jwt_expiration: int = Field(default=3600, alias="JWT_EXPIRATION")
    kill_switch_threshold: int = Field(default=3, alias="KILL_SWITCH_THRESHOLD")
    circuit_breaker_timeout: int = Field(default=60, alias="CIRCUIT_BREAKER_TIMEOUT")
    block_threshold: float = Field(default=0.7, alias="BLOCK_THRESHOLD")

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        populate_by_name=True,
        extra="ignore",
    )

    def resolve_secret_key(self) -> str:
        if self.secret_key:
            return self.secret_key
        if self.environment == "production":
            raise RuntimeError(
                "SECRET_KEY is not set. Refusing to start in production with a "
                "generated or default key — set SECRET_KEY in the environment or .env."
            )
        return "dev-secret-key-do-not-use-in-production"

    @classmethod
    def _load_yaml_defaults(cls) -> dict:
        yaml_path = Path(__file__).parent.parent.parent / "config" / "settings.yaml"
        if not yaml_path.exists():
            return {}
        try:
            with open(yaml_path) as f:
                raw = yaml.safe_load(f) or {}
            cfg = raw.get("secureagentnet", raw)
            mapping = {
                "environment": "environment",
                "deploy_mode": "deploy_mode",
                "contain.cpu_limit": "container_cpu_limit",
                "contain.container_timeout_seconds": "container_timeout_seconds",
                "decide.block_threshold": "block_threshold",
                "decide.kill_switch.denial_threshold": "kill_switch_threshold",
                "decide.presidio_score_threshold": "presidio_score_threshold",
                "decide.circuit_breaker.time_window_seconds": "circuit_breaker_timeout",
            }
            flat = {}
            for dotted_key, settings_field in mapping.items():
                parts = dotted_key.split(".")
                val = cfg
                for p in parts:
                    val = val.get(p, {}) if isinstance(val, dict) else None
                    if val is None:
                        break
                if val is not None and not isinstance(val, dict):
                    flat[settings_field] = val
            if "contain.memory_limit_mb" in str(raw):
                parts = "contain.memory_limit_mb".split(".")
                val = cfg
                for p in parts:
                    val = val.get(p, {}) if isinstance(val, dict) else None
                    if val is None:
                        break
                if val is not None and not isinstance(val, dict):
                    flat["container_memory_limit"] = f"{val}m"
            return flat
        except Exception:
            return {}


@lru_cache()
def get_settings() -> Settings:
    return Settings(**Settings._load_yaml_defaults())
