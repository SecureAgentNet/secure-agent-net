from functools import lru_cache
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field


class Settings(BaseSettings):
    """
    Core configuration settings for SecureAgentNet.
    Automatically loads from environment variables or a .env file.
    """
    
    # Environment
    environment: str = Field(default="development", alias="ENVIRONMENT")
    
    # Database Settings
    database_url: str = Field(
        default="postgresql://secureagent:securepassword@localhost:5432/secureagentnet", 
        alias="DATABASE_URL"
    )
    
    # Vault Settings
    vault_addr: str = Field(default="http://127.0.0.1:8200", alias="VAULT_ADDR")
    vault_token: str = Field(default="root", alias="VAULT_TOKEN")
    
    # LLM Evaluator (Ollama) Settings
    ollama_api_url: str = Field(default="http://localhost:11434/api/generate", alias="OLLAMA_API_URL")
    ollama_model: str = Field(default="llama2:latest", alias="OLLAMA_MODEL")
    
    # General Security
    secret_key: str = Field(default="fallback_secret_for_tests", alias="SECRET_KEY")
    agent_jwt_algorithm: str = Field(default="HS256", alias="AGENT_JWT_ALGORITHM")

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        populate_by_name=True,
        extra="ignore"
    )


@lru_cache()
def get_settings() -> Settings:
    """
    Dependency to get the current settings.
    Uses lru_cache so the configuration is only loaded once per execution.
    """
    return Settings()
