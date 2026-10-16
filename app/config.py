from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    database_url: str
    secret_key: str = Field(min_length=32)
    environment: str = "local"
    session_hours: int = Field(default=12, ge=1, le=168)
    cookie_secure: bool = False
    app_name: str = "HoneyForge"
    ca_cert_path: str = "/run/honeyforge-pki/ca.crt"
    ca_key_path: str = "/run/honeyforge-pki/ca.key"
    agent_gateway_peer_name: str = "agent-gateway"
    agent_certificate_days: int = Field(default=30, ge=1, le=365)
    agent_offline_after_seconds: int = Field(default=90, ge=15, le=3600)


@lru_cache
def get_settings() -> Settings:
    return Settings()
