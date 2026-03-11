from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    app_name: str = "CertShield"
    app_env: str = "development"
    secret_key: str = Field(default="change-me-in-production")
    session_cookie_name: str = "certshield_session"
    session_https_only: bool = False

    bind_host: str = "0.0.0.0"
    bind_port: int = 8000

    db_url: str = "sqlite:///./certshield.db"
    bootstrap_admin_user: str = "admin"
    bootstrap_admin_password: str = "ChangeMeNow!"
    collector_api_token: str = "collector-dev-token"


@lru_cache
def get_settings() -> Settings:
    return Settings()
