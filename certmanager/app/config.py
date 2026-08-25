from pathlib import Path

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="forbid")

    secret_key: str
    pki_path: Path
    db_path: Path
    bind_host: str
    bind_port: int = 8443

    client_cert_days: int = 365
    crl_validity_days: int = 7
    crl_regen_hours: int = 24

    radius_host: str
    radius_ssh_key: Path
    radius_ssh_user: str = "crlpush"

    alert_webhook_url: str | None = None
    initial_superadmin_user: str | None = None

    @field_validator("secret_key")
    @classmethod
    def secret_key_min_length(cls, v: str) -> str:
        if len(v) < 32:
            raise ValueError("SECRET_KEY must be at least 32 characters")
        return v

    @field_validator("pki_path", "radius_ssh_key")
    @classmethod
    def path_must_be_absolute(cls, v: Path) -> Path:
        if not v.is_absolute():
            raise ValueError(f"path must be absolute: {v}")
        return v


def load_settings() -> Settings:
    # Fails fast on missing/malformed env — this is intentional (handoff §11).
    return Settings()
