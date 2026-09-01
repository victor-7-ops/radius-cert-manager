from __future__ import annotations

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

    server_cert_days: int = 365
    site_renewal_stagger_window_days: int = 14

    radius_host: str
    radius_ssh_key: Path
    radius_ssh_user: str = "crlpush"

    alert_webhook_url: str | None = None
    expiry_alert_days: int = 7
    initial_superadmin_user: str | None = None

    # Hub self-monitoring (HANDOFF-FLEET.md §8.2) — when the hub itself is
    # down, the fleet view is down with it, so it needs a signal that
    # doesn't depend on the hub's own alerting path staying up.
    liveness_token: str | None = None
    # If set, GET /api/live/{liveness_token} returns 200 with no auth —
    # for an external check (CloudWatch Synthetics, healthchecks.io) that
    # can't hold an admin session. Unset disables the route entirely
    # (always 404), so it's opt-in, not exposed by default.
    heartbeat_url: str | None = None
    # If set, scripts/fleet_watch.py pings this URL on every successful
    # run — a dead-man's-switch endpoint (e.g. a CloudWatch alarm fed by
    # a Lambda, or healthchecks.io). Must be a DIFFERENT alerting path
    # than alert_webhook_url: if the hub is down, it can't tell you it's
    # down over its own webhook.

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
