from __future__ import annotations

from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="OFFBOARDPROOF_", env_file=".env", extra="ignore")

    database_path: Path = Field(default=Path(".offboardproof/offboardproof.db"))
    evidence_dir: Path = Field(default=Path(".offboardproof/evidence"))
    enable_external_writes: bool = False
    log_level: str = "INFO"
    worker_lease_seconds: int = Field(default=30, ge=5, le=600)
    retry_delays_seconds: str = "1,4,16"
    google_service_account_file: Path | None = None
    google_delegated_admin: str | None = None
    webhook_config_file: Path | None = None
    webhook_max_body_bytes: int = Field(default=65_536, ge=8_192, le=262_144)
    webhook_timestamp_skew_seconds: int = Field(default=300, ge=30, le=3_600)
    signing_key_file: Path | None = None
    signing_key_password_file: Path | None = None
    signing_key_id: str | None = Field(default=None, pattern=r"^[A-Za-z0-9._~-]{1,128}$")
    require_signed_evidence: bool = False
    default_retention_days: int = Field(default=365, ge=1, le=3_650)
    default_retention_policy_id: str = Field(default="default-365-days", pattern=r"^[A-Za-z0-9._~-]{1,128}$")
    max_retention_days: int = Field(default=3_650, ge=1, le=36_500)
    retention_expiring_horizon_days: int = Field(default=30, ge=1, le=365)

    @property
    def retry_delays(self) -> tuple[int, ...]:
        values = tuple(int(value.strip()) for value in self.retry_delays_seconds.split(","))
        if not values or any(value < 0 for value in values):
            raise ValueError("OFFBOARDPROOF_RETRY_DELAYS_SECONDS must contain non-negative integers")
        return values

    def ensure_directories(self) -> None:
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        self.evidence_dir.mkdir(parents=True, exist_ok=True)
