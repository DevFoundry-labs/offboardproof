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

    @property
    def retry_delays(self) -> tuple[int, ...]:
        values = tuple(int(value.strip()) for value in self.retry_delays_seconds.split(","))
        if not values or any(value < 0 for value in values):
            raise ValueError("OFFBOARDPROOF_RETRY_DELAYS_SECONDS must contain non-negative integers")
        return values

    def ensure_directories(self) -> None:
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        self.evidence_dir.mkdir(parents=True, exist_ok=True)
