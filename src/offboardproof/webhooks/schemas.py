from __future__ import annotations

from datetime import UTC, datetime, timedelta

from pydantic import Field, field_validator

from offboardproof.enums import RiskTier
from offboardproof.schemas import StrictModel
from offboardproof.util import normalize_email

IDENTIFIER_PATTERN = r"^[A-Za-z0-9._~-]{8,128}$"


class WebhookSubject(StrictModel):
    email: str
    display_name: str = Field(min_length=1, max_length=200)

    @field_validator("email")
    @classmethod
    def validate_email(cls, value: str) -> str:
        return normalize_email(value)


class WebhookDeparture(StrictModel):
    effective_at: datetime
    risk_tier: RiskTier = RiskTier.STANDARD
    transfer_owner_email: str

    @field_validator("effective_at")
    @classmethod
    def require_offset(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("effective_at must include an explicit UTC offset")
        return value.astimezone(UTC)

    @field_validator("transfer_owner_email")
    @classmethod
    def validate_email(cls, value: str) -> str:
        return normalize_email(value)


class WebhookWorkflow(StrictModel):
    provider: str = Field(pattern=r"^[a-z][a-z0-9_-]{1,31}$")


class WebhookEvent(StrictModel):
    schema_version: int = Field(ge=1, le=1)
    event_type: str = Field(pattern=r"^employee\.departure\.authorized$")
    event_id: str = Field(pattern=IDENTIFIER_PATTERN)
    occurred_at: datetime
    subject: WebhookSubject
    departure: WebhookDeparture
    workflow: WebhookWorkflow

    @field_validator("occurred_at")
    @classmethod
    def require_occurred_offset(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("occurred_at must include an explicit UTC offset")
        return value.astimezone(UTC)

    def validate_clock(self, now: datetime) -> None:
        if self.occurred_at > now.astimezone(UTC) + timedelta(minutes=5):
            raise ValueError("occurred_at cannot be more than five minutes in the future")
