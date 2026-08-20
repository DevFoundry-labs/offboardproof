from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from offboardproof.enums import ApprovalDecision, RiskTier
from offboardproof.util import normalize_email


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class CaseCreate(StrictModel):
    subject_email: str
    subject_name: str = Field(min_length=1, max_length=200)
    transfer_owner: str
    effective_at: datetime
    risk_tier: RiskTier = RiskTier.STANDARD
    provider: str = Field(default="mock", pattern=r"^[a-z][a-z0-9_-]{1,31}$")
    retention_until: datetime | None = None
    retention_policy_id: str | None = Field(default=None, pattern=r"^[A-Za-z0-9._~-]{1,128}$")

    @field_validator("subject_email", "transfer_owner")
    @classmethod
    def validate_email(cls, value: str) -> str:
        return normalize_email(value)

    @field_validator("retention_until")
    @classmethod
    def validate_retention_until(cls, value: datetime | None) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("retention_until must include an explicit UTC offset")
        return value.astimezone(UTC)


class ApprovalCreate(StrictModel):
    decision: ApprovalDecision
    reason: str = Field(min_length=3, max_length=500)
    as_role: str | None = Field(default=None, pattern=r"^(hr|manager|security)$")


class ManualComplete(StrictModel):
    evidence_note: str = Field(min_length=5, max_length=2000)


class WaiverCreate(StrictModel):
    reason: str = Field(min_length=10, max_length=1000)
    expires_at: datetime


class RequeueCreate(StrictModel):
    resolution_note: str = Field(min_length=5, max_length=1000)


class LegalHoldCreate(StrictModel):
    reason: str = Field(min_length=10, max_length=1000)


class LegalHoldRelease(StrictModel):
    reason: str = Field(min_length=10, max_length=1000)


class ActorView(StrictModel):
    id: str
    name: str
    role: str


class CaseView(StrictModel):
    id: str
    idempotency_key: str
    subject_email: str
    subject_name: str
    transfer_owner: str
    effective_at: str
    risk_tier: str
    provider: str
    state: str
    plan_version: int
    plan_digest: str | None
    required_roles: list[str]
    controls: list[dict[str, Any]] = Field(default_factory=list)
    approvals: list[dict[str, Any]] = Field(default_factory=list)
    exceptions: list[dict[str, Any]] = Field(default_factory=list)
    created_at: str
    updated_at: str
    completed_at: str | None


class TokenCreated(StrictModel):
    actor: ActorView
    token: str
    warning: str = "Store this token securely; it will not be shown again."
