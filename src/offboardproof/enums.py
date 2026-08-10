from __future__ import annotations

from enum import StrEnum


class Role(StrEnum):
    ADMIN = "admin"
    HR = "hr"
    MANAGER = "manager"
    OPERATOR = "operator"
    SECURITY = "security"
    AUDITOR = "auditor"
    SERVICE = "service"


class RiskTier(StrEnum):
    STANDARD = "standard"
    HIGH = "high"


class CaseState(StrEnum):
    RECEIVED = "received"
    PLANNED = "planned"
    WAITING_APPROVAL = "waiting_approval"
    READY = "ready"
    EXECUTING = "executing"
    WAITING_MANUAL = "waiting_manual"
    VERIFYING = "verifying"
    EXCEPTION = "exception"
    COMPLETED = "completed"
    REJECTED = "rejected"
    CANCELLED = "cancelled"


class ControlState(StrEnum):
    PENDING = "pending"
    EXECUTING = "executing"
    ACKNOWLEDGED = "acknowledged"
    VERIFIED = "verified"
    EXCEPTION = "exception"
    WAIVED = "waived"


class ActionStatus(StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    RECONCILED = "reconciled"
    RETRY_PENDING = "retry_pending"
    UNKNOWN = "unknown"
    FAILED = "failed"


class JobStatus(StrEnum):
    QUEUED = "queued"
    LEASED = "leased"
    DONE = "done"
    DEAD = "dead"


class ExceptionStatus(StrEnum):
    OPEN = "open"
    RESOLVED = "resolved"


class ApprovalDecision(StrEnum):
    APPROVED = "approved"
    REJECTED = "rejected"


class OutcomeKind(StrEnum):
    OBSERVED = "observed"
    ACKNOWLEDGED = "acknowledged"
    RETRYABLE_FAILURE = "retryable_failure"
    PERMANENT_FAILURE = "permanent_failure"
    OUTCOME_UNKNOWN = "outcome_unknown"
