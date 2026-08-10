from __future__ import annotations


class OffboardProofError(Exception):
    """Base domain error with a safe operator-facing message."""


class NotFoundError(OffboardProofError):
    pass


class ConflictError(OffboardProofError):
    pass


class AuthorizationError(OffboardProofError):
    pass


class InvalidTransitionError(ConflictError):
    pass


class ConfigurationError(OffboardProofError):
    pass


class ProviderError(OffboardProofError):
    def __init__(
        self,
        message: str,
        *,
        retryable: bool = False,
        outcome_unknown: bool = False,
        external_reference: str | None = None,
    ) -> None:
        super().__init__(message)
        self.retryable = retryable
        self.outcome_unknown = outcome_unknown
        self.external_reference = external_reference
