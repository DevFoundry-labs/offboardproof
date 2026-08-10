from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol


@dataclass(frozen=True)
class Discovery:
    subject_email: str
    external_id: str
    suspended: bool
    signed_out: bool | None
    groups: tuple[str, ...] = ()
    raw: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ActionRequest:
    action_id: str
    idempotency_key: str
    operation: str
    subject_email: str
    target: str
    desired: dict[str, Any]


@dataclass(frozen=True)
class ActionReceipt:
    external_reference: str
    acknowledged: bool = True
    details: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class Observation:
    external_id: str | None
    observed: dict[str, Any]
    satisfied: bool
    quality: str = "observed"


class Provider(Protocol):
    name: str

    def discover(self, subject_email: str) -> Discovery: ...

    def execute(self, request: ActionRequest) -> ActionReceipt: ...

    def observe(self, request: ActionRequest) -> Observation: ...
