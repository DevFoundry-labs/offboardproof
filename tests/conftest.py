from __future__ import annotations

import os
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from offboardproof.auth import Actor, create_actor
from offboardproof.config import Settings
from offboardproof.db import connection_for, migrate, transaction
from offboardproof.enums import ApprovalDecision, RiskTier, Role
from offboardproof.providers.mock import MockProvider
from offboardproof.schemas import CaseCreate
from offboardproof.service import WorkflowService


def write_owner_only(path: Path, value: bytes) -> None:
    """Write secret test material with the same permissions production requires."""
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(value)


@dataclass
class World:
    settings: Settings
    service: WorkflowService
    actors: dict[Role, Actor]
    tokens: dict[Role, str]

    def create(self, *, risk: RiskTier = RiskTier.STANDARD, key: str = "case-key-0001") -> dict[str, object]:
        return self.service.create_case(
            self.actors[Role.HR],
            CaseCreate(
                subject_email="alex@example.test",
                subject_name="Alex Morgan",
                transfer_owner="owner@example.test",
                effective_at=datetime.now(UTC) - timedelta(seconds=1),
                risk_tier=risk,
                provider="mock",
            ),
            key,
        )

    def plan_and_approve(self, case_id: str, *, high: bool = False) -> dict[str, object]:
        self.service.plan_case(self.actors[Role.OPERATOR], case_id)
        self.service.approve_case(
            self.actors[Role.HR],
            case_id,
            decision=ApprovalDecision.APPROVED,
            reason="HR authorization confirmed",
        )
        result = self.service.approve_case(
            self.actors[Role.MANAGER],
            case_id,
            decision=ApprovalDecision.APPROVED,
            reason="Manager transfer confirmed",
        )
        if high:
            result = self.service.approve_case(
                self.actors[Role.SECURITY],
                case_id,
                decision=ApprovalDecision.APPROVED,
                reason="Security reviewed high risk departure",
            )
        return result


@pytest.fixture
def world(tmp_path) -> Iterator[World]:  # type: ignore[no-untyped-def]
    settings = Settings(
        database_path=tmp_path / "test.db",
        evidence_dir=tmp_path / "evidence",
        retry_delays_seconds="0,0",
    )
    migrate(settings)
    connection = connection_for(settings)
    actors: dict[Role, Actor] = {}
    tokens: dict[Role, str] = {}
    try:
        with transaction(connection):
            for role in Role:
                actor, token = create_actor(connection, f"Test {role.value}", role)
                actors[role] = actor
                tokens[role] = token
        MockProvider(connection).seed_account(
            "alex@example.test",
            groups=("engineering@example.test", "vpn@example.test"),
        )
    finally:
        connection.close()
    yield World(settings, WorkflowService(settings), actors, tokens)
