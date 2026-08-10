from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from offboardproof.audit import verify_chain
from offboardproof.db import connection_for
from offboardproof.enums import ApprovalDecision, RiskTier, Role
from offboardproof.errors import AuthorizationError, ConflictError, InvalidTransitionError, ProviderError
from offboardproof.evidence import build_evidence, write_evidence
from offboardproof.providers.base import Observation
from offboardproof.providers.mock import MockProvider
from offboardproof.worker import Worker


def _drain(worker: Worker) -> int:
    count = 0
    while worker.run_once():
        count += 1
        assert count < 20
    return count


def test_happy_path_is_replay_safe_and_seals_evidence(world) -> None:  # type: ignore[no-untyped-def]
    case = world.create()
    replay = world.create()
    assert replay["id"] == case["id"]
    ready = world.plan_and_approve(str(case["id"]))
    assert ready["state"] == "ready"
    assert _drain(Worker(world.settings)) == 4
    waiting = world.service.case_view(str(case["id"]))
    assert waiting["state"] == "waiting_manual"
    manual = next(item for item in waiting["controls"] if item["manual"] == 1)
    completed = world.service.complete_manual(
        world.actors[Role.MANAGER],
        str(case["id"]),
        manual["id"],
        "Transfer confirmed in synthetic ticket TEST-42",
    )
    assert completed["state"] == "completed"
    assert len(list(world.settings.evidence_dir.glob("*.evidence.json"))) == 1

    connection = connection_for(world.settings)
    try:
        first = build_evidence(connection, str(case["id"]))
        path, digest = write_evidence(connection, world.settings, str(case["id"]))
        second = build_evidence(connection, str(case["id"]))
        valid, count, broken = verify_chain(connection)
    finally:
        connection.close()
    assert first == second
    assert path.exists() and len(digest) == 64
    assert valid and count > 10 and broken is None


def test_transient_provider_failure_retries_then_recovers(world) -> None:  # type: ignore[no-untyped-def]
    connection = connection_for(world.settings)
    try:
        MockProvider(connection).seed_account(
            "alex@example.test",
            groups=("engineering@example.test",),
            fail_once_operation="sign_out_sessions",
        )
    finally:
        connection.close()
    case = world.create(key="retry-case-0001")
    world.plan_and_approve(str(case["id"]))
    assert _drain(Worker(world.settings)) == 4
    view = world.service.case_view(str(case["id"]))
    sign_out = next(item for item in view["controls"] if item["control_type"] == "sign_out_sessions")
    assert sign_out["state"] == "verified"
    assert any(event["event_type"] == "action.retry_scheduled" for event in world.service.audit_events(str(case["id"])))


def test_high_risk_requires_security_and_rejection_stops_case(world) -> None:  # type: ignore[no-untyped-def]
    case = world.create(risk=RiskTier.HIGH, key="high-risk-0001")
    world.service.plan_case(world.actors[Role.OPERATOR], str(case["id"]))
    world.service.approve_case(
        world.actors[Role.HR],
        str(case["id"]),
        decision=ApprovalDecision.APPROVED,
        reason="HR confirmed authority",
    )
    partial = world.service.approve_case(
        world.actors[Role.MANAGER],
        str(case["id"]),
        decision=ApprovalDecision.APPROVED,
        reason="Manager confirmed owner",
    )
    assert partial["state"] == "waiting_approval"
    rejected = world.service.approve_case(
        world.actors[Role.SECURITY],
        str(case["id"]),
        decision=ApprovalDecision.REJECTED,
        reason="Investigation remains open",
    )
    assert rejected["state"] == "rejected"
    assert not Worker(world.settings).run_once()


def test_authorization_and_invalid_transitions_are_enforced(world) -> None:  # type: ignore[no-untyped-def]
    with pytest.raises(AuthorizationError):
        world.service.create_case(world.actors[Role.AUDITOR], world.create.__annotations__, "bad-key-0001")  # type: ignore[arg-type]
    case = world.create(key="auth-case-0001")
    with pytest.raises(AuthorizationError):
        world.service.plan_case(world.actors[Role.HR], str(case["id"]))
    world.service.plan_case(world.actors[Role.OPERATOR], str(case["id"]))
    with pytest.raises(InvalidTransitionError):
        world.service.plan_case(world.actors[Role.OPERATOR], str(case["id"]))
    with pytest.raises(ConflictError):
        world.service.approve_case(
            world.actors[Role.MANAGER],
            str(case["id"]),
            decision=ApprovalDecision.APPROVED,
            reason="Trying wrong delegated role",
            as_role="hr",
        )


def test_security_can_waive_a_control_with_expiry(world) -> None:  # type: ignore[no-untyped-def]
    case = world.create(key="waiver-case-0001")
    world.plan_and_approve(str(case["id"]))
    view = world.service.case_view(str(case["id"]))
    control = next(item for item in view["controls"] if item["control_type"] == "remove_group")
    waived = world.service.waive_control(
        world.actors[Role.SECURITY],
        str(case["id"]),
        control["id"],
        reason="Emergency access exception approved by security",
        expires_at=datetime.now(UTC) + timedelta(days=1),
    )
    assert next(item for item in waived["controls"] if item["id"] == control["id"])["state"] == "waived"
    with pytest.raises(ValueError):
        world.service.waive_control(
            world.actors[Role.SECURITY],
            str(case["id"]),
            control["id"],
            reason="Expired emergency access exception",
            expires_at=datetime.now(UTC) - timedelta(days=1),
        )


def test_audit_tampering_is_detected(world) -> None:  # type: ignore[no-untyped-def]
    case = world.create(key="audit-case-0001")
    connection = connection_for(world.settings)
    try:
        connection.execute("UPDATE audit_events SET payload_json='{}' WHERE case_id=?", (case["id"],))
        valid, count, broken = verify_chain(connection)
    finally:
        connection.close()
    assert not valid and count == 0 and broken is not None


def test_permanent_failure_opens_exception_and_can_be_requeued(world, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    class FailingProvider:
        name = "failing"

        def observe(self, request) -> Observation:  # type: ignore[no-untyped-def]
            return Observation(request.subject_email, {"satisfied": False}, False)

        def execute(self, _request):  # type: ignore[no-untyped-def]
            raise ProviderError("synthetic permanent failure")

    case = world.create(key="exception-case-0001")
    world.plan_and_approve(str(case["id"]))
    monkeypatch.setattr("offboardproof.worker.get_provider", lambda *_args: FailingProvider())
    assert Worker(world.settings).run_once()
    failed = world.service.case_view(str(case["id"]))
    assert failed["state"] == "exception"
    exception = failed["exceptions"][0]
    requeued = world.service.requeue_exception(
        world.actors[Role.OPERATOR], exception["id"], "Provider configuration was corrected"
    )
    assert requeued["state"] == "ready"


def test_reverification_detects_drift(world) -> None:  # type: ignore[no-untyped-def]
    case = world.create(key="drift-case-0001")
    world.plan_and_approve(str(case["id"]))
    _drain(Worker(world.settings))
    connection = connection_for(world.settings)
    try:
        connection.execute("UPDATE mock_accounts SET suspended=0 WHERE subject_email='alex@example.test'")
    finally:
        connection.close()
    drifted = Worker(world.settings).verify_case(str(case["id"]))
    assert drifted["state"] == "exception"
    assert any(item["category"] == "verification_drift" for item in drifted["exceptions"])
