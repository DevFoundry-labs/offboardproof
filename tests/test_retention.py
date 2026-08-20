from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

import pytest
from conftest import World

from offboardproof.db import connection_for
from offboardproof.enums import Role
from offboardproof.errors import AuthorizationError, ConflictError
from offboardproof.retention import RetentionService
from offboardproof.schemas import CaseCreate


def test_default_and_explicit_retention_snapshots(world: World) -> None:
    default_case = world.create(key="retention-default-0001")
    default_until = datetime.fromisoformat(str(default_case["retention_until"]))
    created_at = datetime.fromisoformat(str(default_case["created_at"]))
    assert timedelta(days=364) < default_until - created_at <= timedelta(days=365)
    assert default_case["retention_policy_id"] == "default-365-days"

    explicit_until = datetime.now(UTC) + timedelta(days=30)
    explicit = world.service.create_case(
        world.actors[Role.HR],
        CaseCreate(
            subject_email="second@example.test",
            subject_name="Second Person",
            transfer_owner="owner@example.test",
            effective_at=datetime.now(UTC),
            provider="mock",
            retention_until=explicit_until,
            retention_policy_id="contract-30-days",
        ),
        "retention-explicit-0001",
    )
    assert datetime.fromisoformat(str(explicit["retention_until"])) == explicit_until
    assert explicit["retention_policy_id"] == "contract-30-days"

    events = world.service.audit_events(str(explicit["id"]))
    snapshot = next(event for event in events if event["event_type"] == "retention.snapshot_created")
    assert "contract-30-days" in snapshot["payload_json"]


def test_legal_hold_authorization_uniqueness_and_release(world: World) -> None:
    case = world.create(key="legal-hold-0001")
    retention = RetentionService(world.settings)
    with pytest.raises(AuthorizationError):
        retention.create_hold(world.actors[Role.OPERATOR], str(case["id"]), "Operator cannot hold evidence")

    created = retention.create_hold(
        world.actors[Role.SECURITY],
        str(case["id"]),
        "Security investigation remains open",
    )
    assert created["status"] == "active"
    with pytest.raises(ConflictError):
        retention.create_hold(
            world.actors[Role.SECURITY],
            str(case["id"]),
            "A second active hold is forbidden",
        )
    released = retention.release_hold(
        world.actors[Role.ADMIN],
        str(case["id"]),
        "Investigation closed with approval",
    )
    assert released["status"] == "released"
    assert released["released_by"] == world.actors[Role.ADMIN].id


def test_retention_report_is_non_mutating_digested_and_pii_free(world: World) -> None:
    case = world.create(key="retention-report-0001")
    connection = connection_for(world.settings)
    try:
        connection.execute(
            "UPDATE cases SET state='completed', retention_until=? WHERE id=?",
            ((datetime.now(UTC) - timedelta(days=1)).isoformat(), case["id"]),
        )
        events_before = int(connection.execute("SELECT COUNT(*) FROM audit_events").fetchone()[0])
    finally:
        connection.close()

    retention = RetentionService(world.settings)
    as_of = datetime.now(UTC)
    first = retention.report(world.actors[Role.AUDITOR], as_of)
    second = retention.report(world.actors[Role.AUDITOR], as_of)
    assert first["report_sha256"] == second["report_sha256"]
    assert first["cases"][0]["eligibility"] == "expired_review_required"
    rendered = json.dumps(first)
    assert "alex@example.test" not in rendered
    assert "Alex Morgan" not in rendered

    connection = connection_for(world.settings)
    try:
        assert int(connection.execute("SELECT COUNT(*) FROM audit_events").fetchone()[0]) == events_before
    finally:
        connection.close()

    metrics = world.service.metrics()
    assert "cases_retention_expired" in metrics
    assert "alex@example.test" not in json.dumps(metrics)


def test_retention_report_covers_non_destructive_categories(world: World) -> None:
    incomplete = world.create(key="retention-category-incomplete")
    future = world.create(key="retention-category-future")
    missing = world.create(key="retention-category-missing")
    held = world.create(key="retention-category-held")
    now = datetime.now(UTC)
    connection = connection_for(world.settings)
    try:
        connection.execute(
            "UPDATE cases SET state='completed', retention_until=? WHERE id=?",
            ((now + timedelta(days=1)).isoformat(), future["id"]),
        )
        connection.execute("UPDATE cases SET retention_until=NULL WHERE id=?", (missing["id"],))
        connection.execute(
            "UPDATE cases SET state='completed', retention_until=? WHERE id=?",
            ((now - timedelta(days=1)).isoformat(), held["id"]),
        )
    finally:
        connection.close()
    retention = RetentionService(world.settings)
    retention.create_hold(world.actors[Role.SECURITY], str(held["id"]), "Active litigation preservation hold")
    report = retention.report(world.actors[Role.OPERATOR], now)
    categories = {item["case_id"]: item["eligibility"] for item in report["cases"]}
    assert categories[str(incomplete["id"])] == "incomplete_case"
    assert categories[str(future["id"])] == "not_expired"
    assert categories[str(missing["id"])] == "missing_retention_policy"
    assert categories[str(held["id"])] == "active_legal_hold"
