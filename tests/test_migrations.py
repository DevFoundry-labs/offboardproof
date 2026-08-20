from __future__ import annotations

import sqlite3
from importlib.resources import files
from pathlib import Path

import pytest

from offboardproof.config import Settings
from offboardproof.db import SCHEMA_VERSION, connection_for, migrate


def _columns(connection: sqlite3.Connection, table: str) -> set[str]:
    return {str(row["name"]) for row in connection.execute(f"PRAGMA table_info({table})").fetchall()}


def test_clean_install_and_repeated_migration(tmp_path) -> None:  # type: ignore[no-untyped-def]
    settings = Settings(database_path=tmp_path / "clean.db", evidence_dir=tmp_path / "evidence")

    assert migrate(settings) == SCHEMA_VERSION
    assert migrate(settings) == SCHEMA_VERSION

    connection = connection_for(settings)
    try:
        assert int(connection.execute("PRAGMA user_version").fetchone()[0]) == 4
        assert {"retention_until", "retention_policy_id"} <= _columns(connection, "cases")
        assert {
            "schema_version",
            "manifest_path",
            "evidence_sha256",
            "signing_status",
            "signing_algorithm",
            "signing_key_id",
            "public_key_fingerprint",
            "completion_event_hash",
        } <= _columns(connection, "evidence_artifacts")
        assert connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='webhook_deliveries'"
        ).fetchone()
        assert connection.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='legal_holds'").fetchone()
        assert connection.execute("PRAGMA foreign_key_check").fetchall() == []
    finally:
        connection.close()


def test_real_v1_fixture_upgrades_without_data_loss(tmp_path) -> None:  # type: ignore[no-untyped-def]
    database_path = tmp_path / "upgrade.db"
    connection = sqlite3.connect(database_path)
    try:
        initial_sql = files("offboardproof").joinpath("migrations", "0001_initial.sql").read_text(encoding="utf-8")
        connection.executescript(initial_sql)
        connection.execute("PRAGMA user_version = 1")
        connection.execute(
            """
            INSERT INTO actors (id, name, role, token_digest, token_prefix, active, created_at)
            VALUES ('actor-1', 'Fixture HR', 'hr', 'digest', 'prefix', 1, '2026-08-01T00:00:00Z')
            """
        )
        connection.execute(
            """
            INSERT INTO cases (
                id, organization_id, idempotency_key, subject_email, subject_name, transfer_owner,
                effective_at, risk_tier, provider, state, created_by, created_at, updated_at
            ) VALUES (
                'case-1', 'local', 'fixture-key', 'person@example.test', 'Fixture Person',
                'owner@example.test', '2026-08-02T00:00:00Z', 'standard', 'mock', 'received',
                'actor-1', '2026-08-01T00:00:00Z', '2026-08-01T00:00:00Z'
            )
            """
        )
        connection.execute(
            """
            INSERT INTO evidence_artifacts (id, case_id, path, sha256, mime_type, created_at)
            VALUES ('evidence-1', 'case-1', 'fixture.json', ?, 'application/json', '2026-08-03T00:00:00Z')
            """,
            ("a" * 64,),
        )
        connection.execute(
            """
            INSERT INTO audit_events (
                event_id, case_id, actor_id, event_type, payload_json, previous_hash, event_hash, created_at
            ) VALUES ('event-1', 'case-1', 'actor-1', 'fixture.created', '{}', ?, ?, '2026-08-01T00:00:00Z')
            """,
            ("0" * 64, "b" * 64),
        )
        connection.commit()
    finally:
        connection.close()

    settings = Settings(database_path=database_path, evidence_dir=tmp_path / "evidence")
    assert migrate(settings) == SCHEMA_VERSION

    upgraded = connection_for(settings)
    try:
        case = upgraded.execute("SELECT * FROM cases WHERE id='case-1'").fetchone()
        artifact = upgraded.execute("SELECT * FROM evidence_artifacts WHERE id='evidence-1'").fetchone()
        event = upgraded.execute("SELECT * FROM audit_events WHERE event_id='event-1'").fetchone()
        assert case is not None and case["subject_email"] == "person@example.test"
        assert case["retention_until"] is None and case["retention_policy_id"] is None
        assert artifact is not None and artifact["sha256"] == "a" * 64
        assert artifact["schema_version"] == 1 and artifact["signing_status"] == "legacy"
        assert event is not None and event["event_hash"] == "b" * 64
        assert upgraded.execute("PRAGMA foreign_key_check").fetchall() == []
    finally:
        upgraded.close()


def test_newer_schema_is_rejected(tmp_path) -> None:  # type: ignore[no-untyped-def]
    settings = Settings(database_path=tmp_path / "future.db", evidence_dir=tmp_path / "evidence")
    connection = sqlite3.connect(settings.database_path)
    try:
        connection.execute(f"PRAGMA user_version = {SCHEMA_VERSION + 1}")
    finally:
        connection.close()

    with pytest.raises(RuntimeError, match="newer than supported"):
        migrate(settings)


def test_project_and_packaged_migrations_are_identical() -> None:
    project_migrations = Path(__file__).resolve().parents[1] / "migrations"
    for name in (
        "0002_webhook_intake.sql",
        "0003_evidence_v2.sql",
        "0004_retention_operations.sql",
    ):
        packaged = files("offboardproof").joinpath("migrations", name).read_bytes()
        assert packaged == (project_migrations / name).read_bytes()
