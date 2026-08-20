from __future__ import annotations

import sqlite3
from datetime import UTC, datetime
from typing import Any

from offboardproof.audit import append_event
from offboardproof.auth import Actor, require_role
from offboardproof.config import Settings
from offboardproof.db import connection_for, transaction
from offboardproof.enums import Role
from offboardproof.errors import ConflictError, NotFoundError
from offboardproof.util import canonical_json, iso_now, new_id, sha256_text

CASE_COUNT_QUERIES = {
    "controls": "SELECT COUNT(*) FROM controls WHERE case_id=?",
    "approvals": "SELECT COUNT(*) FROM approvals WHERE case_id=?",
    "actions": "SELECT COUNT(*) FROM actions WHERE case_id=?",
    "jobs": "SELECT COUNT(*) FROM jobs WHERE case_id=?",
    "exceptions": "SELECT COUNT(*) FROM exceptions WHERE case_id=?",
    "observations": "SELECT COUNT(*) FROM observations WHERE case_id=?",
    "evidence_artifacts": "SELECT COUNT(*) FROM evidence_artifacts WHERE case_id=?",
    "audit_events": "SELECT COUNT(*) FROM audit_events WHERE case_id=?",
    "legal_holds": "SELECT COUNT(*) FROM legal_holds WHERE case_id=?",
}


class RetentionService:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    @staticmethod
    def _case_exists(connection: sqlite3.Connection, case_id: str) -> None:
        if connection.execute("SELECT 1 FROM cases WHERE id=?", (case_id,)).fetchone() is None:
            raise NotFoundError(f"Case '{case_id}' was not found")

    def create_hold(self, actor: Actor, case_id: str, reason: str) -> dict[str, Any]:
        require_role(actor, Role.SECURITY)
        reason = reason.strip()
        if len(reason) < 10:
            raise ValueError("Legal-hold reason must be at least 10 characters")
        connection = connection_for(self.settings)
        try:
            with transaction(connection):
                self._case_exists(connection, case_id)
                hold_id = new_id()
                now = iso_now()
                try:
                    connection.execute(
                        """
                        INSERT INTO legal_holds (id, case_id, status, reason, created_by, created_at)
                        VALUES (?, ?, 'active', ?, ?, ?)
                        """,
                        (hold_id, case_id, reason, actor.id, now),
                    )
                except sqlite3.IntegrityError as exc:
                    raise ConflictError("Case already has an active legal hold") from exc
                append_event(
                    connection,
                    case_id=case_id,
                    actor_id=actor.id,
                    event_type="legal_hold.created",
                    payload={"legal_hold_id": hold_id, "reason": reason},
                )
            return self.hold_view(hold_id)
        finally:
            connection.close()

    def release_hold(self, actor: Actor, case_id: str, reason: str) -> dict[str, Any]:
        require_role(actor, Role.SECURITY)
        reason = reason.strip()
        if len(reason) < 10:
            raise ValueError("Legal-hold release reason must be at least 10 characters")
        connection = connection_for(self.settings)
        try:
            with transaction(connection):
                hold = connection.execute(
                    "SELECT * FROM legal_holds WHERE case_id=? AND status='active'",
                    (case_id,),
                ).fetchone()
                if hold is None:
                    raise NotFoundError("Case has no active legal hold")
                now = iso_now()
                connection.execute(
                    """
                    UPDATE legal_holds SET status='released', released_by=?, released_at=?, release_reason=?
                    WHERE id=?
                    """,
                    (actor.id, now, reason, hold["id"]),
                )
                append_event(
                    connection,
                    case_id=case_id,
                    actor_id=actor.id,
                    event_type="legal_hold.released",
                    payload={"legal_hold_id": hold["id"], "release_reason": reason},
                )
            return self.hold_view(str(hold["id"]))
        finally:
            connection.close()

    def hold_view(self, hold_id: str) -> dict[str, Any]:
        connection = connection_for(self.settings)
        try:
            row = connection.execute("SELECT * FROM legal_holds WHERE id=?", (hold_id,)).fetchone()
            if row is None:
                raise NotFoundError("Legal hold was not found")
            return {key: row[key] for key in row.keys()}
        finally:
            connection.close()

    def report(self, actor: Actor, as_of: datetime) -> dict[str, Any]:
        require_role(actor, Role.OPERATOR, Role.SECURITY, Role.AUDITOR)
        as_of = as_of.astimezone(UTC)
        connection = connection_for(self.settings)
        try:
            cases: list[dict[str, Any]] = []
            for case in connection.execute("SELECT * FROM cases ORDER BY id").fetchall():
                active_hold = connection.execute(
                    "SELECT 1 FROM legal_holds WHERE case_id=? AND status='active'",
                    (case["id"],),
                ).fetchone()
                retention_until = (
                    datetime.fromisoformat(case["retention_until"]).astimezone(UTC) if case["retention_until"] else None
                )
                if retention_until is None:
                    eligibility = "missing_retention_policy"
                elif case["state"] != "completed":
                    eligibility = "incomplete_case"
                elif active_hold:
                    eligibility = "active_legal_hold"
                elif retention_until > as_of:
                    eligibility = "not_expired"
                else:
                    eligibility = "expired_review_required"
                counts = {
                    table: int(connection.execute(query, (case["id"],)).fetchone()[0])
                    for table, query in CASE_COUNT_QUERIES.items()
                }
                artifacts = [
                    {
                        "path": row["path"],
                        "sha256": row["sha256"],
                        "manifest_path": row["manifest_path"],
                        "signing_status": row["signing_status"],
                    }
                    for row in connection.execute(
                        """
                        SELECT path, sha256, manifest_path, signing_status
                        FROM evidence_artifacts WHERE case_id=? ORDER BY path
                        """,
                        (case["id"],),
                    ).fetchall()
                ]
                cases.append(
                    {
                        "case_id": case["id"],
                        "case_state": case["state"],
                        "retention_until": case["retention_until"],
                        "retention_policy_id": case["retention_policy_id"],
                        "active_legal_hold": bool(active_hold),
                        "eligibility": eligibility,
                        "row_counts": counts,
                        "evidence_artifacts": artifacts,
                    }
                )
            stable = {
                "schema_version": 1,
                "database_schema_version": int(connection.execute("PRAGMA user_version").fetchone()[0]),
                "as_of": as_of.isoformat(),
                "case_count": len(cases),
                "cases": cases,
            }
            return {**stable, "generated_at": iso_now(), "report_sha256": sha256_text(canonical_json(stable))}
        finally:
            connection.close()
