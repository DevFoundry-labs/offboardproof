from __future__ import annotations

import json
import sqlite3
from datetime import UTC, datetime, timedelta
from typing import Any

from offboardproof.audit import append_event
from offboardproof.auth import Actor, require_role
from offboardproof.config import Settings
from offboardproof.db import connection_for, transaction
from offboardproof.enums import (
    ActionStatus,
    ApprovalDecision,
    CaseState,
    ControlState,
    ExceptionStatus,
    JobStatus,
    RiskTier,
    Role,
)
from offboardproof.errors import ConfigurationError, ConflictError, InvalidTransitionError, NotFoundError
from offboardproof.evidence import write_evidence
from offboardproof.evidence_v2 import write_evidence_v2
from offboardproof.providers.factory import get_provider
from offboardproof.schemas import CaseCreate
from offboardproof.util import canonical_json, iso_now, new_id, normalize_email, sha256_text

APPROVAL_ROLES = {Role.HR, Role.MANAGER, Role.SECURITY}
SATISFIED_CONTROL_STATES = {
    ControlState.VERIFIED.value,
    ControlState.ACKNOWLEDGED.value,
    ControlState.WAIVED.value,
}


class WorkflowService:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    @staticmethod
    def _case(connection: sqlite3.Connection, case_id: str) -> sqlite3.Row:
        row = connection.execute("SELECT * FROM cases WHERE id=?", (case_id,)).fetchone()
        if row is None:
            raise NotFoundError(f"Case '{case_id}' was not found")
        return row  # type: ignore[no-any-return]

    def create_case(self, actor: Actor, request: CaseCreate, idempotency_key: str) -> dict[str, Any]:
        require_role(actor, Role.HR, Role.OPERATOR)
        key = idempotency_key.strip()
        if len(key) < 8 or len(key) > 128:
            raise ValueError("Idempotency-Key must be between 8 and 128 characters")
        connection = connection_for(self.settings)
        try:
            with transaction(connection):
                case_id = self.create_case_in_transaction(connection, actor, request, key)
            return self.case_view(case_id, connection=connection)
        finally:
            connection.close()

    def create_case_in_transaction(
        self,
        connection: sqlite3.Connection,
        actor: Actor,
        request: CaseCreate,
        idempotency_key: str,
    ) -> str:
        """Create or find a case inside the caller's transaction boundary."""
        require_role(actor, Role.HR, Role.OPERATOR, Role.SERVICE)
        key = idempotency_key.strip()
        if len(key) < 8 or len(key) > 300:
            raise ValueError("Internal idempotency key must be between 8 and 300 characters")
        existing = connection.execute(
            "SELECT id FROM cases WHERE organization_id='local' AND idempotency_key=?",
            (key,),
        ).fetchone()
        if existing:
            return str(existing["id"])

        now = iso_now()
        created_at = datetime.fromisoformat(now)
        if request.retention_until is None:
            retention_until = created_at + timedelta(days=self.settings.default_retention_days)
            retention_policy_id = self.settings.default_retention_policy_id
        else:
            retention_until = request.retention_until.astimezone(UTC)
            if retention_until <= created_at:
                raise ValueError("retention_until must be in the future")
            if retention_until > created_at + timedelta(days=self.settings.max_retention_days):
                raise ValueError("retention_until exceeds the configured maximum")
            retention_policy_id = request.retention_policy_id or "explicit"
        case_id = new_id()
        connection.execute(
            """
            INSERT INTO cases
            (id, organization_id, idempotency_key, subject_email, subject_name,
             transfer_owner, effective_at, risk_tier, provider, state, created_by,
             created_at, updated_at, retention_until, retention_policy_id)
            VALUES (?, 'local', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                case_id,
                key,
                normalize_email(request.subject_email),
                request.subject_name.strip(),
                normalize_email(request.transfer_owner),
                request.effective_at.astimezone(UTC).isoformat(),
                request.risk_tier.value,
                request.provider,
                CaseState.RECEIVED.value,
                actor.id,
                now,
                now,
                retention_until.isoformat(),
                retention_policy_id,
            ),
        )
        append_event(
            connection,
            case_id=case_id,
            actor_id=actor.id,
            event_type="case.received",
            payload={
                "idempotency_key": key,
                "provider": request.provider,
                "risk_tier": request.risk_tier.value,
            },
        )
        append_event(
            connection,
            case_id=case_id,
            actor_id=actor.id,
            event_type="retention.snapshot_created",
            payload={
                "retention_until": retention_until.isoformat(),
                "retention_policy_id": retention_policy_id,
            },
        )
        return case_id

    def plan_case(self, actor: Actor, case_id: str) -> dict[str, Any]:
        require_role(actor, Role.OPERATOR)
        connection = connection_for(self.settings)
        try:
            case = self._case(connection, case_id)
            if case["state"] != CaseState.RECEIVED.value:
                raise InvalidTransitionError("Only a received case can be planned")
            provider = get_provider(case["provider"], connection, self.settings)
            discovery = provider.discover(case["subject_email"])
            required_roles = [Role.HR.value, Role.MANAGER.value]
            if case["risk_tier"] == RiskTier.HIGH.value:
                required_roles.append(Role.SECURITY.value)

            specs: list[dict[str, Any]] = [
                {
                    "type": "suspend_account",
                    "target": case["subject_email"],
                    "desired": {"suspended": True},
                    "manual": False,
                    "quality": "observed",
                },
                {
                    "type": "sign_out_sessions",
                    "target": case["subject_email"],
                    "desired": {"signed_out": True},
                    "manual": False,
                    "quality": "observed" if discovery.signed_out is not None else "acknowledged",
                },
            ]
            specs.extend(
                {
                    "type": "remove_group",
                    "target": group,
                    "desired": {"present": False},
                    "manual": False,
                    "quality": "observed",
                }
                for group in discovery.groups
            )
            specs.append(
                {
                    "type": "confirm_data_transfer",
                    "target": case["transfer_owner"],
                    "desired": {"transfer_confirmed": True},
                    "manual": True,
                    "quality": "human_attested",
                }
            )
            plan_version = int(case["plan_version"]) + 1
            digest_payload = {
                "case_id": case_id,
                "plan_version": plan_version,
                "subject_email": case["subject_email"],
                "effective_at": case["effective_at"],
                "transfer_owner": case["transfer_owner"],
                "provider": case["provider"],
                "required_roles": required_roles,
                "controls": specs,
            }
            plan_digest = sha256_text(canonical_json(digest_payload))
            now = iso_now()
            with transaction(connection):
                for sequence_no, spec in enumerate(specs, start=1):
                    control_id = new_id()
                    connection.execute(
                        """
                        INSERT INTO controls
                        (id, case_id, control_type, provider, target, desired_json, state,
                         required, manual, sequence_no, evidence_quality, created_at, updated_at)
                        VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?, ?)
                        """,
                        (
                            control_id,
                            case_id,
                            spec["type"],
                            case["provider"] if not spec["manual"] else "manual",
                            spec["target"],
                            canonical_json(spec["desired"]),
                            ControlState.PENDING.value,
                            int(spec["manual"]),
                            sequence_no,
                            spec["quality"],
                            now,
                            now,
                        ),
                    )
                    if not spec["manual"]:
                        connection.execute(
                            """
                            INSERT INTO actions
                            (id, case_id, control_id, idempotency_key, operation, payload_json,
                             status, created_at, updated_at)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                            """,
                            (
                                new_id(),
                                case_id,
                                control_id,
                                f"{case_id}:{plan_version}:{spec['type']}:{spec['target'].lower()}",
                                spec["type"],
                                canonical_json(
                                    {
                                        "subject_email": case["subject_email"],
                                        "target": spec["target"],
                                        "desired": spec["desired"],
                                    }
                                ),
                                ActionStatus.PENDING.value,
                                now,
                                now,
                            ),
                        )
                connection.execute(
                    """
                    UPDATE cases SET state=?, plan_version=?, plan_digest=?,
                                     required_roles_json=?, updated_at=? WHERE id=?
                    """,
                    (
                        CaseState.WAITING_APPROVAL.value,
                        plan_version,
                        plan_digest,
                        canonical_json(required_roles),
                        now,
                        case_id,
                    ),
                )
                append_event(
                    connection,
                    case_id=case_id,
                    actor_id=actor.id,
                    event_type="case.planned",
                    payload={
                        "plan_version": plan_version,
                        "plan_digest": plan_digest,
                        "required_roles": required_roles,
                        "control_count": len(specs),
                        "provider_external_id": discovery.external_id,
                    },
                )
            return self.case_view(case_id, connection=connection)
        finally:
            connection.close()

    def approve_case(
        self,
        actor: Actor,
        case_id: str,
        *,
        decision: ApprovalDecision,
        reason: str,
        as_role: str | None = None,
    ) -> dict[str, Any]:
        connection = connection_for(self.settings)
        try:
            case = self._case(connection, case_id)
            if case["state"] not in {
                CaseState.WAITING_APPROVAL.value,
                CaseState.READY.value,
            }:
                raise InvalidTransitionError("This case is not accepting approvals")
            role = Role(as_role) if as_role else actor.role
            if actor.role is not Role.ADMIN and actor.role is not role:
                raise ConflictError("Only an admin can approve as another role")
            if role not in APPROVAL_ROLES:
                raise ConflictError("Approval role must be hr, manager, or security")
            required_roles: list[str] = json.loads(case["required_roles_json"])
            if role.value not in required_roles:
                raise ConflictError(f"Role '{role.value}' is not required for this plan")
            now = iso_now()
            with transaction(connection):
                connection.execute(
                    """
                    INSERT INTO approvals
                    (id, case_id, actor_id, role, decision, reason, plan_digest, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(case_id, role, plan_digest) DO UPDATE SET
                        actor_id=excluded.actor_id, decision=excluded.decision,
                        reason=excluded.reason, created_at=excluded.created_at
                    """,
                    (
                        new_id(),
                        case_id,
                        actor.id,
                        role.value,
                        decision.value,
                        reason.strip(),
                        case["plan_digest"],
                        now,
                    ),
                )
                append_event(
                    connection,
                    case_id=case_id,
                    actor_id=actor.id,
                    event_type=f"approval.{decision.value}",
                    payload={
                        "role": role.value,
                        "reason": reason.strip(),
                        "plan_digest": case["plan_digest"],
                    },
                )
                if decision is ApprovalDecision.REJECTED:
                    connection.execute(
                        "UPDATE cases SET state=?, updated_at=? WHERE id=?",
                        (CaseState.REJECTED.value, now, case_id),
                    )
                elif self._approvals_complete(connection, case):
                    connection.execute(
                        "UPDATE cases SET state=?, updated_at=? WHERE id=?",
                        (CaseState.READY.value, now, case_id),
                    )
                    self._enqueue_actions(connection, case_id, case["effective_at"])
                    append_event(
                        connection,
                        case_id=case_id,
                        actor_id=actor.id,
                        event_type="case.ready",
                        payload={"effective_at": case["effective_at"]},
                    )
            return self.case_view(case_id, connection=connection)
        finally:
            connection.close()

    @staticmethod
    def _approvals_complete(connection: sqlite3.Connection, case: sqlite3.Row) -> bool:
        required: set[str] = set(json.loads(case["required_roles_json"]))
        rows = connection.execute(
            """
            SELECT role, decision FROM approvals
            WHERE case_id=? AND plan_digest=?
            """,
            (case["id"], case["plan_digest"]),
        ).fetchall()
        approved = {row["role"] for row in rows if row["decision"] == "approved"}
        rejected = any(row["decision"] == "rejected" for row in rows)
        return not rejected and required.issubset(approved)

    def _enqueue_actions(self, connection: sqlite3.Connection, case_id: str, effective_at: str) -> None:
        now = iso_now()
        max_attempts = len(self.settings.retry_delays) + 1
        actions = connection.execute(
            "SELECT id FROM actions WHERE case_id=? ORDER BY created_at", (case_id,)
        ).fetchall()
        for action in actions:
            connection.execute(
                """
                INSERT INTO jobs
                (id, action_id, case_id, status, attempt_count, max_attempts,
                 available_at, created_at, updated_at)
                VALUES (?, ?, ?, ?, 0, ?, ?, ?, ?)
                ON CONFLICT(action_id) DO NOTHING
                """,
                (
                    new_id(),
                    action["id"],
                    case_id,
                    JobStatus.QUEUED.value,
                    max_attempts,
                    effective_at,
                    now,
                    now,
                ),
            )

    def complete_manual(self, actor: Actor, case_id: str, control_id: str, evidence_note: str) -> dict[str, Any]:
        require_role(actor, Role.MANAGER, Role.OPERATOR)
        connection = connection_for(self.settings)
        try:
            case = self._case(connection, case_id)
            if not self._approvals_complete(connection, case):
                raise ConflictError("All required approvals must exist before manual completion")
            control = connection.execute(
                "SELECT * FROM controls WHERE id=? AND case_id=?", (control_id, case_id)
            ).fetchone()
            if control is None or not bool(control["manual"]):
                raise NotFoundError("Manual control was not found")
            now = iso_now()
            try:
                with transaction(connection):
                    connection.execute(
                        "UPDATE controls SET state=?, updated_at=? WHERE id=?",
                        (ControlState.VERIFIED.value, now, control_id),
                    )
                    connection.execute(
                        """
                        INSERT INTO observations
                        (id, case_id, control_id, provider, external_id, observed_json,
                         satisfied, quality, created_at)
                        VALUES (?, ?, ?, 'manual', NULL, ?, 1, 'human_attested', ?)
                        """,
                        (
                            new_id(),
                            case_id,
                            control_id,
                            canonical_json({"evidence_note": evidence_note.strip()}),
                            now,
                        ),
                    )
                    connection.execute(
                        """
                        UPDATE exceptions SET status='resolved', resolution_note=?, updated_at=?
                        WHERE control_id=? AND status='open'
                        """,
                        (evidence_note.strip(), now, control_id),
                    )
                    append_event(
                        connection,
                        case_id=case_id,
                        actor_id=actor.id,
                        event_type="control.manual_completed",
                        payload={"control_id": control_id, "evidence_note": evidence_note.strip()},
                    )
                    new_state = self._refresh_case_state(connection, case_id, actor.id)
                    if new_state is CaseState.COMPLETED:
                        self._write_completed_evidence(connection, case_id, actor.id)
            except ConfigurationError:
                self._record_evidence_failure(connection, case_id, control_id, actor.id)
                raise
            return self.case_view(case_id, connection=connection)
        finally:
            connection.close()

    def waive_control(
        self,
        actor: Actor,
        case_id: str,
        control_id: str,
        *,
        reason: str,
        expires_at: datetime,
    ) -> dict[str, Any]:
        require_role(actor, Role.SECURITY)
        if expires_at.astimezone(UTC) <= datetime.now(UTC):
            raise ValueError("Waiver expiry must be in the future")
        connection = connection_for(self.settings)
        try:
            control = connection.execute(
                "SELECT id FROM controls WHERE id=? AND case_id=?", (control_id, case_id)
            ).fetchone()
            if control is None:
                raise NotFoundError("Control was not found")
            now = iso_now()
            with transaction(connection):
                connection.execute(
                    "UPDATE controls SET state=?, updated_at=? WHERE id=?",
                    (ControlState.WAIVED.value, now, control_id),
                )
                connection.execute(
                    """
                    UPDATE exceptions SET status='resolved', resolution_note=?, updated_at=?
                    WHERE control_id=? AND status='open'
                    """,
                    (
                        f"Waived until {expires_at.astimezone(UTC).isoformat()}: {reason}",
                        now,
                        control_id,
                    ),
                )
                append_event(
                    connection,
                    case_id=case_id,
                    actor_id=actor.id,
                    event_type="control.waived",
                    payload={
                        "control_id": control_id,
                        "reason": reason.strip(),
                        "expires_at": expires_at.astimezone(UTC).isoformat(),
                    },
                )
                new_state = self._refresh_case_state(connection, case_id, actor.id)
                if new_state is CaseState.COMPLETED:
                    self._write_completed_evidence(connection, case_id, actor.id)
            return self.case_view(case_id, connection=connection)
        finally:
            connection.close()

    def requeue_exception(self, actor: Actor, exception_id: str, resolution_note: str) -> dict[str, Any]:
        require_role(actor, Role.OPERATOR, Role.SECURITY)
        connection = connection_for(self.settings)
        try:
            exception = connection.execute("SELECT * FROM exceptions WHERE id=?", (exception_id,)).fetchone()
            if exception is None:
                raise NotFoundError("Exception was not found")
            if exception["status"] != ExceptionStatus.OPEN.value:
                raise ConflictError("Only an open exception can be requeued")
            if exception["action_id"] is None:
                raise ConflictError("Manual exceptions must be completed with evidence, not requeued")
            now = iso_now()
            with transaction(connection):
                connection.execute(
                    "UPDATE exceptions SET status='resolved', resolution_note=?, updated_at=? WHERE id=?",
                    (resolution_note.strip(), now, exception_id),
                )
                connection.execute(
                    "UPDATE controls SET state='pending', updated_at=? WHERE id=?",
                    (now, exception["control_id"]),
                )
                connection.execute(
                    "UPDATE actions SET status='pending', last_error=NULL, updated_at=? WHERE id=?",
                    (now, exception["action_id"]),
                )
                connection.execute(
                    """
                    UPDATE jobs SET status='queued', available_at=?, lease_until=NULL,
                                    last_error=NULL, updated_at=? WHERE action_id=?
                    """,
                    (now, now, exception["action_id"]),
                )
                connection.execute(
                    "UPDATE cases SET state='ready', updated_at=? WHERE id=?",
                    (now, exception["case_id"]),
                )
                append_event(
                    connection,
                    case_id=exception["case_id"],
                    actor_id=actor.id,
                    event_type="exception.requeued",
                    payload={
                        "exception_id": exception_id,
                        "resolution_note": resolution_note.strip(),
                    },
                )
            return self.case_view(exception["case_id"], connection=connection)
        finally:
            connection.close()

    def _refresh_case_state(self, connection: sqlite3.Connection, case_id: str, actor_id: str | None) -> CaseState:
        case = self._case(connection, case_id)
        states = [
            row["state"]
            for row in connection.execute("SELECT state FROM controls WHERE case_id=?", (case_id,)).fetchall()
        ]
        open_exception = connection.execute(
            "SELECT 1 FROM exceptions WHERE case_id=? AND status='open' LIMIT 1", (case_id,)
        ).fetchone()
        if open_exception or ControlState.EXCEPTION.value in states:
            new_state = CaseState.EXCEPTION
        elif states and all(state in SATISFIED_CONTROL_STATES for state in states):
            new_state = CaseState.COMPLETED
        else:
            manual_pending = connection.execute(
                """
                SELECT 1 FROM controls WHERE case_id=? AND manual=1
                AND state NOT IN ('verified','waived') LIMIT 1
                """,
                (case_id,),
            ).fetchone()
            automated_pending = connection.execute(
                """
                SELECT 1 FROM controls WHERE case_id=? AND manual=0
                AND state NOT IN ('verified','acknowledged','waived') LIMIT 1
                """,
                (case_id,),
            ).fetchone()
            new_state = (
                CaseState.EXECUTING
                if automated_pending
                else CaseState.WAITING_MANUAL
                if manual_pending
                else CaseState.READY
            )
        now = iso_now()
        completed_at = now if new_state is CaseState.COMPLETED else case["completed_at"]
        connection.execute(
            "UPDATE cases SET state=?, updated_at=?, completed_at=? WHERE id=?",
            (new_state.value, now, completed_at, case_id),
        )
        if new_state is CaseState.COMPLETED and case["state"] != CaseState.COMPLETED.value:
            append_event(
                connection,
                case_id=case_id,
                actor_id=actor_id,
                event_type="case.completed",
                payload={"completed_at": now},
            )
        return new_state

    def _write_completed_evidence(
        self,
        connection: sqlite3.Connection,
        case_id: str,
        actor_id: str | None,
    ) -> str:
        evidence_path, manifest_path, digest = write_evidence_v2(connection, self.settings, case_id)
        write_evidence(connection, self.settings, case_id)
        artifact = connection.execute(
            """
            SELECT signing_status, signing_key_id, public_key_fingerprint
            FROM evidence_artifacts
            WHERE case_id=? AND schema_version=2 AND evidence_sha256=?
            """,
            (case_id, digest),
        ).fetchone()
        append_event(
            connection,
            case_id=case_id,
            actor_id=actor_id,
            event_type="evidence.generated",
            payload={
                "schema_version": 2,
                "evidence_sha256": digest,
                "evidence_path": str(evidence_path),
                "manifest_path": str(manifest_path),
                "signing_status": artifact["signing_status"],
                "signing_key_id": artifact["signing_key_id"],
                "public_key_fingerprint": artifact["public_key_fingerprint"],
            },
        )
        return digest

    def _record_evidence_failure(
        self,
        connection: sqlite3.Connection,
        case_id: str,
        control_id: str,
        actor_id: str | None,
    ) -> None:
        now = iso_now()
        with transaction(connection):
            existing = connection.execute(
                """
                SELECT id FROM exceptions
                WHERE case_id=? AND control_id=? AND category='evidence_signing' AND status='open'
                """,
                (case_id, control_id),
            ).fetchone()
            if existing is None:
                exception_id = new_id()
                connection.execute(
                    """
                    INSERT INTO exceptions (
                        id, case_id, control_id, action_id, category, retryable, status,
                        summary, created_at, updated_at
                    ) VALUES (?, ?, ?, NULL, 'evidence_signing', 1, 'open', ?, ?, ?)
                    """,
                    (
                        exception_id,
                        case_id,
                        control_id,
                        "Evidence signing configuration prevented completion",
                        now,
                        now,
                    ),
                )
            else:
                exception_id = str(existing["id"])
            connection.execute(
                "UPDATE cases SET state='exception', updated_at=?, completed_at=NULL WHERE id=?",
                (now, case_id),
            )
            append_event(
                connection,
                case_id=case_id,
                actor_id=actor_id,
                event_type="evidence.failed",
                payload={"exception_id": exception_id, "reason_code": "signing_configuration"},
            )

    def case_view(self, case_id: str, *, connection: sqlite3.Connection | None = None) -> dict[str, Any]:
        own_connection = connection is None
        connection = connection or connection_for(self.settings)
        try:
            case = self._case(connection, case_id)
            payload = {key: case[key] for key in case.keys()}
            payload["required_roles"] = json.loads(payload.pop("required_roles_json"))
            payload["controls"] = [
                {
                    **{key: row[key] for key in row.keys()},
                    "desired": json.loads(row["desired_json"]),
                }
                for row in connection.execute(
                    "SELECT * FROM controls WHERE case_id=? ORDER BY sequence_no", (case_id,)
                ).fetchall()
            ]
            for control in payload["controls"]:
                control.pop("desired_json", None)
            payload["approvals"] = [
                {key: row[key] for key in row.keys()}
                for row in connection.execute(
                    "SELECT * FROM approvals WHERE case_id=? ORDER BY created_at", (case_id,)
                ).fetchall()
            ]
            payload["exceptions"] = [
                {key: row[key] for key in row.keys()}
                for row in connection.execute(
                    "SELECT * FROM exceptions WHERE case_id=? ORDER BY created_at", (case_id,)
                ).fetchall()
            ]
            payload["legal_holds"] = [
                {key: row[key] for key in row.keys()}
                for row in connection.execute(
                    "SELECT * FROM legal_holds WHERE case_id=? ORDER BY created_at",
                    (case_id,),
                ).fetchall()
            ]
            return payload
        finally:
            if own_connection:
                connection.close()

    def list_cases(self, limit: int = 100) -> list[dict[str, Any]]:
        connection = connection_for(self.settings)
        try:
            rows = connection.execute(
                "SELECT id FROM cases ORDER BY created_at DESC LIMIT ?", (min(max(limit, 1), 500),)
            ).fetchall()
            return [self.case_view(row["id"], connection=connection) for row in rows]
        finally:
            connection.close()

    def audit_events(self, case_id: str) -> list[dict[str, Any]]:
        connection = connection_for(self.settings)
        try:
            self._case(connection, case_id)
            rows = connection.execute(
                "SELECT * FROM audit_events WHERE case_id=? ORDER BY sequence_no", (case_id,)
            ).fetchall()
            return [{key: row[key] for key in row.keys()} for row in rows]
        finally:
            connection.close()

    def metrics(self) -> dict[str, int | float]:
        connection = connection_for(self.settings)
        try:
            result: dict[str, int | float] = {}
            for row in connection.execute("SELECT state, COUNT(*) AS count FROM cases GROUP BY state").fetchall():
                result[f"cases_{row['state']}"] = int(row["count"])
            result["exceptions_open"] = int(
                connection.execute("SELECT COUNT(*) FROM exceptions WHERE status='open'").fetchone()[0]
            )
            result["jobs_queued"] = int(
                connection.execute("SELECT COUNT(*) FROM jobs WHERE status='queued'").fetchone()[0]
            )
            for row in connection.execute("SELECT status, COUNT(*) AS count FROM jobs GROUP BY status").fetchall():
                result[f"jobs_{row['status']}"] = int(row["count"])
            for row in connection.execute(
                "SELECT evidence_quality, state, COUNT(*) AS count FROM controls GROUP BY evidence_quality, state"
            ).fetchall():
                result[f"controls_{row['evidence_quality']}_{row['state']}"] = int(row["count"])
            result["exceptions_overdue"] = int(
                connection.execute(
                    "SELECT COUNT(*) FROM exceptions WHERE status='open' AND due_at IS NOT NULL AND due_at<?",
                    (iso_now(),),
                ).fetchone()[0]
            )
            for status_name in ("signed", "unsigned", "failed", "legacy"):
                result[f"evidence_{status_name}"] = int(
                    connection.execute(
                        "SELECT COUNT(*) FROM evidence_artifacts WHERE signing_status=?",
                        (status_name,),
                    ).fetchone()[0]
                )
            result["evidence_failed"] += int(
                connection.execute("SELECT COUNT(*) FROM audit_events WHERE event_type='evidence.failed'").fetchone()[0]
            )
            now = datetime.now(UTC)
            horizon = now + timedelta(days=self.settings.retention_expiring_horizon_days)
            result["cases_retention_expiring"] = int(
                connection.execute(
                    "SELECT COUNT(*) FROM cases WHERE retention_until>? AND retention_until<=?",
                    (now.isoformat(), horizon.isoformat()),
                ).fetchone()[0]
            )
            result["cases_retention_expired"] = int(
                connection.execute(
                    "SELECT COUNT(*) FROM cases WHERE retention_until IS NOT NULL AND retention_until<=?",
                    (now.isoformat(),),
                ).fetchone()[0]
            )
            result["webhook_deliveries_accepted"] = int(
                connection.execute("SELECT COUNT(*) FROM webhook_deliveries WHERE status='accepted'").fetchone()[0]
            )
            result["webhook_replays_suppressed"] = int(
                connection.execute("SELECT COUNT(*) FROM audit_events WHERE event_type='webhook.replayed'").fetchone()[
                    0
                ]
            )
            result["webhook_conflicts"] = int(
                connection.execute("SELECT COUNT(*) FROM audit_events WHERE event_type='webhook.conflict'").fetchone()[
                    0
                ]
            )
            result["webhook_authenticated_rejections"] = int(
                connection.execute("SELECT COUNT(*) FROM audit_events WHERE event_type='webhook.rejected'").fetchone()[
                    0
                ]
            )
            oldest = connection.execute("SELECT MIN(available_at) FROM jobs WHERE status='queued'").fetchone()[0]
            result["oldest_queued_job_age_seconds"] = (
                max(0.0, (now - datetime.fromisoformat(oldest)).total_seconds()) if oldest else 0.0
            )
            return result
        finally:
            connection.close()
