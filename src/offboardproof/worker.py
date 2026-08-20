from __future__ import annotations

import json
import logging
import sqlite3
from datetime import UTC, datetime, timedelta
from typing import Any

from offboardproof.audit import append_event
from offboardproof.config import Settings
from offboardproof.db import connection_for, transaction
from offboardproof.enums import (
    ActionStatus,
    ControlState,
    ExceptionStatus,
    OutcomeKind,
)
from offboardproof.errors import ConfigurationError, ConflictError, ProviderError
from offboardproof.providers.base import ActionRequest, Observation
from offboardproof.providers.factory import get_provider
from offboardproof.service import WorkflowService
from offboardproof.util import canonical_json, iso_now, new_id, parse_utc

logger = logging.getLogger(__name__)


class Worker:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.service = WorkflowService(settings)

    def claim_job(self, connection: sqlite3.Connection) -> sqlite3.Row | None:
        now = datetime.now(UTC)
        lease_until = now + timedelta(seconds=self.settings.worker_lease_seconds)
        with transaction(connection):
            row = connection.execute(
                """
                SELECT * FROM jobs
                WHERE (status='queued' AND available_at<=?)
                   OR (status='leased' AND lease_until IS NOT NULL AND lease_until<=?)
                ORDER BY available_at, created_at LIMIT 1
                """,
                (now.isoformat(), now.isoformat()),
            ).fetchone()
            if row is None:
                return None
            connection.execute(
                """
                UPDATE jobs SET status='leased', lease_until=?, attempt_count=attempt_count+1,
                                updated_at=? WHERE id=?
                """,
                (lease_until.isoformat(), now.isoformat(), row["id"]),
            )
            return connection.execute("SELECT * FROM jobs WHERE id=?", (row["id"],)).fetchone()  # type: ignore[no-any-return]

    def run_once(self) -> bool:
        connection = connection_for(self.settings)
        try:
            job = self.claim_job(connection)
            if job is None:
                return False
            self._process_job(connection, job)
            return True
        finally:
            connection.close()

    def _load_action_context(
        self, connection: sqlite3.Connection, action_id: str
    ) -> tuple[sqlite3.Row, sqlite3.Row, sqlite3.Row]:
        row = connection.execute(
            """
            SELECT a.*, c.control_type, c.target, c.desired_json, c.evidence_quality,
                   c.state AS control_state, ca.subject_email, ca.provider, ca.state AS case_state,
                   ca.effective_at, ca.plan_digest, ca.required_roles_json
            FROM actions a
            JOIN controls c ON c.id=a.control_id
            JOIN cases ca ON ca.id=a.case_id
            WHERE a.id=?
            """,
            (action_id,),
        ).fetchone()
        if row is None:
            raise ConflictError("Job action no longer exists")
        case = connection.execute("SELECT * FROM cases WHERE id=?", (row["case_id"],)).fetchone()
        control = connection.execute("SELECT * FROM controls WHERE id=?", (row["control_id"],)).fetchone()
        assert case is not None and control is not None
        return row, case, control

    @staticmethod
    def _request(action: sqlite3.Row) -> ActionRequest:
        payload: dict[str, Any] = json.loads(action["payload_json"])
        return ActionRequest(
            action_id=action["id"],
            idempotency_key=action["idempotency_key"],
            operation=action["operation"],
            subject_email=payload["subject_email"],
            target=payload["target"],
            desired=payload["desired"],
        )

    def _process_job(self, connection: sqlite3.Connection, job: sqlite3.Row) -> None:
        action, case, control = self._load_action_context(connection, job["action_id"])
        if not self.service._approvals_complete(connection, case):
            self._fail_permanently(
                connection,
                job,
                action,
                control,
                "approval_missing",
                "Required approvals are missing or stale; re-plan and approve before execution",
            )
            return
        if parse_utc(case["effective_at"]) > datetime.now(UTC):
            with transaction(connection):
                connection.execute(
                    "UPDATE jobs SET status='queued', available_at=?, lease_until=NULL, updated_at=? WHERE id=?",
                    (case["effective_at"], iso_now(), job["id"]),
                )
            return

        request = self._request(action)
        provider = get_provider(case["provider"], connection, self.settings)
        with transaction(connection):
            now = iso_now()
            connection.execute(
                "UPDATE actions SET status=?, attempt_count=attempt_count+1, updated_at=? WHERE id=?",
                (ActionStatus.RUNNING.value, now, action["id"]),
            )
            connection.execute(
                "UPDATE controls SET state=?, updated_at=? WHERE id=?",
                (ControlState.EXECUTING.value, now, control["id"]),
            )
            connection.execute(
                "UPDATE cases SET state='executing', updated_at=? WHERE id=?",
                (now, case["id"]),
            )
            append_event(
                connection,
                case_id=case["id"],
                event_type="action.started",
                payload={
                    "action_id": action["id"],
                    "operation": action["operation"],
                    "attempt": int(job["attempt_count"]),
                    "idempotency_key": action["idempotency_key"],
                },
            )

        try:
            before = provider.observe(request)
            if before.satisfied:
                self._complete_action(
                    connection,
                    job,
                    action,
                    control,
                    before,
                    status=ActionStatus.RECONCILED,
                    external_reference=action["external_reference"],
                )
                return
            receipt = provider.execute(request)
            after = provider.observe(request)
            if after.satisfied:
                self._complete_action(
                    connection,
                    job,
                    action,
                    control,
                    after,
                    status=ActionStatus.SUCCEEDED,
                    external_reference=receipt.external_reference,
                )
                return
            if control["evidence_quality"] == "acknowledged" and receipt.acknowledged:
                acknowledged = Observation(
                    external_id=after.external_id,
                    observed={
                        **after.observed,
                        "provider_acknowledged": True,
                        "external_reference": receipt.external_reference,
                    },
                    satisfied=True,
                    quality="acknowledged",
                )
                self._complete_action(
                    connection,
                    job,
                    action,
                    control,
                    acknowledged,
                    status=ActionStatus.SUCCEEDED,
                    external_reference=receipt.external_reference,
                    control_state=ControlState.ACKNOWLEDGED,
                )
                return
            self._fail_permanently(
                connection,
                job,
                action,
                control,
                "verification_failed",
                "Provider acknowledged the action but the required final state was not observed",
            )
        except ConfigurationError as exc:
            self._fail_permanently(connection, job, action, control, "configuration", str(exc))
        except ProviderError as exc:
            self._handle_provider_error(connection, job, action, control, exc)

    def _complete_action(
        self,
        connection: sqlite3.Connection,
        job: sqlite3.Row,
        action: sqlite3.Row,
        control: sqlite3.Row,
        observation: Observation,
        *,
        status: ActionStatus,
        external_reference: str | None,
        control_state: ControlState = ControlState.VERIFIED,
    ) -> None:
        now = iso_now()
        with transaction(connection):
            connection.execute(
                """
                UPDATE actions SET status=?, external_reference=?, outcome_kind=?,
                                   last_error=NULL, updated_at=? WHERE id=?
                """,
                (
                    status.value,
                    external_reference,
                    OutcomeKind.OBSERVED.value
                    if control_state is ControlState.VERIFIED
                    else OutcomeKind.ACKNOWLEDGED.value,
                    now,
                    action["id"],
                ),
            )
            connection.execute(
                "UPDATE controls SET state=?, updated_at=? WHERE id=?",
                (control_state.value, now, control["id"]),
            )
            connection.execute(
                "UPDATE jobs SET status='done', lease_until=NULL, updated_at=? WHERE id=?",
                (now, job["id"]),
            )
            connection.execute(
                """
                INSERT INTO observations
                (id, case_id, control_id, provider, external_id, observed_json,
                 satisfied, quality, created_at)
                VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?)
                """,
                (
                    new_id(),
                    action["case_id"],
                    control["id"],
                    control["provider"],
                    observation.external_id,
                    canonical_json(observation.observed),
                    observation.quality,
                    now,
                ),
            )
            append_event(
                connection,
                case_id=action["case_id"],
                event_type="action.verified" if control_state is ControlState.VERIFIED else "action.acknowledged",
                payload={
                    "action_id": action["id"],
                    "control_id": control["id"],
                    "status": status.value,
                    "external_reference": external_reference,
                    "quality": observation.quality,
                    "observed": observation.observed,
                },
            )
            new_state = self.service._refresh_case_state(connection, action["case_id"], actor_id=None)
            if new_state.value == "completed":
                self.service._write_completed_evidence(connection, action["case_id"], actor_id=None)

    def _handle_provider_error(
        self,
        connection: sqlite3.Connection,
        job: sqlite3.Row,
        action: sqlite3.Row,
        control: sqlite3.Row,
        error: ProviderError,
    ) -> None:
        attempts = int(job["attempt_count"])
        if (error.retryable or error.outcome_unknown) and attempts < int(job["max_attempts"]):
            delay_index = min(max(attempts - 1, 0), len(self.settings.retry_delays) - 1)
            available_at = datetime.now(UTC) + timedelta(seconds=self.settings.retry_delays[delay_index])
            action_status = ActionStatus.UNKNOWN if error.outcome_unknown else ActionStatus.RETRY_PENDING
            outcome_kind = OutcomeKind.OUTCOME_UNKNOWN if error.outcome_unknown else OutcomeKind.RETRYABLE_FAILURE
            now = iso_now()
            with transaction(connection):
                connection.execute(
                    """
                    UPDATE actions SET status=?, outcome_kind=?, external_reference=?,
                                       last_error=?, updated_at=? WHERE id=?
                    """,
                    (
                        action_status.value,
                        outcome_kind.value,
                        error.external_reference,
                        str(error),
                        now,
                        action["id"],
                    ),
                )
                connection.execute(
                    "UPDATE controls SET state='pending', updated_at=? WHERE id=?",
                    (now, control["id"]),
                )
                connection.execute(
                    """
                    UPDATE jobs SET status='queued', available_at=?, lease_until=NULL,
                                    last_error=?, updated_at=? WHERE id=?
                    """,
                    (available_at.isoformat(), str(error), now, job["id"]),
                )
                append_event(
                    connection,
                    case_id=action["case_id"],
                    event_type="action.retry_scheduled",
                    payload={
                        "action_id": action["id"],
                        "attempt": attempts,
                        "available_at": available_at.isoformat(),
                        "outcome_unknown": error.outcome_unknown,
                        "error": str(error),
                    },
                )
            return
        category = "outcome_unknown" if error.outcome_unknown else "provider_failure"
        self._fail_permanently(connection, job, action, control, category, str(error))

    def _fail_permanently(
        self,
        connection: sqlite3.Connection,
        job: sqlite3.Row,
        action: sqlite3.Row,
        control: sqlite3.Row,
        category: str,
        summary: str,
    ) -> None:
        now = iso_now()
        retryable = category in {"provider_failure", "outcome_unknown", "configuration"}
        with transaction(connection):
            connection.execute(
                """
                UPDATE actions SET status='failed', outcome_kind='permanent_failure',
                                   last_error=?, updated_at=? WHERE id=?
                """,
                (summary, now, action["id"]),
            )
            connection.execute(
                "UPDATE controls SET state='exception', updated_at=? WHERE id=?",
                (now, control["id"]),
            )
            connection.execute(
                "UPDATE jobs SET status='dead', lease_until=NULL, last_error=?, updated_at=? WHERE id=?",
                (summary, now, job["id"]),
            )
            existing = connection.execute(
                "SELECT id FROM exceptions WHERE control_id=? AND status='open'",
                (control["id"],),
            ).fetchone()
            exception_id = existing["id"] if existing else new_id()
            if existing:
                connection.execute(
                    "UPDATE exceptions SET category=?, retryable=?, summary=?, updated_at=? WHERE id=?",
                    (category, int(retryable), summary, now, exception_id),
                )
            else:
                connection.execute(
                    """
                    INSERT INTO exceptions
                    (id, case_id, control_id, action_id, category, retryable, status,
                     summary, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        exception_id,
                        action["case_id"],
                        control["id"],
                        action["id"],
                        category,
                        int(retryable),
                        ExceptionStatus.OPEN.value,
                        summary,
                        now,
                        now,
                    ),
                )
            append_event(
                connection,
                case_id=action["case_id"],
                event_type="exception.opened",
                payload={
                    "exception_id": exception_id,
                    "action_id": action["id"],
                    "control_id": control["id"],
                    "category": category,
                    "retryable": retryable,
                    "summary": summary,
                },
            )
            self.service._refresh_case_state(connection, action["case_id"], actor_id=None)

    def verify_case(self, case_id: str) -> dict[str, Any]:
        connection = connection_for(self.settings)
        try:
            case = self.service._case(connection, case_id)
            actions = connection.execute(
                """
                SELECT a.*, c.target, c.desired_json, c.evidence_quality, c.provider
                FROM actions a JOIN controls c ON c.id=a.control_id
                WHERE a.case_id=? ORDER BY c.sequence_no
                """,
                (case_id,),
            ).fetchall()
            provider = get_provider(case["provider"], connection, self.settings)
            for action in actions:
                request = self._request(action)
                observation = provider.observe(request)
                now = iso_now()
                with transaction(connection):
                    connection.execute(
                        """
                        INSERT INTO observations
                        (id, case_id, control_id, provider, external_id, observed_json,
                         satisfied, quality, created_at)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            new_id(),
                            case_id,
                            action["control_id"],
                            action["provider"],
                            observation.external_id,
                            canonical_json(observation.observed),
                            int(observation.satisfied),
                            observation.quality,
                            now,
                        ),
                    )
                    if observation.satisfied:
                        connection.execute(
                            "UPDATE controls SET state='verified', updated_at=? WHERE id=?",
                            (now, action["control_id"]),
                        )
                    elif action["evidence_quality"] != "acknowledged":
                        connection.execute(
                            "UPDATE controls SET state='exception', updated_at=? WHERE id=?",
                            (now, action["control_id"]),
                        )
                        existing = connection.execute(
                            "SELECT id FROM exceptions WHERE control_id=? AND status='open'",
                            (action["control_id"],),
                        ).fetchone()
                        if existing is None:
                            connection.execute(
                                """
                                INSERT INTO exceptions
                                (id, case_id, control_id, action_id, category, retryable, status,
                                 summary, created_at, updated_at)
                                VALUES (?, ?, ?, ?, 'verification_drift', 1, 'open', ?, ?, ?)
                                """,
                                (
                                    new_id(),
                                    case_id,
                                    action["control_id"],
                                    action["id"],
                                    "Previously required state is no longer observed",
                                    now,
                                    now,
                                ),
                            )
                    append_event(
                        connection,
                        case_id=case_id,
                        event_type="control.observed",
                        payload={
                            "control_id": action["control_id"],
                            "satisfied": observation.satisfied,
                            "quality": observation.quality,
                            "observed": observation.observed,
                        },
                    )
                    self.service._refresh_case_state(connection, case_id, actor_id=None)
            return self.service.case_view(case_id, connection=connection)
        finally:
            connection.close()
