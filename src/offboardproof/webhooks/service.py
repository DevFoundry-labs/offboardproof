from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from typing import Any

from offboardproof.audit import append_event
from offboardproof.auth import Actor
from offboardproof.config import Settings
from offboardproof.db import connection_for, transaction
from offboardproof.enums import Role
from offboardproof.errors import ConflictError, WebhookAuthenticationError
from offboardproof.schemas import CaseCreate
from offboardproof.service import WorkflowService
from offboardproof.util import iso_now, new_id
from offboardproof.webhooks.schemas import WebhookEvent


@dataclass(frozen=True)
class WebhookResult:
    delivery_id: str
    event_id: str
    case_id: str
    case_state: str
    replayed: bool

    def as_dict(self) -> dict[str, Any]:
        return {
            "delivery_id": self.delivery_id,
            "event_id": self.event_id,
            "case_id": self.case_id,
            "case_state": self.case_state,
            "replayed": self.replayed,
        }


class WebhookService:
    def __init__(self, settings: Settings, workflow: WorkflowService) -> None:
        self.settings = settings
        self.workflow = workflow

    @staticmethod
    def _service_actor(connection: sqlite3.Connection, actor_id: str) -> Actor:
        row = connection.execute("SELECT id, name, role, active FROM actors WHERE id=?", (actor_id,)).fetchone()
        if row is None or not bool(row["active"]) or row["role"] != Role.SERVICE.value:
            raise WebhookAuthenticationError("Webhook authentication failed")
        return Actor(id=str(row["id"]), name=str(row["name"]), role=Role.SERVICE)

    def accept(
        self,
        *,
        source_id: str,
        actor_id: str,
        delivery_id: str,
        event: WebhookEvent,
        payload_sha256: str,
    ) -> WebhookResult:
        connection = connection_for(self.settings)
        conflict_message: str | None = None
        result: WebhookResult | None = None
        try:
            with transaction(connection):
                actor = self._service_actor(connection, actor_id)
                existing = connection.execute(
                    """
                    SELECT * FROM webhook_deliveries
                    WHERE source_id=? AND (delivery_id=? OR event_id=?)
                    ORDER BY received_at LIMIT 1
                    """,
                    (source_id, delivery_id, event.event_id),
                ).fetchone()
                if existing is not None:
                    same_payload = existing["payload_sha256"] == payload_sha256
                    same_event = existing["event_id"] == event.event_id
                    if not same_payload or not same_event:
                        append_event(
                            connection,
                            event_type="webhook.conflict",
                            actor_id=actor.id,
                            case_id=existing["case_id"],
                            payload={
                                "source_id": source_id,
                                "delivery_id": delivery_id,
                                "event_id": event.event_id,
                                "original_payload_sha256": existing["payload_sha256"],
                                "received_payload_sha256": payload_sha256,
                            },
                        )
                        conflict_message = "Webhook delivery or event identifier was reused with different content"
                    else:
                        case = connection.execute(
                            "SELECT state FROM cases WHERE id=?", (existing["case_id"],)
                        ).fetchone()
                        if case is None:
                            raise ConflictError("Webhook replay references a missing case")
                        append_event(
                            connection,
                            event_type="webhook.replayed",
                            actor_id=actor.id,
                            case_id=existing["case_id"],
                            payload={
                                "source_id": source_id,
                                "delivery_id": delivery_id,
                                "event_id": event.event_id,
                                "payload_sha256": payload_sha256,
                                "original_delivery_id": existing["delivery_id"],
                            },
                        )
                        result = WebhookResult(
                            delivery_id=delivery_id,
                            event_id=event.event_id,
                            case_id=str(existing["case_id"]),
                            case_state=str(case["state"]),
                            replayed=True,
                        )
                else:
                    request = CaseCreate(
                        subject_email=event.subject.email,
                        subject_name=event.subject.display_name,
                        transfer_owner=event.departure.transfer_owner_email,
                        effective_at=event.departure.effective_at,
                        risk_tier=event.departure.risk_tier,
                        provider=event.workflow.provider,
                    )
                    case_id = self.workflow.create_case_in_transaction(
                        connection,
                        actor,
                        request,
                        f"webhook:{source_id}:{event.event_id}",
                    )
                    now = iso_now()
                    connection.execute(
                        """
                        INSERT INTO webhook_deliveries
                        (id, source_id, delivery_id, event_id, payload_sha256, case_id,
                         status, received_at, completed_at)
                        VALUES (?, ?, ?, ?, ?, ?, 'accepted', ?, ?)
                        """,
                        (new_id(), source_id, delivery_id, event.event_id, payload_sha256, case_id, now, now),
                    )
                    append_event(
                        connection,
                        event_type="webhook.accepted",
                        actor_id=actor.id,
                        case_id=case_id,
                        payload={
                            "source_id": source_id,
                            "delivery_id": delivery_id,
                            "event_id": event.event_id,
                            "payload_sha256": payload_sha256,
                        },
                    )
                    case = connection.execute("SELECT state FROM cases WHERE id=?", (case_id,)).fetchone()
                    result = WebhookResult(
                        delivery_id=delivery_id,
                        event_id=event.event_id,
                        case_id=case_id,
                        case_state=str(case["state"]),
                        replayed=False,
                    )
            if conflict_message is not None:
                raise ConflictError(conflict_message)
            if result is None:
                raise RuntimeError("Webhook transaction produced no result")
            return result
        finally:
            connection.close()

    def record_rejection(
        self,
        *,
        source_id: str,
        actor_id: str,
        delivery_id: str,
        payload_sha256: str,
        reason_code: str,
    ) -> None:
        connection = connection_for(self.settings)
        try:
            with transaction(connection):
                actor = self._service_actor(connection, actor_id)
                append_event(
                    connection,
                    event_type="webhook.rejected",
                    actor_id=actor.id,
                    payload={
                        "source_id": source_id,
                        "delivery_id": delivery_id,
                        "payload_sha256": payload_sha256,
                        "reason_code": reason_code,
                    },
                )
        finally:
            connection.close()
