from __future__ import annotations

import json
import sqlite3

from offboardproof.errors import NotFoundError, ProviderError
from offboardproof.providers.base import ActionReceipt, ActionRequest, Discovery, Observation
from offboardproof.util import canonical_json, iso_now


class MockProvider:
    name = "mock"

    def __init__(self, connection: sqlite3.Connection) -> None:
        self.connection = connection

    def seed_account(
        self,
        subject_email: str,
        *,
        suspended: bool = False,
        signed_out: bool = False,
        groups: tuple[str, ...] = (),
        fail_once_operation: str | None = None,
    ) -> None:
        self.connection.execute(
            """
            INSERT INTO mock_accounts
            (provider, subject_email, suspended, signed_out, groups_json, fail_once_operation, updated_at)
            VALUES ('mock', ?, ?, ?, ?, ?, ?)
            ON CONFLICT(provider, subject_email) DO UPDATE SET
                suspended=excluded.suspended,
                signed_out=excluded.signed_out,
                groups_json=excluded.groups_json,
                fail_once_operation=excluded.fail_once_operation,
                updated_at=excluded.updated_at
            """,
            (
                subject_email,
                int(suspended),
                int(signed_out),
                canonical_json(list(groups)),
                fail_once_operation,
                iso_now(),
            ),
        )

    def _row(self, subject_email: str) -> sqlite3.Row:
        row = self.connection.execute(
            "SELECT * FROM mock_accounts WHERE provider='mock' AND subject_email=?",
            (subject_email,),
        ).fetchone()
        if row is None:
            raise NotFoundError(f"Mock account '{subject_email}' was not seeded")
        return row  # type: ignore[no-any-return]

    def discover(self, subject_email: str) -> Discovery:
        row = self._row(subject_email)
        return Discovery(
            subject_email=subject_email,
            external_id=subject_email,
            suspended=bool(row["suspended"]),
            signed_out=bool(row["signed_out"]),
            groups=tuple(json.loads(row["groups_json"])),
        )

    def execute(self, request: ActionRequest) -> ActionReceipt:
        row = self._row(request.subject_email)
        if row["fail_once_operation"] == request.operation:
            self.connection.execute(
                "UPDATE mock_accounts SET fail_once_operation=NULL, updated_at=? "
                "WHERE provider='mock' AND subject_email=?",
                (iso_now(), request.subject_email),
            )
            raise ProviderError(f"Simulated transient failure for {request.operation}", retryable=True)

        if request.operation == "suspend_account":
            self.connection.execute(
                "UPDATE mock_accounts SET suspended=1, updated_at=? WHERE provider='mock' AND subject_email=?",
                (iso_now(), request.subject_email),
            )
        elif request.operation == "sign_out_sessions":
            self.connection.execute(
                "UPDATE mock_accounts SET signed_out=1, updated_at=? WHERE provider='mock' AND subject_email=?",
                (iso_now(), request.subject_email),
            )
        elif request.operation == "remove_group":
            groups = list(json.loads(row["groups_json"]))
            groups = [group for group in groups if group.lower() != request.target.lower()]
            self.connection.execute(
                "UPDATE mock_accounts SET groups_json=?, updated_at=? WHERE provider='mock' AND subject_email=?",
                (canonical_json(groups), iso_now(), request.subject_email),
            )
        else:
            raise ProviderError(f"Mock provider does not support operation '{request.operation}'")
        return ActionReceipt(external_reference=f"mock:{request.action_id}")

    def observe(self, request: ActionRequest) -> Observation:
        discovery = self.discover(request.subject_email)
        if request.operation == "suspend_account":
            observed: dict[str, object] = {"suspended": discovery.suspended}
            satisfied = discovery.suspended is True
        elif request.operation == "sign_out_sessions":
            observed = {"signed_out": discovery.signed_out}
            satisfied = discovery.signed_out is True
        elif request.operation == "remove_group":
            present = any(group.lower() == request.target.lower() for group in discovery.groups)
            observed = {"group": request.target, "present": present}
            satisfied = not present
        else:
            raise ProviderError(f"Mock provider cannot observe operation '{request.operation}'")
        return Observation(
            external_id=discovery.external_id,
            observed=observed,
            satisfied=satisfied,
        )
