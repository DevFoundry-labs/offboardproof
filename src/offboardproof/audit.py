from __future__ import annotations

import sqlite3
from typing import Any

from offboardproof.util import canonical_json, iso_now, new_id, sha256_text

GENESIS_HASH = "0" * 64


def append_event(
    connection: sqlite3.Connection,
    *,
    event_type: str,
    payload: dict[str, Any],
    case_id: str | None = None,
    actor_id: str | None = None,
) -> str:
    previous = connection.execute("SELECT event_hash FROM audit_events ORDER BY sequence_no DESC LIMIT 1").fetchone()
    previous_hash = previous["event_hash"] if previous else GENESIS_HASH
    event_id = new_id()
    created_at = iso_now()
    payload_json = canonical_json(payload)
    event_hash = sha256_text(
        "|".join(
            [
                previous_hash,
                event_id,
                case_id or "",
                actor_id or "",
                event_type,
                payload_json,
                created_at,
            ]
        )
    )
    connection.execute(
        """
        INSERT INTO audit_events
        (event_id, case_id, actor_id, event_type, payload_json, previous_hash, event_hash, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            event_id,
            case_id,
            actor_id,
            event_type,
            payload_json,
            previous_hash,
            event_hash,
            created_at,
        ),
    )
    return event_hash


def verify_chain(connection: sqlite3.Connection) -> tuple[bool, int, str | None]:
    previous_hash = GENESIS_HASH
    count = 0
    rows = connection.execute("SELECT * FROM audit_events ORDER BY sequence_no").fetchall()
    for row in rows:
        expected = sha256_text(
            "|".join(
                [
                    previous_hash,
                    row["event_id"],
                    row["case_id"] or "",
                    row["actor_id"] or "",
                    row["event_type"],
                    row["payload_json"],
                    row["created_at"],
                ]
            )
        )
        if row["previous_hash"] != previous_hash or row["event_hash"] != expected:
            return False, count, row["event_id"]
        previous_hash = row["event_hash"]
        count += 1
    return True, count, None
