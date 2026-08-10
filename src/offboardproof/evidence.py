from __future__ import annotations

import json
import os
import sqlite3
from pathlib import Path
from typing import Any

from offboardproof.audit import verify_chain
from offboardproof.config import Settings
from offboardproof.errors import ConflictError, NotFoundError
from offboardproof.util import canonical_json, iso_now, new_id, sha256_text


def _json_rows(rows: list[sqlite3.Row], *, omit: set[str] | None = None) -> list[dict[str, Any]]:
    omit = omit or set()
    return [{key: row[key] for key in row.keys() if key not in omit} for row in rows]


def build_evidence(connection: sqlite3.Connection, case_id: str) -> dict[str, Any]:
    case = connection.execute("SELECT * FROM cases WHERE id=?", (case_id,)).fetchone()
    if case is None:
        raise NotFoundError(f"Case '{case_id}' was not found")
    if case["state"] != "completed":
        raise ConflictError("Evidence can be sealed only after the case is completed")

    completion = connection.execute(
        """
        SELECT sequence_no FROM audit_events
        WHERE case_id=? AND event_type='case.completed'
        ORDER BY sequence_no LIMIT 1
        """,
        (case_id,),
    ).fetchone()
    if completion is None:
        raise ConflictError("Completed case has no case.completed audit event")

    chain_valid, _, broken_event = verify_chain(connection)
    payload: dict[str, Any] = {
        "schema_version": 1,
        "case": {key: case[key] for key in case.keys()},
        "controls": _json_rows(
            connection.execute("SELECT * FROM controls WHERE case_id=? ORDER BY sequence_no", (case_id,)).fetchall()
        ),
        "approvals": _json_rows(
            connection.execute("SELECT * FROM approvals WHERE case_id=? ORDER BY created_at", (case_id,)).fetchall()
        ),
        "actions": _json_rows(
            connection.execute("SELECT * FROM actions WHERE case_id=? ORDER BY created_at", (case_id,)).fetchall()
        ),
        "exceptions": _json_rows(
            connection.execute("SELECT * FROM exceptions WHERE case_id=? ORDER BY created_at", (case_id,)).fetchall()
        ),
        "observations": _json_rows(
            connection.execute("SELECT * FROM observations WHERE case_id=? ORDER BY created_at", (case_id,)).fetchall()
        ),
        "audit_events": _json_rows(
            connection.execute(
                """
                SELECT sequence_no, event_id, case_id, actor_id, event_type, payload_json,
                       previous_hash, event_hash, created_at
                FROM audit_events WHERE case_id=? AND sequence_no<=? ORDER BY sequence_no
                """,
                (case_id, completion["sequence_no"]),
            ).fetchall()
        ),
        "audit_chain": {
            "global_chain_valid_at_export": chain_valid,
            "broken_event": broken_event,
            "case_cutoff_sequence": completion["sequence_no"],
        },
        "assurance_limit": (
            "Evidence records what configured provider APIs and authorized humans reported at the "
            "listed times. It is not an independent certification and cannot observe systems that "
            "were not connected."
        ),
    }
    payload["bundle_sha256"] = sha256_text(canonical_json(payload))
    return payload


def write_evidence(connection: sqlite3.Connection, settings: Settings, case_id: str) -> tuple[Path, str]:
    payload = build_evidence(connection, case_id)
    settings.evidence_dir.mkdir(parents=True, exist_ok=True)
    destination = settings.evidence_dir / f"{case_id}.evidence.json"
    temporary = destination.with_suffix(".tmp")
    rendered = json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    temporary.write_text(rendered, encoding="utf-8")
    os.replace(temporary, destination)
    digest = sha256_text(rendered)
    existing = connection.execute(
        "SELECT id FROM evidence_artifacts WHERE case_id=? AND path=? AND sha256=?",
        (case_id, str(destination), digest),
    ).fetchone()
    if existing is None:
        connection.execute(
            """
            INSERT INTO evidence_artifacts (id, case_id, path, sha256, mime_type, created_at)
            VALUES (?, ?, ?, ?, 'application/json', ?)
            """,
            (new_id(), case_id, str(destination), digest, iso_now()),
        )
    return destination, digest
