from __future__ import annotations

import hashlib
import json
import os
import sqlite3
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from offboardproof import __version__
from offboardproof.audit import verify_chain
from offboardproof.config import Settings
from offboardproof.errors import ConflictError, NotFoundError
from offboardproof.evidence_signing import (
    b64url_decode,
    b64url_encode,
    load_signing_key,
    public_key_bytes,
    public_key_fingerprint,
)
from offboardproof.util import canonical_json, iso_now, new_id, parse_utc

ASSURANCE_LIMIT = (
    "Evidence records configured provider observations and authorized human statements; "
    "it is not an independent certification."
)


def _existing_signed_is_valid(
    existing: sqlite3.Row,
    evidence_path: Path,
    manifest_path: Path,
    digest: str,
    case_id: str,
    completion_hash: str,
) -> bool:
    try:
        if hashlib.sha256(evidence_path.read_bytes()).hexdigest() != digest:
            return False
        manifest = json.loads(manifest_path.read_bytes())
        statement = manifest["statement"]
        public_bytes = b64url_decode(manifest["public_key"]["value"])
        fingerprint = hashlib.sha256(public_bytes).hexdigest()
        if (
            manifest["signing_status"] != "signed"
            or statement["case_id"] != case_id
            or statement["evidence_sha256"] != digest
            or statement["completion_event_hash"] != completion_hash
            or statement["key_id"] != existing["signing_key_id"]
            or fingerprint != existing["public_key_fingerprint"]
            or fingerprint != manifest["public_key"]["fingerprint_sha256"]
        ):
            return False
        Ed25519PublicKey.from_public_bytes(public_bytes).verify(
            b64url_decode(manifest["signature"]["value"]),
            canonical_json(statement).encode("utf-8"),
        )
        return True
    except (InvalidSignature, KeyError, OSError, TypeError, ValueError, json.JSONDecodeError):
        return False


def _timestamp(value: str | None) -> str | None:
    if value is None:
        return None
    return parse_utc(value).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _json_value(value: str | None) -> Any:
    return None if value is None else json.loads(value)


def _select_rows(
    connection: sqlite3.Connection,
    query: str,
    parameters: tuple[object, ...],
    fields: tuple[str, ...],
    json_fields: dict[str, str] | None = None,
) -> list[dict[str, Any]]:
    json_fields = json_fields or {}
    result: list[dict[str, Any]] = []
    for row in connection.execute(query, parameters).fetchall():
        item = {field: row[field] for field in fields}
        for source, destination in json_fields.items():
            item[destination] = _json_value(row[source])
            if destination != source:
                item.pop(source, None)
        result.append(item)
    return result


def build_evidence_v2(connection: sqlite3.Connection, case_id: str) -> dict[str, Any]:
    case = connection.execute("SELECT * FROM cases WHERE id=?", (case_id,)).fetchone()
    if case is None:
        raise NotFoundError(f"Case '{case_id}' was not found")
    if case["state"] != "completed":
        raise ConflictError("Evidence can be exported only after the case is completed")
    completion = connection.execute(
        """
        SELECT sequence_no, event_id, event_hash, created_at FROM audit_events
        WHERE case_id=? AND event_type='case.completed'
        ORDER BY sequence_no LIMIT 1
        """,
        (case_id,),
    ).fetchone()
    if completion is None:
        raise ConflictError("Completed case has no case.completed audit event")
    chain_valid, _, broken_event = verify_chain(connection)
    if not chain_valid:
        raise ConflictError(f"Audit chain is invalid at event '{broken_event}'")

    case_fields = (
        "id",
        "organization_id",
        "idempotency_key",
        "subject_email",
        "subject_name",
        "transfer_owner",
        "effective_at",
        "risk_tier",
        "provider",
        "state",
        "plan_version",
        "plan_digest",
        "created_by",
        "created_at",
        "updated_at",
        "completed_at",
        "retention_until",
        "retention_policy_id",
    )
    case_payload = {field: case[field] for field in case_fields}
    case_payload["required_roles"] = _json_value(case["required_roles_json"])
    for field in ("effective_at", "created_at", "updated_at", "completed_at", "retention_until"):
        case_payload[field] = _timestamp(case_payload[field])

    controls = _select_rows(
        connection,
        "SELECT * FROM controls WHERE case_id=? ORDER BY sequence_no, id",
        (case_id,),
        (
            "id",
            "control_type",
            "provider",
            "target",
            "desired_json",
            "state",
            "required",
            "manual",
            "sequence_no",
            "evidence_quality",
            "created_at",
            "updated_at",
        ),
        {"desired_json": "desired"},
    )
    approvals = _select_rows(
        connection,
        "SELECT * FROM approvals WHERE case_id=? ORDER BY created_at, id",
        (case_id,),
        ("id", "actor_id", "role", "decision", "reason", "plan_digest", "created_at"),
    )
    actions = _select_rows(
        connection,
        "SELECT * FROM actions WHERE case_id=? ORDER BY created_at, id",
        (case_id,),
        (
            "id",
            "control_id",
            "idempotency_key",
            "operation",
            "payload_json",
            "status",
            "attempt_count",
            "external_reference",
            "outcome_kind",
            "created_at",
            "updated_at",
        ),
        {"payload_json": "payload"},
    )
    exceptions = _select_rows(
        connection,
        "SELECT * FROM exceptions WHERE case_id=? ORDER BY created_at, id",
        (case_id,),
        (
            "id",
            "control_id",
            "action_id",
            "category",
            "retryable",
            "status",
            "owner_actor_id",
            "due_at",
            "summary",
            "resolution_note",
            "created_at",
            "updated_at",
        ),
    )
    observations = _select_rows(
        connection,
        "SELECT * FROM observations WHERE case_id=? ORDER BY created_at, id",
        (case_id,),
        ("id", "control_id", "provider", "external_id", "observed_json", "satisfied", "quality", "created_at"),
        {"observed_json": "observed"},
    )
    audit_events = _select_rows(
        connection,
        """
        SELECT * FROM audit_events WHERE case_id=? AND sequence_no<=?
        ORDER BY sequence_no
        """,
        (case_id, completion["sequence_no"]),
        (
            "sequence_no",
            "event_id",
            "case_id",
            "actor_id",
            "event_type",
            "payload_json",
            "previous_hash",
            "event_hash",
            "created_at",
        ),
        {"payload_json": "payload"},
    )
    for collection in (controls, approvals, actions, exceptions, observations, audit_events):
        for item in collection:
            for key in ("created_at", "updated_at", "due_at"):
                if key in item:
                    item[key] = _timestamp(item[key])

    assurance_counts = {"observed": 0, "acknowledged": 0, "human_attested": 0, "waived": 0}
    for control in controls:
        if control["state"] == "waived":
            assurance_counts["waived"] += 1
        elif control["evidence_quality"] in assurance_counts:
            assurance_counts[str(control["evidence_quality"])] += 1

    return {
        "schema_version": 2,
        "application": {"name": "offboardproof", "version": __version__},
        "case": case_payload,
        "controls": controls,
        "approvals": approvals,
        "actions": actions,
        "exceptions": exceptions,
        "observations": observations,
        "audit_events": audit_events,
        "completion": {
            "sequence_no": completion["sequence_no"],
            "event_id": completion["event_id"],
            "event_hash": completion["event_hash"],
            "completed_at": _timestamp(completion["created_at"]),
        },
        "retention": {
            "retention_until": _timestamp(case["retention_until"]),
            "policy_snapshot": case["retention_policy_id"],
        },
        "assurance": {
            "observed_controls": assurance_counts["observed"],
            "acknowledged_controls": assurance_counts["acknowledged"],
            "human_attested_controls": assurance_counts["human_attested"],
            "waived_controls": assurance_counts["waived"],
            "limit": ASSURANCE_LIMIT,
        },
    }


def evidence_bytes(payload: dict[str, Any]) -> bytes:
    return (canonical_json(payload) + "\n").encode("utf-8")


def write_evidence_v2(
    connection: sqlite3.Connection,
    settings: Settings,
    case_id: str,
) -> tuple[Path, Path, str]:
    payload = build_evidence_v2(connection, case_id)
    rendered = evidence_bytes(payload)
    digest = hashlib.sha256(rendered).hexdigest()
    completion_hash = str(payload["completion"]["event_hash"])
    settings.evidence_dir.mkdir(parents=True, exist_ok=True)
    evidence_path = settings.evidence_dir / f"{case_id}.evidence.v2.json"
    manifest_path = settings.evidence_dir / f"{case_id}.evidence.v2.manifest.json"
    existing = connection.execute(
        """
        SELECT * FROM evidence_artifacts
        WHERE case_id=? AND schema_version=2 AND evidence_sha256=?
        ORDER BY created_at LIMIT 1
        """,
        (case_id, digest),
    ).fetchone()
    if (
        existing is not None
        and existing["signing_status"] == "signed"
        and evidence_path.is_file()
        and manifest_path.is_file()
        and _existing_signed_is_valid(existing, evidence_path, manifest_path, digest, case_id, completion_hash)
    ):
        return evidence_path, manifest_path, digest
    signing_key = load_signing_key(settings)
    statement = {
        "domain": "offboardproof.evidence.signature.v1",
        "case_id": case_id,
        "evidence_schema_version": 2,
        "evidence_sha256": digest,
        "completion_event_hash": completion_hash,
        "key_id": signing_key.key_id if signing_key else "unsigned",
    }
    if signing_key is None:
        manifest: dict[str, Any] = {
            "manifest_schema_version": 1,
            "statement": statement,
            "signing_status": "unsigned",
            "reason_code": "signing_not_configured",
        }
        signing_status = "unsigned"
        algorithm = key_id = fingerprint = None
    else:
        statement_bytes = canonical_json(statement).encode("utf-8")
        signature = signing_key.private_key.sign(statement_bytes)
        fingerprint = public_key_fingerprint(signing_key.public_key)
        manifest = {
            "manifest_schema_version": 1,
            "statement": statement,
            "signature": {
                "algorithm": "Ed25519",
                "encoding": "base64url-no-padding",
                "value": b64url_encode(signature),
            },
            "public_key": {
                "encoding": "raw-base64url-no-padding",
                "fingerprint_sha256": fingerprint,
                "value": b64url_encode(public_key_bytes(signing_key.public_key)),
            },
            "signing_status": "signed",
        }
        signing_status = "signed"
        algorithm = "Ed25519"
        key_id = signing_key.key_id

    evidence_tmp = evidence_path.with_suffix(evidence_path.suffix + ".tmp")
    manifest_tmp = manifest_path.with_suffix(manifest_path.suffix + ".tmp")
    evidence_tmp.write_bytes(rendered)
    manifest_tmp.write_bytes(evidence_bytes(manifest))
    os.replace(evidence_tmp, evidence_path)
    os.replace(manifest_tmp, manifest_path)

    if existing is None:
        connection.execute(
            """
            INSERT INTO evidence_artifacts (
                id, case_id, path, sha256, mime_type, created_at, schema_version,
                manifest_path, evidence_sha256, signing_status, signing_algorithm,
                signing_key_id, public_key_fingerprint, completion_event_hash
            ) VALUES (?, ?, ?, ?, 'application/json', ?, 2, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                new_id(),
                case_id,
                str(evidence_path),
                digest,
                iso_now(),
                str(manifest_path),
                digest,
                signing_status,
                algorithm,
                key_id,
                fingerprint,
                completion_hash,
            ),
        )
    else:
        connection.execute(
            """
            UPDATE evidence_artifacts
            SET manifest_path=?, sha256=?, signing_status=?, signing_algorithm=?,
                signing_key_id=?, public_key_fingerprint=?, completion_event_hash=?
            WHERE id=?
            """,
            (
                str(manifest_path),
                digest,
                signing_status,
                algorithm,
                key_id,
                fingerprint,
                completion_hash,
                existing["id"],
            ),
        )
    return evidence_path, manifest_path, digest
