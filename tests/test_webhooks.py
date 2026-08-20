from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any

from conftest import World
from fastapi.testclient import TestClient

from offboardproof.api import create_app
from offboardproof.db import connection_for
from offboardproof.enums import Role
from offboardproof.util import canonical_json
from offboardproof.webhooks.signature import sign_for_testing


def _configure(world: World, tmp_path) -> bytes:  # type: ignore[no-untyped-def]
    secret = b"a-secure-webhook-secret-with-more-than-32-bytes"
    secret_file = tmp_path / "webhook.secret"
    secret_file.write_bytes(secret)
    config_file = tmp_path / "webhooks.json"
    config_file.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "sources": {
                    "hr-primary": {
                        "active": True,
                        "actor_id": world.actors[Role.SERVICE].id,
                        "current_key": {"key_id": "current-key", "secret_file": str(secret_file.resolve())},
                    }
                },
            }
        ),
        encoding="utf-8",
    )
    world.settings.webhook_config_file = config_file.resolve()
    return secret


def _event(*, display_name: str = "Alex Morgan") -> dict[str, Any]:
    return {
        "schema_version": 1,
        "event_type": "employee.departure.authorized",
        "event_id": "hr-event-0192",
        "occurred_at": datetime.now(UTC).isoformat(),
        "subject": {"email": "alex@example.test", "display_name": display_name},
        "departure": {
            "effective_at": "2026-08-20T17:00:00Z",
            "risk_tier": "standard",
            "transfer_owner_email": "owner@example.test",
        },
        "workflow": {"provider": "mock"},
    }


def _headers(secret: bytes, raw_body: bytes, *, delivery_id: str, timestamp: int | None = None) -> dict[str, str]:
    timestamp = timestamp if timestamp is not None else int(datetime.now(UTC).timestamp())
    return {
        "Content-Type": "application/json",
        "OffboardProof-Delivery": delivery_id,
        "OffboardProof-Timestamp": str(timestamp),
        "OffboardProof-Key-Id": "current-key",
        "OffboardProof-Signature": sign_for_testing(
            secret=secret,
            timestamp=timestamp,
            delivery_id=delivery_id,
            raw_body=raw_body,
        ),
    }


def test_valid_delivery_replay_and_conflict(world: World, tmp_path) -> None:  # type: ignore[no-untyped-def]
    secret = _configure(world, tmp_path)
    client = TestClient(create_app(world.settings))
    raw_body = canonical_json(_event()).encode()

    first = client.post(
        "/v1/intake/webhooks/hr-primary",
        content=raw_body,
        headers=_headers(secret, raw_body, delivery_id="delivery-0192"),
    )
    assert first.status_code == 202
    assert first.json()["replayed"] is False

    replay = client.post(
        "/v1/intake/webhooks/hr-primary",
        content=raw_body,
        headers=_headers(secret, raw_body, delivery_id="delivery-0193"),
    )
    assert replay.status_code == 200
    assert replay.json()["case_id"] == first.json()["case_id"]
    assert replay.json()["replayed"] is True

    changed_body = canonical_json(_event(display_name="Changed Name")).encode()
    conflict = client.post(
        "/v1/intake/webhooks/hr-primary",
        content=changed_body,
        headers=_headers(secret, changed_body, delivery_id="delivery-0192"),
    )
    assert conflict.status_code == 409

    connection = connection_for(world.settings)
    try:
        assert connection.execute("SELECT count(*) FROM cases").fetchone()[0] == 1
        assert connection.execute("SELECT count(*) FROM webhook_deliveries").fetchone()[0] == 1
        event_types = [
            row["event_type"]
            for row in connection.execute(
                "SELECT event_type FROM audit_events WHERE event_type LIKE 'webhook.%' ORDER BY sequence_no"
            ).fetchall()
        ]
        assert event_types == ["webhook.accepted", "webhook.replayed", "webhook.conflict"]
    finally:
        connection.close()


def test_authentication_and_schema_failures_create_no_case(world: World, tmp_path) -> None:  # type: ignore[no-untyped-def]
    secret = _configure(world, tmp_path)
    client = TestClient(create_app(world.settings))
    raw_body = canonical_json(_event()).encode()
    invalid_signature_headers = _headers(secret, raw_body, delivery_id="delivery-0200")
    invalid_signature_headers["OffboardProof-Signature"] = "sha256=" + "0" * 64

    invalid_signature = client.post(
        "/v1/intake/webhooks/hr-primary",
        content=raw_body,
        headers=invalid_signature_headers,
    )
    assert invalid_signature.status_code == 401
    assert "secret" not in invalid_signature.text.lower()

    invalid_event = _event()
    invalid_event["unexpected"] = "forbidden"
    invalid_body = canonical_json(invalid_event).encode()
    invalid_schema = client.post(
        "/v1/intake/webhooks/hr-primary",
        content=invalid_body,
        headers=_headers(secret, invalid_body, delivery_id="delivery-0201"),
    )
    assert invalid_schema.status_code == 400

    stale = int(datetime.now(UTC).timestamp()) - 1_000
    stale_response = client.post(
        "/v1/intake/webhooks/hr-primary",
        content=raw_body,
        headers=_headers(secret, raw_body, delivery_id="delivery-0202", timestamp=stale),
    )
    assert stale_response.status_code == 401

    connection = connection_for(world.settings)
    try:
        assert connection.execute("SELECT count(*) FROM cases").fetchone()[0] == 0
        assert connection.execute("SELECT count(*) FROM webhook_deliveries").fetchone()[0] == 0
        rejected = connection.execute(
            "SELECT payload_json FROM audit_events WHERE event_type='webhook.rejected'"
        ).fetchone()
        assert rejected is not None
        assert "invalid_event_schema" in rejected["payload_json"]
        assert "alex@example.test" not in rejected["payload_json"]
    finally:
        connection.close()


def test_body_and_content_type_limits(world: World, tmp_path) -> None:  # type: ignore[no-untyped-def]
    secret = _configure(world, tmp_path)
    world.settings.webhook_max_body_bytes = 8_192
    client = TestClient(create_app(world.settings))
    raw_body = canonical_json(_event()).encode()

    unsupported = client.post(
        "/v1/intake/webhooks/hr-primary",
        content=raw_body,
        headers={**_headers(secret, raw_body, delivery_id="delivery-0300"), "Content-Type": "text/plain"},
    )
    assert unsupported.status_code == 415

    oversized_body = b"{" + b" " * 8_192 + b"}"
    oversized = client.post(
        "/v1/intake/webhooks/hr-primary",
        content=oversized_body,
        headers=_headers(secret, oversized_body, delivery_id="delivery-0301"),
    )
    assert oversized.status_code == 413


def test_previous_key_rotation_window_and_raw_body_integrity(world: World, tmp_path) -> None:  # type: ignore[no-untyped-def]
    current_secret = _configure(world, tmp_path)
    previous_secret = b"previous-secure-webhook-secret-more-than-32-bytes"
    previous_file = tmp_path / "previous.secret"
    previous_file.write_bytes(previous_secret)
    config = json.loads(world.settings.webhook_config_file.read_text(encoding="utf-8"))  # type: ignore[union-attr]
    config["sources"]["hr-primary"]["previous_key"] = {
        "key_id": "previous-key",
        "secret_file": str(previous_file.resolve()),
        "accept_until": "2099-01-01T00:00:00Z",
    }
    world.settings.webhook_config_file.write_text(json.dumps(config), encoding="utf-8")  # type: ignore[union-attr]
    client = TestClient(create_app(world.settings))
    raw_body = canonical_json(_event()).encode()
    headers = _headers(previous_secret, raw_body, delivery_id="delivery-0400")
    headers["OffboardProof-Key-Id"] = "previous-key"
    accepted = client.post("/v1/intake/webhooks/hr-primary", content=raw_body, headers=headers)
    assert accepted.status_code == 202

    changed_raw_body = raw_body + b"\n"
    invalid = client.post(
        "/v1/intake/webhooks/hr-primary",
        content=changed_raw_body,
        headers={
            **_headers(current_secret, raw_body, delivery_id="delivery-0401"),
            "OffboardProof-Key-Id": "current-key",
        },
    )
    assert invalid.status_code == 401
