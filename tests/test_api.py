from __future__ import annotations

from datetime import UTC, datetime

from fastapi.testclient import TestClient

from offboardproof.api import create_app
from offboardproof.enums import Role


def test_health_auth_and_idempotent_create(world) -> None:  # type: ignore[no-untyped-def]
    client = TestClient(create_app(world.settings))
    assert client.get("/health/live").status_code == 200
    assert client.get("/health/ready").json() == {"status": "ready"}
    assert client.get("/v1/cases").status_code == 403
    headers = {
        "Authorization": f"Bearer {world.tokens[Role.HR]}",
        "Idempotency-Key": "api-case-0001",
    }
    body = {
        "subject_email": "alex@example.test",
        "subject_name": "Alex Morgan",
        "transfer_owner": "owner@example.test",
        "effective_at": datetime.now(UTC).isoformat(),
        "risk_tier": "standard",
        "provider": "mock",
    }
    first = client.post("/v1/cases", headers=headers, json=body)
    second = client.post("/v1/cases", headers=headers, json=body)
    assert first.status_code == 201
    assert second.json()["id"] == first.json()["id"]


def test_api_validates_payload_and_role(world) -> None:  # type: ignore[no-untyped-def]
    client = TestClient(create_app(world.settings))
    headers = {
        "Authorization": f"Bearer {world.tokens[Role.HR]}",
        "Idempotency-Key": "api-invalid-0001",
    }
    assert client.post("/v1/cases", headers=headers, json={"unexpected": True}).status_code == 422
    case = world.create(key="api-plan-0001")
    response = client.post(
        f"/v1/cases/{case['id']}/plan",
        headers={"Authorization": f"Bearer {world.tokens[Role.HR]}"},
    )
    assert response.status_code == 403
