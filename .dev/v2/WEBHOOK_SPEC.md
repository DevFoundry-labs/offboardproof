# V2 Webhook Intake Contract

Status: DRAFT

## Purpose

Accept an authorized departure event from an external HRIS, ITSM, or integration layer without creating a second authorization or workflow model. A valid webhook must enter the existing `WorkflowService.create_case` path under a dedicated service actor.

## Endpoint

`POST /v1/intake/webhooks/{source_id}`

This endpoint does not accept bearer-token authentication. It authenticates the exact request bytes through the signature protocol below. Unknown or inactive sources return a generic authentication failure.

## Required headers

| Header | Meaning |
|---|---|
| `Content-Type` | Must be exactly `application/json`, with an optional UTF-8 charset. |
| `OffboardProof-Delivery` | Source-unique delivery ID, 8–128 URL-safe characters. |
| `OffboardProof-Timestamp` | Unix epoch seconds as an integer. |
| `OffboardProof-Key-Id` | Identifier for the active or temporarily accepted previous key. |
| `OffboardProof-Signature` | Lowercase `sha256=<64 hex characters>`. |

Header names are case-insensitive under HTTP. Duplicate security headers are rejected.

## Signature protocol

The sender computes:

```text
signed_bytes = b"offboardproof.webhook.v1\n" +
               timestamp_ascii + b"\n" +
               delivery_id_utf8 + b"\n" +
               raw_request_body

signature = HMAC-SHA256(secret, signed_bytes)
header = "sha256=" + lowercase_hex(signature)
```

The receiver:

1. Enforces a maximum body size before buffering the complete request.
2. Parses and validates the timestamp without using body data.
3. Loads the source/key configuration without revealing whether it exists.
4. Calculates the expected signature over the unmodified raw bytes.
5. Compares signatures with `hmac.compare_digest`.
6. Rejects timestamps outside the configured skew window, default 300 seconds.
7. Parses JSON only after authentication succeeds.

The server never normalizes JSON before signature verification.

## Source and secret configuration

Non-secret source configuration is loaded from a JSON file referenced by `OFFBOARDPROOF_WEBHOOK_CONFIG_FILE`. Each source contains:

```json
{
  "schema_version": 1,
  "sources": {
    "hr-primary": {
      "active": true,
      "actor_id": "service-actor-uuid",
      "current_key": {
        "key_id": "2026-08",
        "secret_file": "C:/secure/offboardproof/hr-primary-2026-08.secret"
      },
      "previous_key": {
        "key_id": "2026-05",
        "secret_file": "C:/secure/offboardproof/hr-primary-2026-05.secret",
        "accept_until": "2026-08-24T00:00:00Z"
      }
    }
  }
}
```

Rules:

- Secret files contain raw high-entropy secret bytes and remain outside the repository, database, evidence directory, and backups unless the operator explicitly includes them.
- The service rejects secrets shorter than 32 bytes.
- Relative secret paths are rejected.
- A configured actor must exist, be active, and have role `service`.
- Configuration is validated at readiness time. An invalid source is disabled; a missing global config does not prevent non-webhook use.
- Previous keys are accepted only until `accept_until`; there is never more than one previous key.

## Canonical event schema

Unknown fields are rejected. Version 1 is:

```json
{
  "schema_version": 1,
  "event_type": "employee.departure.authorized",
  "event_id": "hr-event-0192",
  "occurred_at": "2026-08-17T09:30:00Z",
  "subject": {
    "email": "alex@example.test",
    "display_name": "Alex Morgan"
  },
  "departure": {
    "effective_at": "2026-08-20T17:00:00Z",
    "risk_tier": "standard",
    "transfer_owner_email": "owner@example.test"
  },
  "workflow": {
    "provider": "google"
  }
}
```

Validation:

- Only `employee.departure.authorized` is accepted in V2.
- All timestamps require an explicit offset and are normalized to UTC.
- `occurred_at` cannot be more than five minutes in the future.
- Email and provider normalization reuse existing domain functions.
- `event_id` is 8–128 URL-safe characters.
- Display name is 1–200 characters after trimming.
- Event size defaults to 64 KiB and is configurable only downward/upward within 8–256 KiB.
- The external event does not supply approvals, controls, waiver state, or an arbitrary organization identifier.

## Idempotency and conflict behavior

Migration `0002_webhook_intake.sql` introduces:

```text
webhook_deliveries
- id UUID primary key
- source_id text not null
- delivery_id text not null
- event_id text not null
- payload_sha256 text not null
- case_id text nullable references cases(id)
- status text: accepted | rejected | conflict
- received_at text not null
- completed_at text nullable
- unique(source_id, delivery_id)
- unique(source_id, event_id)
```

The mapped case idempotency key is `webhook:{source_id}:{event_id}`.

Behavior:

- Same source, delivery ID, event ID, and payload digest returns the original result.
- Same event ID under a new delivery ID and the same payload returns the original case and records the replay.
- Reuse of a delivery ID or event ID with a different authenticated payload returns `409 Conflict` and creates no case.
- Concurrent identical requests converge on one delivery/event and one case through database uniqueness plus one transaction boundary.
- Authentication failures are not persisted in `webhook_deliveries`; they increment an in-memory/log metric with no sensitive value.
- Authenticated schema failures may be stored as a safe rejection event containing source, delivery ID, event ID when parseable, reason code, and payload digest—but never the body.

## Response contract

### First accepted delivery

Status `202 Accepted`:

```json
{
  "delivery_id": "delivery-0192",
  "event_id": "hr-event-0192",
  "case_id": "uuid",
  "case_state": "received",
  "replayed": false
}
```

### Valid replay

Status `200 OK` with the same representation and `replayed: true`.

### Errors

- `400`: authenticated but invalid schema/header formatting.
- `401`: unknown source/key, inactive source, invalid signature, or expired previous key. The message is deliberately generic.
- `409`: authenticated delivery/event identifier reused with different content.
- `413`: body too large; processing stops before JSON parsing.
- `415`: unsupported content type.
- `503`: database unavailable; sender may retry the identical delivery.

## Audit events

- `webhook.accepted`: source ID, delivery ID, event ID, payload digest, case ID.
- `webhook.replayed`: same safe identifiers and original case ID.
- `webhook.rejected`: authenticated source, safe reason code, identifiers if valid, payload digest.
- `webhook.conflict`: safe identifiers and both digests; no payload.

Signature values, secrets, raw bodies, and full request headers are never audit payloads.

## Threat cases that require tests

- Signature computed after JSON reformatting.
- Timestamp represented with whitespace, sign, decimal, overflow, or duplicate header.
- Header/body Unicode normalization differences.
- Source/key enumeration through timing or error text.
- Valid request replayed before and after the skew window.
- Two simultaneous deliveries for one event.
- Delivery ID collision across sources.
- Secret rotation boundary and clock skew.
- Slow or oversized body.
- Database failure before delivery insert, after insert, and after case creation.
- Attempt to inject approvals, roles, organization, or control definitions through unknown fields.

## Implementation boundary

Suggested modules:

- `offboardproof/webhooks/config.py`
- `offboardproof/webhooks/signature.py`
- `offboardproof/webhooks/schemas.py`
- `offboardproof/webhooks/service.py`
- one thin route in `api.py`

The webhook service may depend on `WorkflowService`; the domain service must not depend on FastAPI request objects.
