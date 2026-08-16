# Evidence Schema V2 and Signature Contract

Status: DRAFT

## Purpose

Make a completed-case export independently portable and cryptographically verifiable without overstating who signed it or what provider state was observable.

V2 separates three properties:

1. **Integrity:** the evidence bytes have not changed.
2. **Origin:** the signing key matches a public key the verifier already trusts.
3. **Assurance:** each control remains labeled observed, acknowledged, human-attested, or waived.

A bundled public key alone proves self-consistency, not trusted origin. The default verifier therefore requires an operator-supplied trusted public key or pinned fingerprint.

## Export set

For case `{case_id}`:

```text
{case_id}.evidence.v2.json
{case_id}.evidence.v2.manifest.json
```

The evidence file is canonical UTF-8 JSON with no BOM and exactly one trailing LF. It does not contain its own digest or signature.

The manifest is deterministic canonical JSON with exactly one trailing LF. It contains the signing statement, signature, and optional transport copy of the public key.

## Evidence envelope

Top-level keys:

```json
{
  "schema_version": 2,
  "application": {
    "name": "offboardproof",
    "version": "0.2.0"
  },
  "case": {},
  "controls": [],
  "approvals": [],
  "actions": [],
  "exceptions": [],
  "observations": [],
  "audit_events": [],
  "completion": {
    "sequence_no": 42,
    "event_id": "uuid",
    "event_hash": "sha256-hex",
    "completed_at": "RFC3339 UTC"
  },
  "retention": {
    "retention_until": "RFC3339 UTC or null",
    "policy_snapshot": "default-365-days or explicit identifier"
  },
  "assurance": {
    "observed_controls": 3,
    "acknowledged_controls": 1,
    "human_attested_controls": 1,
    "waived_controls": 0,
    "limit": "Evidence records configured provider observations and authorized human statements; it is not an independent certification."
  }
}
```

Rules:

- Only events at or before the first `case.completed` sequence are included.
- Rows use explicit allowlists; internal-only or future columns never appear automatically.
- JSON-valued database columns are embedded as JSON values, not serialized JSON strings.
- Collections have stable order based on domain sequence then stable identifiers.
- Timestamps are normalized to UTC with a `Z` suffix and fixed microsecond policy.
- Approval and actor identifiers remain because evidence must establish authorization; bearer token metadata never appears.
- Post-completion lifecycle events do not rewrite the sealed evidence. They belong to later lifecycle reports.
- Evidence schema v1 remains readable and verifiable by its legacy digest behavior.

## Signing statement

The signer computes the exact evidence file bytes and constructs:

```json
{
  "domain": "offboardproof.evidence.signature.v1",
  "case_id": "uuid",
  "evidence_schema_version": 2,
  "evidence_sha256": "64 lowercase hex characters",
  "completion_event_hash": "64 lowercase hex characters",
  "key_id": "operator-defined-stable-id"
}
```

The Ed25519 signature is calculated over the canonical UTF-8 bytes of this statement with no trailing LF. The domain string prevents the key/signature from being confused with another protocol.

## Manifest envelope

```json
{
  "manifest_schema_version": 1,
  "statement": {
    "domain": "offboardproof.evidence.signature.v1",
    "case_id": "uuid",
    "evidence_schema_version": 2,
    "evidence_sha256": "hex",
    "completion_event_hash": "hex",
    "key_id": "pilot-2026-q3"
  },
  "signature": {
    "algorithm": "Ed25519",
    "encoding": "base64url-no-padding",
    "value": "..."
  },
  "public_key": {
    "encoding": "raw-base64url-no-padding",
    "fingerprint_sha256": "hex",
    "value": "optional transport copy"
  },
  "signing_status": "signed"
}
```

Unsigned evaluation exports use `signing_status: "unsigned"`, omit `signature`, and may contain a safe reason code. They are never described as sealed or origin-verified.

## Key configuration

Settings:

- `OFFBOARDPROOF_SIGNING_KEY_FILE`: absolute path to an encrypted PKCS8 or explicitly supported raw private key file.
- `OFFBOARDPROOF_SIGNING_KEY_PASSWORD_FILE`: optional absolute path, never an inline environment password.
- `OFFBOARDPROOF_SIGNING_KEY_ID`: required stable identifier when signing is enabled.
- `OFFBOARDPROOF_REQUIRE_SIGNED_EVIDENCE`: defaults false for evaluation; pilot configuration sets true.

Rules:

- Private key files remain outside the database, repository, evidence directory, and ordinary evidence backup.
- Public keys are exported separately and distributed through an authenticated channel.
- Key ID is not a trust anchor.
- When signed evidence is required, key load/sign failure prevents case evidence completion and opens an operational exception; it never silently emits unsigned evidence.
- When signing is optional, an unsigned artifact and audit event state that fact explicitly.
- Historical evidence keeps its original key ID. Rotation changes only new signatures.

## Verification interface

CLI:

```text
offboardproof evidence-verify \
  --evidence CASE.evidence.v2.json \
  --manifest CASE.evidence.v2.manifest.json \
  --trusted-public-key pilot-2026-q3.pub
```

Machine-readable output:

```json
{
  "valid": true,
  "integrity": "verified",
  "origin": "trusted_key_match",
  "assurance": "mixed_observed_and_acknowledged",
  "case_id": "uuid",
  "key_id": "pilot-2026-q3",
  "evidence_sha256": "hex"
}
```

The CLI exits:

- `0`: valid signature and trusted-key match.
- `2`: malformed inputs or unsupported schema/algorithm.
- `3`: digest mismatch.
- `4`: signature failure.
- `5`: supplied trust anchor does not match manifest fingerprint.
- `6`: unsigned evidence.

API:

- `POST /v1/evidence/verify` is read-only and accepts bounded multipart files only if upload handling is deliberately added.
- Preferred first slice is CLI/library verification to avoid expanding the HTTP attack surface.
- A later API endpoint should return verification facts, never persist uploaded third-party evidence by default.

## Persistence changes

Migration `0003_evidence_v2.sql` extends `evidence_artifacts` with:

```text
- schema_version integer not null default 1
- manifest_path text nullable
- evidence_sha256 text nullable
- signing_status text not null default 'legacy'
- signing_algorithm text nullable
- signing_key_id text nullable
- public_key_fingerprint text nullable
- completion_event_hash text nullable
```

Existing `sha256` remains the exact artifact-file digest for backward compatibility. V2 sets it equal to `evidence_sha256` because the evidence file is the signed byte sequence.

## Required tests

- Golden v2 canonical serialization across Windows and Linux.
- Byte change, whitespace change, reordered key, changed manifest statement, changed signature, and changed trusted key all fail as specified.
- Embedded public-key substitution fails when a trusted key is supplied.
- Verification refuses implicit trust of only an embedded key.
- Historical key verifies after active-key rotation.
- Encrypted key load success/failure and absent password behavior.
- Private material absent from database, audit events, logs, exception messages, evidence, built distributions, and test snapshots.
- v1 evidence remains readable and reports `legacy_digest_only` rather than signed origin.
- Concurrent export converges on one artifact record and identical bytes.
- Signing-required failure cannot mark evidence ready.

## Implementation boundary

Suggested modules:

- `offboardproof/evidence/schema_v2.py`
- `offboardproof/evidence/canonical.py`
- `offboardproof/evidence/signing.py`
- `offboardproof/evidence/verification.py`
- `offboardproof/evidence/export.py`

The existing single `evidence.py` module should be split only as part of this vertical slice, retaining a compatibility import for v1 callers.
