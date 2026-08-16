# V2 Issue Backlog Draft

Status: FIRST APPROVED BATCH PUBLISHED — V2-01 THROUGH V2-04

Published issues:

- V2-01: https://github.com/DevFoundry-labs/offboardproof/issues/8
- V2-02: https://github.com/DevFoundry-labs/offboardproof/issues/9
- V2-03: https://github.com/DevFoundry-labs/offboardproof/issues/10
- V2-04: https://github.com/DevFoundry-labs/offboardproof/issues/11

V2-05 onward remain local backlog items until the M0 gate passes.

Suggested labels: `v2`, `discovery`, `security`, `api`, `evidence`, `operations`, `provider`, `documentation`, `release`, plus `size:S/M/L`.

## M0 — Pilot validation gate

### V2-01: Run design-partner discovery and publish scope decision

Labels: `v2`, `discovery`, `size:M`

Deliverables:

- Complete the interview/baseline guide with 5–8 participants across at least 3 organizations.
- Score requested capabilities using the documented rubric.
- Identify a pilot trigger/provider/evidence consumer.
- Publish a PII-free keep/revise/stop decision.

Acceptance: all M0 exit criteria are answered with evidence or the build is explicitly stopped.

Dependencies: none.

## M1 — Contracts and migrations

### V2-02: Freeze webhook event and HMAC protocol

Labels: `v2`, `security`, `api`, `size:M`

Acceptance:

- JSON Schema and golden signing vectors exist.
- Header parsing, skew, size, rotation, replay, conflict, and error contracts are unambiguous.
- Threat cases map to tests.

Dependencies: V2-01.

### V2-03: Freeze evidence v2 and detached signature manifest

Labels: `v2`, `security`, `evidence`, `size:M`

Acceptance:

- Allowlists, canonical bytes, signing statement, trust-anchor behavior, exit codes, and v1 compatibility are specified.
- Cross-platform golden evidence/signature vectors exist.

Dependencies: V2-01.

### V2-04: Add forward-only v0.1→v0.2 migrations and fixtures

Labels: `v2`, `operations`, `size:M`

Acceptance:

- `0002_webhook_intake`, `0003_evidence_v2`, and `0004_retention_operations` migrate a real v0.1 fixture.
- Clean install and repeated migration are tested.
- Released migration 0001 is unchanged.

Dependencies: V2-02, V2-03.

## M2 — Secure intake

### V2-05: Load and validate webhook sources with rotating file-backed secrets

Labels: `v2`, `security`, `api`, `size:M`

Acceptance: config validation, service actor mapping, current/previous keys, expiry, readiness, secret length, absolute paths, and redaction tests pass.

Dependencies: V2-02.

### V2-06: Implement raw-body HMAC authentication

Labels: `v2`, `security`, `api`, `size:M`

Acceptance: official golden vectors, constant-time comparison, duplicate-header rejection, timestamp/skew checks, and body limit tests pass before JSON parsing.

Dependencies: V2-05.

### V2-07: Implement replay-safe webhook delivery service

Labels: `v2`, `api`, `security`, `size:L`

Acceptance: first delivery, exact replay, event replay, conflicting reuse, concurrent delivery, database failures, and existing case idempotency tests pass.

Dependencies: V2-04, V2-06.

### V2-08: Add webhook endpoint, safe audit events, and synthetic sender

Labels: `v2`, `api`, `documentation`, `size:M`

Acceptance: endpoint contract/OpenAPI, error behavior, safe audit payloads, example sender, and end-to-end test pass.

Dependencies: V2-07.

## M3 — Signed evidence

### V2-09: Implement evidence schema v2 canonical exporter

Labels: `v2`, `evidence`, `size:L`

Acceptance: allowlisted deterministic bytes match golden vectors on Windows/Linux; completion cutoff and assurance counts are correct; v1 behavior is preserved.

Dependencies: V2-03, V2-04.

### V2-10: Implement Ed25519 key loading and signing

Labels: `v2`, `security`, `evidence`, `size:L`

Acceptance: raw/encrypted supported format, public fingerprint, signing statement, required/optional mode, rotation, permissions where available, and secret-absence tests pass.

Dependencies: V2-03.

### V2-11: Implement offline evidence verification CLI/library

Labels: `v2`, `security`, `evidence`, `size:L`

Acceptance: trusted-key default, explicit result classes/exit codes, all tamper cases, unsigned and v1 classification, and clean-wheel test pass.

Dependencies: V2-09, V2-10.

## M4 — Lifecycle and operations

### V2-12: Add retention snapshot and legal holds

Labels: `v2`, `security`, `operations`, `size:L`

Acceptance: default/explicit snapshot, role checks, active/released hold history, concurrency, audit events, and evidence snapshot tests pass.

Dependencies: V2-04.

### V2-13: Add mutation-free retention report and lifecycle metrics

Labels: `v2`, `operations`, `size:M`

Acceptance: every eligibility state is covered, output is deterministic/digested, aggregate metrics contain no PII, and indexed query plan is reviewed.

Dependencies: V2-12.

### V2-14: Add safe backup and scratch restore verification

Labels: `v2`, `security`, `operations`, `size:L`

Acceptance: SQLite online backup, bounded safe paths, inventory digests, excluded secrets, audit/evidence verification, corruption cases, and Windows/Linux tests pass.

Dependencies: V2-11, V2-12.

### V2-15: Propagate correlation IDs and test structured-log redaction

Labels: `v2`, `security`, `operations`, `size:M`

Acceptance: request/delivery/case/job/provider identifiers correlate without PII; tokens, secrets, signatures, bodies, private keys, and free text are absent from protected fields.

Dependencies: V2-08.

## M5 — Conditional provider evidence

### V2-16: Spike Google Reports correlation for administrative sign-out

Labels: `v2`, `provider`, `discovery`, `size:S`

Acceptance: fixture-backed result states whether a causal signal exists; sign-out remains `acknowledged` unless the evidence supports promotion; scope/latency/retention limits are documented.

Dependencies: V2-01.

### V2-17: Decide whether Entra is in v0.2.0

Labels: `v2`, `provider`, `discovery`, `size:S`

Acceptance: demand gate, permissions, group edge cases, observable postconditions, cloud boundaries, and schedule impact produce a build/defer decision.

Dependencies: V2-01.

If and only if V2-17 says build, create separate discovery, adapter, contract-test, least-privilege documentation, and synthetic-tenant rehearsal issues. Do not hide them inside V2-17.

## M6 — Pilot and release

### V2-18: Run synthetic pilot rehearsal and recovery drill

Labels: `v2`, `security`, `release`, `size:L`

Acceptance: signed trigger through signed evidence, duplicate/retry/exception paths, external-write safety review, backup/restore, key rotation, and retention report pass with artifacts.

Dependencies: V2-08, V2-11, V2-14, V2-15, and any committed provider work.

### V2-19: Run design-partner pilot and publish sanitized findings

Labels: `v2`, `discovery`, `release`, `size:L`

Acceptance: baseline and outcomes for 5–10 cases where permitted; no PII; observed results separated from estimates; defects and scope changes triaged.

Dependencies: V2-18.

### V2-20: Release v0.2.0

Labels: `v2`, `documentation`, `release`, `size:M`

Acceptance: migration/security/operator docs, changelog, quality/security gates, built-wheel smoke, signed release artifacts, protected-main CI, release notes, and roadmap update are verified.

Dependencies: V2-19 and all committed release blockers.

## Recommended first GitHub batch after approval

Open only V2-01 through V2-04 plus milestone shells. Create implementation issues V2-05 onward after M0 confirms the thesis and M1 freezes contracts. This keeps GitHub commitments aligned with evidence.
