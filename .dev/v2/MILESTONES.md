# V2 Milestones and Critical Path

Status: DRAFT

The milestones are sequenced by dependency and decision risk, not calendar dates. Estimates are relative engineering effort for one focused contributor and exclude waiting for design-partner access.

## M0 — Pilot validation gate

Outcome: decide whether to proceed and freeze the pilot path.

Deliverables:

- Interview guide and sanitized baseline worksheet.
- 5–8 interviews across at least 3 organizations.
- Named pilot trigger, provider, operator, approvers, and evidence consumer.
- Signing-key and retention ownership decisions.
- Entra commit/defer decision.

Exit gate: the discovery criteria in `V2_PLAN.md` pass and a product decision record is approved.

Estimate: 3–5 engineering/product days plus interview scheduling.

## M1 — Contracts and migration skeleton

Outcome: freeze security-critical interfaces before implementation.

Deliverables:

- Webhook protocol and event JSON Schema.
- Evidence v2 schema, signing statement, and golden vectors.
- Retention/legal-hold model.
- Migrations `0002`–`0004` with upgrade fixtures from v0.1.0.
- Threat-model update and acceptance-test matrix.

Exit gate: schemas have compatibility/versioning rules and tests fail for unimplemented behavior.

Depends on: M0.

Estimate: 4–6 days.

## M2 — Secure intake vertical slice

Outcome: a signed external event creates exactly one existing-style case.

Deliverables:

- File-backed source/key configuration and readiness checks.
- Raw-body HMAC verification and rotation.
- Delivery persistence, replay/conflict handling, and audit events.
- Thin FastAPI route and synthetic sender example.
- Fuzz/property/concurrency tests.

Exit gate: the complete webhook acceptance matrix passes on Windows and Linux; no existing case/approval behavior changes.

Depends on: M1 webhook schema/migration.

Estimate: 5–7 days.

## M3 — Signed evidence vertical slice

Outcome: a completed case produces portable evidence that verifies against an external trust anchor.

Deliverables:

- Evidence v2 allowlisted serialization.
- Ed25519 key loading, signing statement, and detached manifest.
- Offline verification library and CLI.
- v1 compatibility classification.
- Key rotation and golden cross-platform tests.

Exit gate: clean-wheel verification succeeds; every tamper case fails with the specified code; private material absence scan passes.

Depends on: M1 evidence schema/migration. Can run alongside M2 after M1.

Estimate: 6–8 days.

## M4 — Lifecycle and operations

Outcome: pilots can understand retention, holds, queue health, and recoverability without unsafe deletion.

Deliverables:

- Retention snapshot and legal holds.
- Retention dry-run report.
- Aggregate operational metrics.
- SQLite online backup, backup verification, and scratch restore drill.
- Correlation IDs and redaction tests.

Exit gate: restore drill reproduces audit/evidence verification and retention reports are mutation-free.

Depends on: M1 retention migration; M3 for signed-artifact restore verification.

Estimate: 6–9 days.

## M5 — Conditional provider decision

Outcome: close provider uncertainty without bloating committed scope.

Deliverables:

- Time-boxed Google Reports correlation result.
- Entra provider contract only if M0 demand gate passes.
- Explicit assurance classification for every considered operation.

Exit gate: decision record says build/defer and why. Any provider code requires contract tests and least-privilege documentation.

Depends on: M0. Spike can run alongside M2/M3.

Estimate: 1–3 days for spikes; 6–10 additional days if Entra is committed.

## M6 — Pilot and v0.2.0 release

Outcome: measured pilot-ready release.

Deliverables:

- Synthetic rehearsal with external writes disabled, then controlled enablement.
- Backup/restore rehearsal.
- 5–10 pilot cases if partner policy permits.
- Baseline/outcome report with PII removed.
- Documentation, changelog, migration guide, security review, and release artifacts.

Exit gate: all V2 release gates pass; pilot results and assurance limitations are explicit.

Depends on: M2, M3, M4, and any committed part of M5.

Estimate: 4–6 engineering days plus pilot observation period.

## Critical path

```text
M0 validation
   → M1 contracts/migrations
      → M2 secure intake ─┐
      → M3 evidence ──────┼→ M4 operations/restore → M6 pilot/release
   → M5 provider decision ┘        (only committed work blocks release)
```

## Scope controls

- M0 failure stops implementation.
- M2 and M3 are the minimum coherent V2 product slice.
- M4 may be split only by deferring backup convenience—not retention truth or restore verification.
- Entra adds schedule only after the demand gate; it cannot silently become critical path.
- UI, SSO, PostgreSQL, multi-worker, and physical purge requests go to a later-candidate list.
