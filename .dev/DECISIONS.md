# Architecture Decisions

## ADR-001 — Local-first SQLite instead of PostgreSQL for v0.1

### Context

The first user is a small IT/MSP operator evaluating a sensitive workflow. Requiring a database service slows time-to-first-value.

### Decision

Use SQLite with foreign keys, WAL, migrations, short transactions, and a single worker.

### Reason

It preserves durable state and auditability while enabling a one-command local demo. The scale target does not require horizontal workers.

### Consequences

One worker per database and no multi-tenant hosted claims. PostgreSQL migration is deferred until design-partner load proves it necessary.

## ADR-002 — API/CLI product before a browser dashboard

The v0.1 workflow is operated by technical IT users. A typed API and CLI can prove approval, replay, verification, and evidence quality sooner and with less client-side attack surface. OpenAPI supports future UI work.

## ADR-003 — External writes disabled by default

The default service can discover/plan/verify. Provider writes require `OFFBOARDPROOF_ENABLE_EXTERNAL_WRITES=true`, current digest-bound approvals, and a capable adapter. Account deletion is not implemented.

## ADR-004 — No AI in v0.1

The core workflow is deterministic. AI would add cost, privacy, prompt-injection surface, and weak value. Explanations can be added later behind recorded facts, never action authority.

## ADR-005 — High-entropy bearer tokens with digest storage

Local admins create random 256-bit tokens via CLI. Only SHA-256 digests and non-secret prefixes are stored. Database access is already trusted administrative access; password-style slow hashing is unnecessary for unguessable tokens.

## ADR-006 — Google Workspace integration is capability-bounded

The adapter supports get/suspend/sign-out/group-list/group-remove/verify using official Admin SDK endpoints. Domain-wide delegation and sensitive scopes are explicit operator setup. Missing scopes become actionable exceptions; the evidence report states what was and was not observable.

## ADR-007 — Evidence uses deterministic JSON first

JSON is regenerable and testable. A PDF renderer would increase dependencies and is not required to prove the audit model; PDF is deferred.
