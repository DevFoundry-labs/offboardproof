# Changelog

All notable changes follow [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and semantic versioning.

## [Unreleased]

### Added

- HMAC-SHA256 authenticated webhook intake with raw-body verification, rotation windows, replay convergence, conflict detection, and safe audit events.
- Evidence schema v2 with deterministic canonical exports, detached Ed25519 manifests, trusted-key verification, explicit unsigned mode, and key-rotation preservation.
- Forward-only schema migrations from v0.1, including real-fixture upgrade and packaged-migration checks.
- Retention snapshots, role-gated legal holds, mutation-free retention reports, and aggregate lifecycle/queue/evidence/webhook metrics.
- SQLite online backups with inventory digests, secret exclusions, evidence verification, and scratch-only restore drills.
- Request correlation IDs and new CLI commands for evidence verification, retention reporting, backup, and restore verification.

### Security

- Signing-required failures cannot mark a case completed and are routed to an explicit operational exception.
- Evidence verification requires an operator-supplied trust anchor and rejects substituted embedded keys.
- Webhook signatures, secrets, raw request bodies, private signing keys, and password files are excluded from persisted audit evidence and backups.

## [0.1.0] - 2026-08-10

### Added

- Digest-bound, role-separated offboarding approvals.
- Durable SQLite workflow, retries, reconciliation, exceptions, and re-verification.
- Mock and bounded Google Workspace providers.
- Hash-chained audit events and deterministic JSON evidence bundles.
- REST API, CLI, synthetic demo, tests, security scans, and release automation.

[0.1.0]: https://github.com/DevFoundry-labs/offboardproof/releases/tag/v0.1.0
[Unreleased]: https://github.com/DevFoundry-labs/offboardproof/compare/v0.1.0...HEAD
