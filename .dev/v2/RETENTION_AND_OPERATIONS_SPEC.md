# V2 Retention and Operations Contract

Status: DRAFT

## Retention model

Retention in V2 is a visibility and governance feature, not an automated deletion feature.

At case creation, OffboardProof snapshots one of:

- an explicit `retention_until` supplied by an authorized HR/operator request and bounded by policy; or
- the configured default retention period added to the case creation time.

The snapshot is stored on the case and included in evidence schema v2. Later default-policy changes do not rewrite it.

Migration `0004_retention_operations.sql` adds:

```text
cases.retention_until text nullable
cases.retention_policy_id text nullable

legal_holds
- id UUID primary key
- case_id text not null references cases(id)
- status text: active | released
- reason text not null
- created_by text not null references actors(id)
- created_at text not null
- released_by text nullable references actors(id)
- released_at text nullable
- release_reason text nullable
```

Only one active hold may exist per case, enforced by service logic and a partial unique index where supported by SQLite.

## Authorization

- HR/operator may set an allowed retention date only at case creation.
- Security/admin may create or release a legal hold.
- Auditor/operator/security/admin may read retention and hold state.
- No V2 role can physically purge evidence through the product.

Audit events:

- `retention.snapshot_created`
- `legal_hold.created`
- `legal_hold.released`
- `retention.expiring_reported`
- `retention.expired_reported`

## Retention dry run

CLI:

```text
offboardproof retention-report --as-of 2027-08-17T00:00:00Z --format json
```

Each result includes case ID, completion state, retention date, active-hold flag, evidence artifact paths/digests, database row counts by table, and eligibility reason. It never deletes or moves data.

Eligibility categories:

- `not_expired`
- `active_legal_hold`
- `incomplete_case`
- `expired_review_required`
- `missing_retention_policy`

The report itself includes generation time, database schema version, case count, and SHA-256 digest.

## Operational metrics

Extend the existing summary with bounded aggregate data only:

- cases by state
- controls by evidence quality/state
- queued/leased/dead jobs
- oldest available queued job age
- open and overdue exceptions
- evidence signed/unsigned/failed
- cases expiring within configurable horizon
- cases expired with/without legal hold
- duplicate webhook deliveries suppressed
- webhook conflicts and authenticated schema rejections

No metric contains employee email, display name, group name, free-text reason, or provider receipt.

## Backup and restore

Commands:

```text
offboardproof backup-create --destination <new-empty-directory>
offboardproof backup-verify --backup <directory>
offboardproof restore-verify --backup <directory> --scratch <new-empty-directory>
```

V2 does not overwrite a live database through a restore command. `restore-verify` restores into a new scratch location, migrates only when explicitly requested, validates SQLite integrity/foreign keys, verifies the audit chain, checks evidence file digests/signatures, and emits a machine-readable report.

Backup contents:

- SQLite online backup output, not a raw copy of a live WAL database.
- Evidence and manifest files referenced by artifact rows.
- Public signing keys and non-secret configuration snapshot.
- Inventory manifest containing relative paths, sizes, and SHA-256 digests.

Excluded by default:

- actor bearer tokens
- webhook secret files
- evidence private signing keys/passwords
- `.env` files
- unrelated filesystem content

The backup command refuses a destination inside the database, evidence, repository, or source directory and refuses a non-empty destination.

## Required tests

- Default and explicit retention snapshot behavior at UTC/date boundaries.
- Policy change does not mutate existing case snapshot or signed evidence.
- Legal-hold role enforcement and concurrent duplicate hold creation.
- Dry run classifies every state without mutation.
- Metrics contain no PII/free text and use indexed aggregate queries.
- SQLite online backup during worker activity is internally consistent.
- Restore drill catches missing, extra, changed, or path-traversal artifact entries.
- Restore drill validates audit chain and v1/v2 evidence.
- Backup never includes configured secret/private-key paths.
- Windows and Linux path behavior.

## Explicit limit

Secure erasure cannot be guaranteed by deleting a row or file because SQLite pages, WAL files, backups, filesystem snapshots, and storage media may retain bytes. A future purge design requires a separate threat model, legal requirements, backup policy, encryption-key strategy, recovery model, and explicit destructive-action confirmation.
