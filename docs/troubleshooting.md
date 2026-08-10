# Troubleshooting

## A case remains `waiting_approval`

Compare `required_roles` with approvals. Approvals must be `approved` and carry the current `plan_digest`. A rejected case cannot execute.

## A worker finds no jobs

Confirm the case is `ready`, approvals are complete, and `effective_at` is not in the future. Run only one worker in v0.1.0.

## A case enters `exception`

Inspect the case's `exceptions` and audit endpoint. Correct provider configuration or external state, then requeue a retryable exception. Use a waiver only after security documents the risk and expiry.

## Google writes are blocked

This is the default. Confirm both delegated credential settings, validate your scopes, then explicitly enable external writes. Never commit a service-account file.

## SQLite is locked

Stop duplicate long-running workers, verify the database directory is writable and local, and avoid network filesystems. WAL sidecar files are expected while the service runs.

## Audit verification fails

Treat this as evidence corruption. Preserve the database and backups, stop mutation, record the reported event ID, and investigate privileged access. Do not “repair” the chain in place.
