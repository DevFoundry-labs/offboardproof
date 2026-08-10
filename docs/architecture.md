# Architecture

## Runtime shape

OffboardProof is a modular monolith with two entry points over one domain model:

```text
CLI / FastAPI
      │
WorkflowService ── append-only hash-chained audit
      │
    SQLite ─────── durable jobs / controls / evidence metadata
      │
    Worker ─────── provider adapter ───── external identity system
```

SQLite is deliberate for the first release: the smallest useful deployment has one organization and one worker, and the database keeps sensitive workflow data under the operator's direct control. WAL mode, foreign keys, transactions, unique idempotency constraints, and short leases supply predictable local durability. Multi-worker or multi-tenant deployment needs a transactional server database and is out of scope.

## Domain invariants

- A case trigger is unique by organization and idempotency key.
- A plan digest covers subject, effective time, transfer owner, provider, required roles, and controls.
- An approval is unique by case, role, and plan digest.
- An automated control owns one replay-safe action and durable job.
- Execution requires all current plan approvals and cannot precede the effective time.
- A worker observes before mutation, allowing safe reconciliation after an ambiguous crash.
- Completion requires every required control to be verified, acknowledged, or security-waived.
- `case.completed` is the immutable cutoff for the evidence bundle.
- Each audit event hashes its canonical payload plus the previous global event hash.

## Failure semantics

Retryable and outcome-unknown errors are delayed with bounded backoff. Before retry, the worker observes state again. Exhausted or non-retryable failures open an exception and move the case to `exception`. An operator can requeue a recoverable exception; security can create a documented, time-bounded waiver. No failure is silently converted to success.

## Evidence semantics

Observed means the provider exposed and satisfied a queryable postcondition. Acknowledged means the mutation endpoint accepted the request but no corresponding final state is queryable. Human-attested means an authorized person supplied a durable note. Waived means security explicitly accepted residual risk until a stated expiration. Those qualities remain distinct in the bundle.
