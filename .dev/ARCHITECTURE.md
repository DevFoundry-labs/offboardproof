# Architecture

OffboardProof v0.1 is a local-first modular monolith. SQLite lowers setup friction and keeps identity/evidence data local; a single worker and WAL mode fit the initial organizational scale. The provider protocol keeps Google-specific behavior outside workflow policy.

```text
CLI / REST trigger
       |
       v
auth + idempotent ingestion
       |
       v
case / policy / immutable plan digest -----> approvals bound to digest
       |                                            |
       +------------------- ready ------------------+
                            |
                      durable SQLite job
                            |
                            v
                  least-privilege executor
                      /       |       \
                  mock     manual    Google Admin SDK
                    |          |          |
                    +----------+----------+
                               |
                    independent observation
                               |
                    deterministic verification
                      /                  \
                 verified              exception
                    |                reprocess/waive
                    +--------------------+
                               |
                  hash-linked audit + evidence JSON
```

## States

`RECEIVED → PLANNED → WAITING_APPROVAL → READY → EXECUTING → VERIFYING → COMPLETED`, with `EXCEPTION`, `REJECTED`, and `CANCELLED` branches. A case in `EXCEPTION` can return to `READY` after an authorized requeue or manual evidence completion. Controls are `PENDING`, `EXECUTING`, `VERIFIED`, `EXCEPTION`, or `WAIVED`.

## Boundaries

- API/CLI authenticate actors and call application services.
- Domain modules own state transitions, policy, approval completeness, and verification predicates.
- Repositories own transactions; provider adapters never mutate workflow state directly.
- Worker claims durable jobs with leases and invokes one action at a time.
- External write mode is a global safety gate plus per-provider capability check.
- Evidence renderer reads recorded facts only and cannot call providers.

## Failure semantics

At-least-once jobs plus action idempotency keys. Before a repeated external write, the worker asks the adapter to observe whether the desired state already exists. Timeouts are `OUTCOME_UNKNOWN`, not ordinary transient failures. Bounded retries use 1, 4, and 16 second demo delays (configurable); exhausted/permanent failures create exceptions.

## Trust boundaries

Inbound requests, evidence text, provider payloads, and filenames are untrusted. Bearer tokens are high entropy and stored as digests. Google service-account credentials remain outside the database in a local protected file/environment path. No AI or shell execution exists. Audit hash chaining exposes record alteration but is not claimed to provide external notarization.

## Deployment

One Python process can serve API and a separate `offboardproof worker` process claims jobs. The reproducible demo runs entirely locally against contract-faithful providers. Production users should use filesystem permissions, TLS reverse proxy, managed secret injection, encrypted backups, and one worker per database.
