# OffboardProof

[![CI](https://github.com/DevFoundry-labs/offboardproof/actions/workflows/ci.yml/badge.svg)](https://github.com/DevFoundry-labs/offboardproof/actions/workflows/ci.yml)
[![CodeQL](https://github.com/DevFoundry-labs/offboardproof/actions/workflows/codeql.yml/badge.svg)](https://github.com/DevFoundry-labs/offboardproof/actions/workflows/codeql.yml)

OffboardProof is a verification-first employee-offboarding service. It turns an authorized departure into a digest-bound plan, collects role-separated approvals, executes replay-safe identity actions, observes resulting state, routes failures to explicit exceptions, and exports tamper-evident evidence.

It is intentionally local-first: one Python process, SQLite, a REST API, a CLI, and a durable worker. External writes are disabled by default. V2 adds authenticated external intake, portable signed evidence, and explicit evidence lifecycle operations without introducing a hosted control plane.

## Why it exists

Offboarding often ends at “the ticket was closed.” That does not prove the account was suspended, sessions were invalidated, access groups were removed, or a transfer was acknowledged. OffboardProof records the desired state, authorization, action receipt, post-action observation, exception history, and immutable completion boundary in one evidence bundle.

## Workflow

`received → waiting_approval → ready → executing → waiting_manual → completed`

Any failed or drifting control enters `exception`. A case completes only when every required control is independently observed, explicitly provider-acknowledged where observation is impossible, manually attested, or time-bounded and security-waived.

## Quick start

Requires Python 3.12+.

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
offboardproof demo
```

The demo creates a synthetic employee, suppresses a duplicate trigger, recovers from one transient provider failure, verifies four automated controls, records a manual transfer attestation, validates the audit hash chain, and writes evidence under `.offboardproof-demo/`.

To run the API:

```powershell
offboardproof init
offboardproof token-create --name "Local operator" --role operator
$env:OFFBOARDPROOF_TOKEN = "<one-time-token>"
offboardproof serve
```

Interactive OpenAPI documentation is then available at `http://127.0.0.1:8000/docs`. See [docs/development.md](docs/development.md) for an end-to-end API workflow.

## Safety model

- Bearer tokens are generated with high entropy and stored only as SHA-256 digests.
- HR, manager, security, operator, auditor, and admin roles have distinct permissions.
- Approvals bind to the exact SHA-256 plan digest; a changed plan needs fresh approvals.
- Every action and case has an idempotency key.
- Jobs use durable leases, bounded retries, reconciliation before mutation, and explicit outcome-unknown handling.
- Audit events form a hash chain. Evidence is generated at the `case.completed` boundary.
- Webhook intake authenticates the exact raw request bytes with HMAC-SHA256, bounded clock skew, rotating file-backed secrets, and replay-safe delivery/event identifiers.
- Evidence v2 uses deterministic canonical JSON and a detached Ed25519 manifest. Verification requires an operator-trusted public key; a bundled key is never trusted implicitly.
- Retention is snapshotted at case creation. Legal holds and dry-run reports are supported, but automatic physical deletion is intentionally absent.
- Backups use SQLite online backup, inventory digests, evidence verification, and scratch-only restore drills; webhook secrets and private signing keys are excluded.
- Google Workspace writes require both configuration and `OFFBOARDPROOF_ENABLE_EXTERNAL_WRITES=true`.
- Logs and errors avoid credentials; evidence contains operational identity data and must be protected.

Read [docs/security-model.md](docs/security-model.md) before enabling a real provider.

## Provider support

The built-in `mock` provider is deterministic and fully observable. The bounded Google Workspace adapter supports account suspension, session sign-out, and group removal. Google exposes observable suspension and membership state; its session sign-out endpoint provides acknowledgement rather than a queryable signed-out final state, so OffboardProof labels that control `acknowledged` instead of claiming independent verification. See [docs/google-workspace.md](docs/google-workspace.md).

## V2 operations

The V2 commands and configuration boundaries are documented in [docs/v2-operations.md](docs/v2-operations.md). Common examples:

```powershell
offboardproof evidence-export-v2 <case-id>
offboardproof evidence-verify --evidence <evidence.json> --manifest <manifest.json> --trusted-public-key <operator.pub>
offboardproof retention-report --as-of 2027-08-17T00:00:00Z
offboardproof backup-create --destination D:\offboardproof-backup
offboardproof backup-verify --backup D:\offboardproof-backup
offboardproof restore-verify --backup D:\offboardproof-backup --scratch D:\offboardproof-restore-check
```

## Scope

Version 0.2.0 remains a focused single-organization engine and API, not a universal HRIS, ITSM, or secrets vault. It does not physically purge evidence, delete accounts, transfer Google Drive content, send notifications, or include a browser dashboard. Its design-partner validation gate remains open; synthetic measurements are not customer ROI. See [docs/roadmap.md](docs/roadmap.md).

## Development

```powershell
ruff check .
ruff format --check .
mypy src
pytest --cov=offboardproof --cov-report=term-missing
python -m build
pip-audit
detect-secrets scan --all-files
```

Architecture, operating limits, and contribution guidance live in [docs/architecture.md](docs/architecture.md), [docs/troubleshooting.md](docs/troubleshooting.md), and [CONTRIBUTING.md](CONTRIBUTING.md).

## License

Apache License 2.0. See [LICENSE](LICENSE).
