# OffboardProof

[![CI](https://github.com/DevFoundry-labs/offboardproof/actions/workflows/ci.yml/badge.svg)](https://github.com/DevFoundry-labs/offboardproof/actions/workflows/ci.yml)
[![CodeQL](https://github.com/DevFoundry-labs/offboardproof/actions/workflows/codeql.yml/badge.svg)](https://github.com/DevFoundry-labs/offboardproof/actions/workflows/codeql.yml)

OffboardProof is a verification-first employee-offboarding service. It turns an authorized departure into a digest-bound plan, collects role-separated approvals, executes replay-safe identity actions, observes resulting state, routes failures to explicit exceptions, and exports tamper-evident evidence.

It is intentionally local-first: one Python process, SQLite, a REST API, a CLI, and a durable worker. External writes are disabled by default.

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
- Google Workspace writes require both configuration and `OFFBOARDPROOF_ENABLE_EXTERNAL_WRITES=true`.
- Logs and errors avoid credentials; evidence contains operational identity data and must be protected.

Read [docs/security-model.md](docs/security-model.md) before enabling a real provider.

## Provider support

The built-in `mock` provider is deterministic and fully observable. The bounded Google Workspace adapter supports account suspension, session sign-out, and group removal. Google exposes observable suspension and membership state; its session sign-out endpoint provides acknowledgement rather than a queryable signed-out final state, so OffboardProof labels that control `acknowledged` instead of claiming independent verification. See [docs/google-workspace.md](docs/google-workspace.md).

## Scope

Version 0.1.0 is a focused engine and API, not a universal HRIS, ITSM, or secrets vault. It does not delete accounts, transfer Google Drive content, send notifications, or include a browser dashboard. See [docs/roadmap.md](docs/roadmap.md).

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
