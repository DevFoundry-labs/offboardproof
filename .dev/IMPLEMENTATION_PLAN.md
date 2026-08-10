# Implementation Plan

1. Scaffold a Python package with FastAPI, Typer, versioned SQL migrations, Ruff, mypy, pytest, and build tooling.
2. Implement domain enums, transition rules, policy/action-plan digest, approvals, controls, exceptions, and audit hashing.
3. Implement SQLite persistence, migrations, transaction boundaries, token authentication, outbox/jobs, and leases.
4. Implement mock, manual, and Google Workspace provider adapters behind one capability protocol.
5. Implement application services, REST endpoints, CLI commands, worker, evidence export, and a deterministic demo.
6. Exercise happy, approval, replay, transient retry, permanent exception, manual completion, verification, and audit paths.
7. Add public documentation, security model, CI, templates, release metadata, and a clean-room install/run check.
8. Publish only after local gates pass; inspect remote CI and create v0.1.0.

## Risk areas

- Approval staleness and action replay.
- Unknown external outcomes after timeout.
- Google Workspace domain-wide delegation/scopes.
- Local token bootstrap and accidental external writes.
- Audit/evidence claims exceeding what providers expose.

## External requirements

- Python 3.12+.
- Optional Google Workspace service-account JSON, delegated admin email, and explicitly authorized Admin SDK scopes.
- GitHub CLI only for repository publication, not product runtime.
