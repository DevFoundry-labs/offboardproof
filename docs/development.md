# Development and API walkthrough

## Local setup

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
offboardproof init --database .offboardproof/dev.db
```

Create separate tokens for HR, manager, operator, security, and auditor as needed. The plaintext token appears once. Set `OFFBOARDPROOF_TOKEN` before using authenticated CLI commands.

## Workflow walkthrough

1. Seed a synthetic account with `offboardproof mock-seed --email alex@example.test --group engineering@example.test`.
2. Create a case with an effective time in RFC 3339 form and a unique idempotency key.
3. Plan it as an operator. Record the returned plan digest.
4. Approve the exact plan as HR and manager; high-risk plans also require security.
5. Start `offboardproof worker`. It observes, mutates, verifies, and records each automated control.
6. Complete the manual transfer control with a durable evidence note.
7. Run `offboardproof case-verify`, `offboardproof audit-verify`, and `offboardproof evidence-export`.

Every REST request except liveness/readiness uses `Authorization: Bearer …`. Creation also requires `Idempotency-Key`. OpenAPI at `/docs` is the canonical request schema.

## Schema changes

Add a numbered SQL file to both `migrations/` and the packaged `src/offboardproof/migrations/` directory. Migrations must be forward-only, transactional, deterministic, and tested from a blank database. Never edit a released migration.

## Release gates

The release workflow only publishes GitHub artifacts; this package is not uploaded to PyPI. A release candidate must pass formatting, lint, strict typing, branch coverage, dependency audit, secret scan, package build, installed-wheel smoke test, demo, and clean-worktree checks.
