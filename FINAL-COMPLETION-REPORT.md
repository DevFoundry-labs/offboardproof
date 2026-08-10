# Final completion report

## Product

OffboardProof v0.1.0 is a local-first, verification-first employee offboarding engine. It accepts an idempotent departure trigger, discovers identity state, creates a digest-bound control plan, collects role-separated approvals, executes durable replay-safe actions, distinguishes observed evidence from provider acknowledgement, handles retries and exceptions, verifies drift, and exports a tamper-evident evidence bundle.

## Delivered scope

- FastAPI REST service and Typer CLI.
- SQLite schema and packaged forward migration.
- Durable leased worker with pre-action reconciliation and bounded retries.
- Deterministic mock provider and bounded Google Workspace adapter.
- HR, manager, security, operator, auditor, admin, and service roles.
- Manual transfer attestation, security waiver, exception requeue, and post-completion verification.
- SHA-256 audit hash chain and deterministic JSON evidence.
- Operator, architecture, security, provider, troubleshooting, roadmap, and contribution documentation.
- CI, CodeQL, Dependabot, issue forms, PR template, and Apache-2.0 license.

## Verification evidence

- Ruff format and lint: passed.
- Strict mypy: passed for 21 source files.
- Pytest: 15 passed.
- Branch-aware coverage: 88.06% (required: 80%).
- Package build: source distribution and wheel produced.
- Clean wheel install/demo: passed in a fresh virtual environment.
- Dependency audit: no known vulnerabilities.
- Tracked-source secret scan: no findings.
- Synthetic demo: five controls satisfied; duplicate trigger suppressed; transient failure recovered; case completed; 18-event audit chain valid; evidence written with SHA-256 digest.
- GitHub CI quality and installed-wheel jobs: passed.
- GitHub CodeQL analysis: passed.
- GitHub license detection: Apache-2.0.
- Dependabot security updates, secret scanning, push protection, and private vulnerability reporting: enabled.

## Assurance and measurement limits

The demo proves workflow properties, not customer ROI. Its 14-touch manual baseline is a research hypothesis requiring design-partner measurement. Google session sign-out has no queryable final-state field in the Directory API, so its evidence is correctly labeled `acknowledged`; suspension and group removal are observed. Evidence is not an independent certification or external timestamp.

## Deployment posture

External writes are disabled by default. Production operators must supply TLS/reverse-proxy controls, restrictive filesystem permissions, encrypted storage, backups, token rotation, evidence retention rules, and least-privilege Google domain-wide delegation. Version 0.1.0 supports one organization and one worker.

## Publication

Target repository: https://github.com/DevFoundry-labs/offboardproof
Target release: https://github.com/DevFoundry-labs/offboardproof/releases/tag/v0.1.0

Verified CI run: https://github.com/DevFoundry-labs/offboardproof/actions/runs/31381005687

Verified CodeQL run: https://github.com/DevFoundry-labs/offboardproof/actions/runs/31381005714
