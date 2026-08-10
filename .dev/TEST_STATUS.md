# Test Status

## Passed gates

- `python -m ruff format --check .`
- `python -m ruff check .`
- `python -m mypy src`
- `python -m pytest -q --cov=offboardproof --cov-report=term-missing`
- `python -m build`
- clean migration and CLI demo in a fresh virtual environment
- `pip-audit`
- `detect-secrets scan --all-files`

## Covered scenarios

- Happy path and completion evidence.
- Missing/stale/rejected approval.
- Duplicate trigger and action replay.
- Transient failure then retry.
- Unknown outcome reconciliation.
- Permanent failure to exception and reprocess.
- Manual control evidence.
- Security-only waiver with expiry.
- Audit hash-chain verification.
- Google adapter HTTP contract tests.

Local result: 15 tests passed with 88.06% branch-aware coverage on Python 3.12.10. Ruff formatting/lint and strict mypy checks passed.
