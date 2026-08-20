PRAGMA foreign_keys = ON;

ALTER TABLE cases ADD COLUMN retention_until TEXT;
ALTER TABLE cases ADD COLUMN retention_policy_id TEXT;

CREATE INDEX idx_cases_retention_until ON cases(retention_until);

CREATE TABLE legal_holds (
    id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    status TEXT NOT NULL CHECK (status IN ('active','released')),
    reason TEXT NOT NULL CHECK (length(trim(reason)) > 0),
    created_by TEXT NOT NULL REFERENCES actors(id),
    created_at TEXT NOT NULL,
    released_by TEXT REFERENCES actors(id),
    released_at TEXT,
    release_reason TEXT,
    CHECK (
        (status = 'active' AND released_by IS NULL AND released_at IS NULL AND release_reason IS NULL)
        OR
        (status = 'released' AND released_by IS NOT NULL AND released_at IS NOT NULL AND length(trim(release_reason)) > 0)
    )
);

CREATE UNIQUE INDEX idx_legal_holds_one_active_per_case ON legal_holds(case_id) WHERE status = 'active';
CREATE INDEX idx_legal_holds_case_status ON legal_holds(case_id, status);
