PRAGMA foreign_keys = ON;

CREATE TABLE actors (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('admin','hr','manager','operator','security','auditor','service')),
    token_digest TEXT NOT NULL UNIQUE,
    token_prefix TEXT NOT NULL,
    active INTEGER NOT NULL DEFAULT 1 CHECK (active IN (0,1)),
    created_at TEXT NOT NULL
);

CREATE TABLE cases (
    id TEXT PRIMARY KEY,
    organization_id TEXT NOT NULL DEFAULT 'local',
    idempotency_key TEXT NOT NULL,
    subject_email TEXT NOT NULL,
    subject_name TEXT NOT NULL,
    transfer_owner TEXT NOT NULL,
    effective_at TEXT NOT NULL,
    risk_tier TEXT NOT NULL CHECK (risk_tier IN ('standard','high')),
    provider TEXT NOT NULL,
    state TEXT NOT NULL,
    plan_version INTEGER NOT NULL DEFAULT 0,
    plan_digest TEXT,
    required_roles_json TEXT NOT NULL DEFAULT '[]',
    created_by TEXT NOT NULL REFERENCES actors(id),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    completed_at TEXT,
    UNIQUE (organization_id, idempotency_key)
);

CREATE INDEX idx_cases_state_effective ON cases(state, effective_at);

CREATE TABLE controls (
    id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    control_type TEXT NOT NULL,
    provider TEXT NOT NULL,
    target TEXT NOT NULL,
    desired_json TEXT NOT NULL,
    state TEXT NOT NULL,
    required INTEGER NOT NULL DEFAULT 1 CHECK (required IN (0,1)),
    manual INTEGER NOT NULL DEFAULT 0 CHECK (manual IN (0,1)),
    sequence_no INTEGER NOT NULL,
    evidence_quality TEXT NOT NULL DEFAULT 'observed',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE (case_id, control_type, target)
);

CREATE INDEX idx_controls_case_state ON controls(case_id, state);

CREATE TABLE approvals (
    id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    actor_id TEXT NOT NULL REFERENCES actors(id),
    role TEXT NOT NULL,
    decision TEXT NOT NULL CHECK (decision IN ('approved','rejected')),
    reason TEXT NOT NULL,
    plan_digest TEXT NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE (case_id, role, plan_digest)
);

CREATE TABLE actions (
    id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    control_id TEXT NOT NULL UNIQUE REFERENCES controls(id) ON DELETE CASCADE,
    idempotency_key TEXT NOT NULL UNIQUE,
    operation TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    status TEXT NOT NULL,
    attempt_count INTEGER NOT NULL DEFAULT 0,
    external_reference TEXT,
    outcome_kind TEXT,
    last_error TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE jobs (
    id TEXT PRIMARY KEY,
    action_id TEXT NOT NULL REFERENCES actions(id) ON DELETE CASCADE,
    case_id TEXT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    status TEXT NOT NULL,
    attempt_count INTEGER NOT NULL DEFAULT 0,
    max_attempts INTEGER NOT NULL,
    available_at TEXT NOT NULL,
    lease_until TEXT,
    last_error TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(action_id)
);

CREATE INDEX idx_jobs_claim ON jobs(status, available_at, lease_until);

CREATE TABLE exceptions (
    id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    control_id TEXT NOT NULL REFERENCES controls(id) ON DELETE CASCADE,
    action_id TEXT REFERENCES actions(id) ON DELETE SET NULL,
    category TEXT NOT NULL,
    retryable INTEGER NOT NULL CHECK (retryable IN (0,1)),
    status TEXT NOT NULL,
    owner_actor_id TEXT REFERENCES actors(id),
    due_at TEXT,
    summary TEXT NOT NULL,
    resolution_note TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE INDEX idx_exceptions_open ON exceptions(status, due_at);

CREATE TABLE observations (
    id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    control_id TEXT NOT NULL REFERENCES controls(id) ON DELETE CASCADE,
    provider TEXT NOT NULL,
    external_id TEXT,
    observed_json TEXT NOT NULL,
    satisfied INTEGER NOT NULL CHECK (satisfied IN (0,1)),
    quality TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE evidence_artifacts (
    id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    path TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    mime_type TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE audit_events (
    sequence_no INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id TEXT NOT NULL UNIQUE,
    case_id TEXT REFERENCES cases(id) ON DELETE CASCADE,
    actor_id TEXT,
    event_type TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    previous_hash TEXT NOT NULL,
    event_hash TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL
);

CREATE INDEX idx_audit_case_sequence ON audit_events(case_id, sequence_no);

CREATE TABLE mock_accounts (
    provider TEXT NOT NULL,
    subject_email TEXT NOT NULL,
    suspended INTEGER NOT NULL DEFAULT 0 CHECK (suspended IN (0,1)),
    signed_out INTEGER NOT NULL DEFAULT 0 CHECK (signed_out IN (0,1)),
    groups_json TEXT NOT NULL DEFAULT '[]',
    fail_once_operation TEXT,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (provider, subject_email)
);
