PRAGMA foreign_keys = ON;

ALTER TABLE evidence_artifacts ADD COLUMN schema_version INTEGER NOT NULL DEFAULT 1 CHECK (schema_version IN (1,2));
ALTER TABLE evidence_artifacts ADD COLUMN manifest_path TEXT;
ALTER TABLE evidence_artifacts ADD COLUMN evidence_sha256 TEXT CHECK (evidence_sha256 IS NULL OR length(evidence_sha256) = 64);
ALTER TABLE evidence_artifacts ADD COLUMN signing_status TEXT NOT NULL DEFAULT 'legacy' CHECK (signing_status IN ('legacy','unsigned','signed','failed'));
ALTER TABLE evidence_artifacts ADD COLUMN signing_algorithm TEXT;
ALTER TABLE evidence_artifacts ADD COLUMN signing_key_id TEXT;
ALTER TABLE evidence_artifacts ADD COLUMN public_key_fingerprint TEXT CHECK (public_key_fingerprint IS NULL OR length(public_key_fingerprint) = 64);
ALTER TABLE evidence_artifacts ADD COLUMN completion_event_hash TEXT CHECK (completion_event_hash IS NULL OR length(completion_event_hash) = 64);

CREATE INDEX idx_evidence_artifacts_case_schema ON evidence_artifacts(case_id, schema_version);
CREATE INDEX idx_evidence_artifacts_signing_status ON evidence_artifacts(signing_status, created_at);
