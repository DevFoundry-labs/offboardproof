PRAGMA foreign_keys = ON;

CREATE TABLE webhook_deliveries (
    id TEXT PRIMARY KEY,
    source_id TEXT NOT NULL,
    delivery_id TEXT NOT NULL,
    event_id TEXT NOT NULL,
    payload_sha256 TEXT NOT NULL CHECK (length(payload_sha256) = 64),
    case_id TEXT REFERENCES cases(id) ON DELETE SET NULL,
    status TEXT NOT NULL CHECK (status IN ('accepted','rejected','conflict')),
    received_at TEXT NOT NULL,
    completed_at TEXT,
    UNIQUE (source_id, delivery_id),
    UNIQUE (source_id, event_id)
);

CREATE INDEX idx_webhook_deliveries_case ON webhook_deliveries(case_id);
CREATE INDEX idx_webhook_deliveries_status_received ON webhook_deliveries(status, received_at);
