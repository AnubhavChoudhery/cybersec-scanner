-- Minimal schema used by Graph phase
-- Findings and endpoints needed for graph construction

CREATE TABLE IF NOT EXISTS findings (
    id TEXT PRIMARY KEY,
    type TEXT NOT NULL,
    severity TEXT NOT NULL,
    source TEXT NOT NULL,
    summary TEXT NOT NULL,
    snippet TEXT,
    metadata JSON,
    scan_id TEXT,
    timestamp INTEGER
);

CREATE TABLE IF NOT EXISTS endpoints (
    id TEXT PRIMARY KEY,
    url TEXT NOT NULL,
    method TEXT,
    first_seen INTEGER,
    last_seen INTEGER
);

CREATE TABLE IF NOT EXISTS cwe_entries (
    cwe_id TEXT PRIMARY KEY,
    name TEXT,
    description TEXT,
    severity TEXT,
    metadata JSON
);
