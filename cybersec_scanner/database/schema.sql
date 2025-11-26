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

CREATE TABLE IF NOT EXISTS finding_cwe_map (
    finding_id TEXT,
    cwe_id TEXT,
    confidence REAL,
    FOREIGN KEY (finding_id) REFERENCES findings(id),
    FOREIGN KEY (cwe_id) REFERENCES cwe_entries(cwe_id)
);

CREATE TABLE IF NOT EXISTS owasp_categories (
    owasp_id TEXT PRIMARY KEY,
    name TEXT,
    description TEXT,
    year INTEGER,
    rank INTEGER
);

CREATE TABLE IF NOT EXISTS cwe_owasp_map (
    cwe_id TEXT,
    owasp_id TEXT,
    FOREIGN KEY (cwe_id) REFERENCES cwe_entries(cwe_id),
    FOREIGN KEY (owasp_id) REFERENCES owasp_categories(owasp_id)
);

CREATE TABLE IF NOT EXISTS mitigations (
    id TEXT PRIMARY KEY,
    name TEXT,
    description TEXT,
    code_example TEXT,
    applicable_to TEXT
);

-- Performance indexes for common queries
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_findings_timestamp ON findings(timestamp);
CREATE INDEX IF NOT EXISTS idx_findings_source ON findings(source);
CREATE INDEX IF NOT EXISTS idx_findings_type ON findings(type);

CREATE INDEX IF NOT EXISTS idx_finding_cwe_map_finding ON finding_cwe_map(finding_id);
CREATE INDEX IF NOT EXISTS idx_finding_cwe_map_cwe ON finding_cwe_map(cwe_id);
CREATE INDEX IF NOT EXISTS idx_finding_cwe_map_confidence ON finding_cwe_map(confidence);

CREATE INDEX IF NOT EXISTS idx_endpoints_url ON endpoints(url);
CREATE INDEX IF NOT EXISTS idx_endpoints_method ON endpoints(method);

CREATE INDEX IF NOT EXISTS idx_cwe_owasp_map_cwe ON cwe_owasp_map(cwe_id);
CREATE INDEX IF NOT EXISTS idx_cwe_owasp_map_owasp ON cwe_owasp_map(owasp_id);
