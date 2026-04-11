-- 018_code_scan.sql
-- Stores code scan results per connector

CREATE TABLE IF NOT EXISTS code_scan_results (
    id              BIGSERIAL PRIMARY KEY,
    connector_id    BIGINT REFERENCES devops_connectors(id) ON DELETE CASCADE,
    scanned_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    repo_count      INT NOT NULL DEFAULT 0,
    file_count      INT NOT NULL DEFAULT 0,
    finding_count   INT NOT NULL DEFAULT 0,
    critical_count  INT NOT NULL DEFAULT 0,
    high_count      INT NOT NULL DEFAULT 0,
    medium_count    INT NOT NULL DEFAULT 0,
    findings        JSONB NOT NULL DEFAULT '[]',
    ai_summary      TEXT,
    ai_analysed_at  TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_code_scan_connector
    ON code_scan_results (connector_id, scanned_at DESC);

CREATE TABLE IF NOT EXISTS sast_results (
    id              BIGSERIAL PRIMARY KEY,
    connector_id    BIGINT REFERENCES devops_connectors(id) ON DELETE CASCADE,
    scanned_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    repo_count      INT NOT NULL DEFAULT 0,
    file_count      INT NOT NULL DEFAULT 0,
    finding_count   INT NOT NULL DEFAULT 0,
    critical_count  INT NOT NULL DEFAULT 0,
    high_count      INT NOT NULL DEFAULT 0,
    medium_count    INT NOT NULL DEFAULT 0,
    findings        JSONB NOT NULL DEFAULT '[]',
    ai_summary      TEXT,
    ai_analysed_at  TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_sast_connector
    ON sast_results (connector_id, scanned_at DESC);
