-- 009_threat_intel_sources.sql
-- Threat intelligence source configuration and IOC storage.

-- Source configuration
CREATE TABLE IF NOT EXISTS threat_intel_sources (
    id          SERIAL PRIMARY KEY,
    name        TEXT NOT NULL UNIQUE,    -- 'threatfox' | 'otx' | 'sigma'
    enabled     BOOLEAN NOT NULL DEFAULT FALSE,
    api_key     TEXT,                    -- NULL for sources that don't need one
    last_sync   TIMESTAMPTZ,
    last_error  TEXT,
    ioc_count   INT NOT NULL DEFAULT 0,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Seed default sources (all disabled by default)
INSERT INTO threat_intel_sources (name, enabled) VALUES
    ('threatfox', FALSE),
    ('otx',       FALSE),
    ('sigma',     FALSE)
ON CONFLICT (name) DO NOTHING;

-- IOC indicators (IPs, domains, hashes from ThreatFox and OTX)
CREATE TABLE IF NOT EXISTS ioc_indicators (
    id          BIGSERIAL PRIMARY KEY,
    source      TEXT NOT NULL,           -- 'threatfox' | 'otx'
    ioc_type    TEXT NOT NULL,           -- 'ip' | 'domain' | 'hash' | 'url'
    value       TEXT NOT NULL,           -- the actual IOC value
    malware     TEXT,                    -- malware family name
    threat_type TEXT,                    -- e.g. 'botnet_cc', 'payload_delivery'
    confidence  INT NOT NULL DEFAULT 50, -- 0-100
    severity    INT NOT NULL DEFAULT 4,  -- 1-5
    tags        TEXT,                    -- comma-separated tags
    expires_at  TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_ioc_source_value ON ioc_indicators(source, ioc_type, value);
CREATE INDEX IF NOT EXISTS idx_ioc_type_value ON ioc_indicators(ioc_type, value);
CREATE INDEX IF NOT EXISTS idx_ioc_source ON ioc_indicators(source);

-- Sigma rules (parsed from GitHub SigmaHQ)
CREATE TABLE IF NOT EXISTS sigma_rules (
    id          TEXT PRIMARY KEY,        -- rule UUID from Sigma YAML
    title       TEXT NOT NULL,
    description TEXT,
    status      TEXT,                    -- stable | test | experimental
    level       TEXT,                    -- critical | high | medium | low | informational
    severity    INT NOT NULL DEFAULT 3,
    category    TEXT,
    mitre       TEXT,                    -- ATT&CK technique IDs comma-separated
    logsource   TEXT,                    -- product/category/service JSON
    detection   TEXT NOT NULL,           -- raw detection YAML block
    enabled     BOOLEAN NOT NULL DEFAULT TRUE,
    source      TEXT NOT NULL DEFAULT 'sigma',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_sigma_enabled ON sigma_rules(enabled);
CREATE INDEX IF NOT EXISTS idx_sigma_level ON sigma_rules(level);
