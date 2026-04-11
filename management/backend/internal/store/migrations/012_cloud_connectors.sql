-- 012_cloud_connectors.sql
-- Cloud provider integrations — AWS, Azure, GCP

CREATE TABLE IF NOT EXISTS cloud_connectors (
    id           BIGSERIAL    PRIMARY KEY,
    provider     TEXT         NOT NULL,                        -- 'aws' | 'azure' | 'gcp'
    account_id   TEXT         NOT NULL DEFAULT '',             -- AWS account ID / Azure subscription / GCP project
    account_label TEXT        NOT NULL DEFAULT '',             -- human-readable label
    credentials  JSONB        NOT NULL DEFAULT '{}',           -- encrypted-at-rest in prod; plaintext for now
    status       TEXT         NOT NULL DEFAULT 'pending',      -- pending | connected | error
    last_sync    TIMESTAMPTZ,
    last_error   TEXT,
    event_count  BIGINT       NOT NULL DEFAULT 0,
    sync_cursor  TEXT,                                         -- last processed position (S3 key, timestamp, etc.)
    created_at   TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at   TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_cloud_connectors_provider ON cloud_connectors(provider);
