-- 030_azure_suppress_rules.sql (AZ-06)
CREATE TABLE IF NOT EXISTS azure_suppress_rules (
    id              BIGSERIAL PRIMARY KEY,
    subscription_id TEXT NOT NULL DEFAULT '',
    finding_title   TEXT NOT NULL DEFAULT '',
    resource        TEXT NOT NULL DEFAULT '',
    category        TEXT NOT NULL DEFAULT '',
    severity        TEXT NOT NULL DEFAULT '',
    reason          TEXT NOT NULL,
    created_by      TEXT NOT NULL DEFAULT '',
    expires_at      TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
