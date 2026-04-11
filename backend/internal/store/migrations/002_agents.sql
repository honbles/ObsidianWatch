-- 002_agents.sql
-- Tracks every agent that has ever connected, with last-seen metadata.

CREATE TABLE IF NOT EXISTS agents (
    id           TEXT        PRIMARY KEY,
    hostname     TEXT        NOT NULL,
    os           TEXT        NOT NULL DEFAULT 'windows',
    version      TEXT        NOT NULL,
    first_seen   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_ip      TEXT,
    event_count  BIGINT      NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_agents_last_seen ON agents (last_seen DESC);
CREATE INDEX IF NOT EXISTS idx_agents_hostname  ON agents (hostname);
