-- 001_events.sql
-- Creates the main events hypertable (TimescaleDB time-series table)

CREATE EXTENSION IF NOT EXISTS timescaledb;

CREATE TABLE IF NOT EXISTS events (
    id           TEXT        NOT NULL,
    time         TIMESTAMPTZ NOT NULL,
    agent_id     TEXT        NOT NULL,
    host         TEXT        NOT NULL,
    os           TEXT        NOT NULL DEFAULT 'windows',
    event_type   TEXT        NOT NULL,
    severity     SMALLINT    NOT NULL DEFAULT 1,
    source       TEXT        NOT NULL,
    raw          JSONB,

    -- Process fields
    pid          INTEGER,
    ppid         INTEGER,
    process_name TEXT,
    command_line TEXT,
    image_path   TEXT,

    -- Identity fields
    user_name    TEXT,
    domain       TEXT,
    logon_id     TEXT,

    -- Network fields
    src_ip       INET,
    src_port     INTEGER,
    dst_ip       INET,
    dst_port     INTEGER,
    proto        TEXT,

    -- Registry fields
    reg_key      TEXT,
    reg_value    TEXT,
    reg_data     TEXT,

    -- File fields
    file_path    TEXT,
    file_hash    TEXT,

    -- Windows Event Log fields
    event_id     INTEGER,
    channel      TEXT,
    record_id    BIGINT,

    PRIMARY KEY (id, time)
);

-- Convert to TimescaleDB hypertable partitioned by time
SELECT create_hypertable(
    'events',
    'time',
    chunk_time_interval => INTERVAL '1 day',
    if_not_exists       => TRUE
);

-- Indexes for common query patterns
CREATE INDEX IF NOT EXISTS idx_events_agent_id   ON events (agent_id, time DESC);
CREATE INDEX IF NOT EXISTS idx_events_host       ON events (host, time DESC);
CREATE INDEX IF NOT EXISTS idx_events_event_type ON events (event_type, time DESC);
CREATE INDEX IF NOT EXISTS idx_events_severity   ON events (severity, time DESC);
CREATE INDEX IF NOT EXISTS idx_events_src_ip     ON events (src_ip, time DESC);
CREATE INDEX IF NOT EXISTS idx_events_dst_ip     ON events (dst_ip, time DESC);
CREATE INDEX IF NOT EXISTS idx_events_user_name  ON events (user_name, time DESC);
CREATE INDEX IF NOT EXISTS idx_events_process    ON events (process_name, time DESC);

-- Retention policy: drop chunks older than 90 days (adjust as needed)
SELECT add_retention_policy('events', INTERVAL '90 days', if_not_exists => TRUE);

-- NOTE: Compression policy (add_compression_policy) requires the TimescaleDB
-- Community/Enterprise license and is not available in the free Apache edition.
-- If you upgrade to a licensed version, you can enable it with:
--   SELECT add_compression_policy('events', INTERVAL '7 days', if_not_exists => TRUE);
