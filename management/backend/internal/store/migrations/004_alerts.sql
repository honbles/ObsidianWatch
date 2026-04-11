-- 004_alerts.sql
CREATE TABLE IF NOT EXISTS alerts (
    id           BIGSERIAL   PRIMARY KEY,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    title        TEXT        NOT NULL,
    description  TEXT,
    severity     SMALLINT    NOT NULL DEFAULT 3,
    status       TEXT        NOT NULL DEFAULT 'open',  -- open | acknowledged | closed
    agent_id     TEXT,
    host         TEXT,
    event_type   TEXT,
    event_id     TEXT,        -- reference to the triggering event
    acknowledged_by TEXT,
    acknowledged_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_alerts_status     ON alerts (status, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_severity   ON alerts (severity DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_agent_id   ON alerts (agent_id);
