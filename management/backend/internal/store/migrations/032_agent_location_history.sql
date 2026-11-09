-- 032_agent_location_history.sql (F-17)
CREATE TABLE IF NOT EXISTS agent_location_history (
    id        BIGSERIAL PRIMARY KEY,
    agent_id  TEXT NOT NULL,
    ts        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    lat       DOUBLE PRECISION NOT NULL,
    lng       DOUBLE PRECISION NOT NULL,
    accuracy  DOUBLE PRECISION,
    source    TEXT,
    city      TEXT,
    country   TEXT
);
CREATE INDEX IF NOT EXISTS idx_agent_loc_hist_agent ON agent_location_history (agent_id, ts DESC);
