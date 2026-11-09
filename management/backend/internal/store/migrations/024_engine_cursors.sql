-- 024_engine_cursors.sql
-- D-01/D-02: persisted per-engine cursor on events.ingested_at, replacing
-- wall-clock "WHERE time > now() - N" polling windows. See
-- backend/internal/store/migrations/007_ingested_at.sql for why ingested_at
-- (not the agent-reported `time`) is the safe thing to page on.
CREATE TABLE IF NOT EXISTS engine_cursors (
    engine_name TEXT PRIMARY KEY,
    cursor_at   TIMESTAMPTZ NOT NULL,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
