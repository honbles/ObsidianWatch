-- 021_saved_event_queries.sql
CREATE TABLE IF NOT EXISTS saved_event_queries (
    id         BIGSERIAL PRIMARY KEY,
    name       TEXT NOT NULL,
    query      TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
