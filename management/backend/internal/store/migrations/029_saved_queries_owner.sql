-- 029_saved_queries_owner.sql (F-09)
ALTER TABLE saved_event_queries ADD COLUMN IF NOT EXISTS owner  TEXT NOT NULL DEFAULT '';
ALTER TABLE saved_event_queries ADD COLUMN IF NOT EXISTS shared BOOLEAN NOT NULL DEFAULT false;
-- Pre-existing rows had no owner; keep them visible to everyone.
UPDATE saved_event_queries SET shared = true WHERE owner = '';
CREATE INDEX IF NOT EXISTS idx_saved_event_queries_owner ON saved_event_queries(owner);
