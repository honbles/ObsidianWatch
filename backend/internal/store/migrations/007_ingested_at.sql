-- 007_ingested_at.sql
-- D-01/D-02/G-01/G-02 foundation: engines previously evaluated events using
-- a wall-clock window on `time` (the timestamp the AGENT recorded locally),
-- e.g. "WHERE time > now() - 2 minutes". An event whose agent was offline,
-- queued it, and flushed it minutes or hours later arrives with an old
-- `time` value — by the time it lands in the DB it has already fallen
-- outside every future window's lookback, so it is silently never
-- evaluated by any detection engine. `ingested_at` records when the row
-- actually landed in this table, which is monotonic with respect to when
-- engines can see it, so a cursor on ingested_at (see management's
-- engine_cursors table and pageEventCursor()) never has this gap: every
-- row gets picked up by the next poll exactly once, regardless of how late
-- its agent-reported `time` is.
ALTER TABLE events ADD COLUMN IF NOT EXISTS ingested_at TIMESTAMPTZ NOT NULL DEFAULT NOW();
-- Backfill existing rows to their original event time (the ADD COLUMN
-- default above only applies going forward / fills pre-existing rows with
-- "now", which would make every historical event look freshly ingested).
UPDATE events SET ingested_at = time;
CREATE INDEX IF NOT EXISTS idx_events_ingested_at ON events (ingested_at);
