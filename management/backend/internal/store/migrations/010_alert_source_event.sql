-- 010_alert_source_event.sql
-- Adds source_event_id to alerts so we can link back to the exact triggering event.
-- event_id continues to hold the dedup key; source_event_id holds the events table UUID.

ALTER TABLE alerts ADD COLUMN IF NOT EXISTS source_event_id TEXT;
CREATE INDEX IF NOT EXISTS idx_alerts_source_event ON alerts(source_event_id) WHERE source_event_id IS NOT NULL;
