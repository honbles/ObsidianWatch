-- 014_alerts_dedup.sql
-- Adds UNIQUE constraint on alerts.event_id so INSERT ON CONFLICT can be used
-- for atomic deduplication — prevents duplicate alerts from race conditions
-- between the AlertEngine and DetectionEngine evaluation cycles.
--
-- event_id stores the dedup key:
--   AlertEngine:     "rule:<id>:event:<uuid>"
--   DetectionEngine: "sig:<id>:host:<host>:h:<hour>"
--   IOC matches:     "ioc:<source>:<value>:host:<host>:h:<hour>"
--
-- Existing duplicates (if any) are removed first, keeping the oldest alert.

DELETE FROM alerts
WHERE id NOT IN (
    SELECT MIN(id)
    FROM alerts
    WHERE event_id IS NOT NULL AND event_id != ''
    GROUP BY event_id
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_alerts_event_id_unique
    ON alerts (event_id)
    WHERE event_id IS NOT NULL AND event_id != '';
