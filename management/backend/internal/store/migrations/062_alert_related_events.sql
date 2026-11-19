-- Repeats of an alert inside the dedupe window are folded into the existing alert (occurrence_count,
-- last_seen). The triggering events are kept here so nothing is lost: up to 50 per alert.
CREATE TABLE IF NOT EXISTS alert_related_events (
    alert_id        BIGINT      NOT NULL REFERENCES alerts(id) ON DELETE CASCADE,
    source_event_id TEXT        NOT NULL,
    seen_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (alert_id, source_event_id)
);
-- the window lookup in CreateAlertDeduped
CREATE INDEX IF NOT EXISTS idx_alerts_window ON alerts (title, host, last_seen DESC) WHERE status IN ('open','acknowledged');
