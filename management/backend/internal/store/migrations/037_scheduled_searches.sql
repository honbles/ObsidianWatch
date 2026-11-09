-- P-07: saved searches can run on a schedule and alert when matches reach a threshold.
ALTER TABLE saved_event_queries ADD COLUMN IF NOT EXISTS sched_enabled   BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE saved_event_queries ADD COLUMN IF NOT EXISTS sched_every_min INT     NOT NULL DEFAULT 15;
ALTER TABLE saved_event_queries ADD COLUMN IF NOT EXISTS sched_window_min INT    NOT NULL DEFAULT 15;
ALTER TABLE saved_event_queries ADD COLUMN IF NOT EXISTS sched_threshold INT     NOT NULL DEFAULT 1;
ALTER TABLE saved_event_queries ADD COLUMN IF NOT EXISTS sched_severity  INT     NOT NULL DEFAULT 3;
ALTER TABLE saved_event_queries ADD COLUMN IF NOT EXISTS sched_last_run  TIMESTAMPTZ;
ALTER TABLE saved_event_queries ADD COLUMN IF NOT EXISTS sched_last_count INT;
