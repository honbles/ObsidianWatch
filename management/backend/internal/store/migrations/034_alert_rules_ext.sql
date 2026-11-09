-- D-09: richer custom alert rules — regex matching, exclusions, thresholds.
ALTER TABLE alert_rules ADD COLUMN IF NOT EXISTS match_mode TEXT NOT NULL DEFAULT 'substring';
ALTER TABLE alert_rules ADD COLUMN IF NOT EXISTS exclude_host TEXT NOT NULL DEFAULT '';
ALTER TABLE alert_rules ADD COLUMN IF NOT EXISTS exclude_user TEXT NOT NULL DEFAULT '';
ALTER TABLE alert_rules ADD COLUMN IF NOT EXISTS exclude_process TEXT NOT NULL DEFAULT '';
ALTER TABLE alert_rules ADD COLUMN IF NOT EXISTS threshold_count INT NOT NULL DEFAULT 0;
ALTER TABLE alert_rules ADD COLUMN IF NOT EXISTS threshold_window_sec INT NOT NULL DEFAULT 0;
