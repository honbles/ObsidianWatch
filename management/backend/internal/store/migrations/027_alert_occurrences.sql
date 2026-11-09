-- 027_alert_occurrences.sql
-- D-06: dedup keys were host+hour+rule only, so two DIFFERENT attacker
-- activities on the same host matching the same rule within the same hour
-- collapsed into a single alert — the second (possibly more severe) match
-- never surfaced at all, it just silently bumped into the ON CONFLICT DO
-- NOTHING from the first. occurrence_count/last_seen let a genuine repeat
-- of the SAME activity update the existing alert instead of vanishing,
-- while alertEntityKey() (see alert_entity.go) is folded into the dedup
-- key itself so distinct activity (different process/command line) gets
-- its own alert rather than being swallowed by an earlier match.
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS occurrence_count INT NOT NULL DEFAULT 1;
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS last_seen TIMESTAMPTZ NOT NULL DEFAULT NOW();
