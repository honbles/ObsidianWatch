-- 071_hunt_offline_states.sql (spec E1)
-- Per-host hunt state is now: running (pending), answered (ok/failed/timeout),
-- queued, expired or skipped. sent_at is when the question actually went to
-- the host, so a late answer shows its real run time.
ALTER TABLE fleet_hunt_results ADD COLUMN IF NOT EXISTS sent_at TIMESTAMPTZ;
ALTER TABLE fleet_hunts ADD COLUMN IF NOT EXISTS wait_mode TEXT NOT NULL DEFAULT '';
