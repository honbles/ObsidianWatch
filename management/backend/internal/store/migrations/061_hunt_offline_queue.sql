-- Live fleet hunts can wait for hosts that are offline: the question is stored per host and sent when the
-- agent's tunnel reconnects, until expires_at. Read-only queries only (see liveHuntKinds).
ALTER TABLE fleet_hunts ADD COLUMN IF NOT EXISTS expires_at TIMESTAMPTZ;
ALTER TABLE fleet_hunt_results ADD COLUMN IF NOT EXISTS was_queued BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE fleet_hunt_results ADD COLUMN IF NOT EXISTS queued_at TIMESTAMPTZ;
-- status now also: queued | expired
CREATE INDEX IF NOT EXISTS idx_fleet_hunt_results_queued ON fleet_hunt_results (agent_id) WHERE status = 'queued';
