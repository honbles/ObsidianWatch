-- Time window for the recent_files live hunt kind (hours; 0 = agent default).
ALTER TABLE fleet_hunts ADD COLUMN IF NOT EXISTS hours INTEGER NOT NULL DEFAULT 0;
