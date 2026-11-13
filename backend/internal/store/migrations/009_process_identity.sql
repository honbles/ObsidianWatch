-- 009_process_identity.sql (Alert Graph phase 1)
-- Process instance identity lifted out of raw at ingest. NULL for events that
-- carry no GUID (old rows, Windows without Sysmon). Existing logon_id and
-- file_hash indexes live in 003 / 008; only the agent-scoped variants are new.
ALTER TABLE events ADD COLUMN IF NOT EXISTS process_guid        TEXT;
ALTER TABLE events ADD COLUMN IF NOT EXISTS parent_process_guid TEXT;

CREATE INDEX IF NOT EXISTS idx_events_proc_guid
    ON events (agent_id, process_guid, time DESC) WHERE process_guid IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_events_parent_guid
    ON events (agent_id, parent_process_guid, time DESC) WHERE parent_process_guid IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_events_agent_logon
    ON events (agent_id, logon_id, time DESC) WHERE logon_id IS NOT NULL;
