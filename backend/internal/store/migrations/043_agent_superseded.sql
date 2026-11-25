-- 043_agent_superseded.sql
-- When a host enrolls again (reinstall), older agent records with the same
-- host name are marked as replaced and hidden from the fleet. A replaced
-- record that reports again is un-hidden automatically (UpsertAgent), so a
-- live agent can never be hidden this way. Same file as management 072.
ALTER TABLE agents ADD COLUMN IF NOT EXISTS superseded_by TEXT;
ALTER TABLE agents ADD COLUMN IF NOT EXISTS superseded_at TIMESTAMPTZ;
CREATE INDEX IF NOT EXISTS idx_agents_hostname_lower ON agents (LOWER(hostname));
