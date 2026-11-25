-- Prevention (agent-side IOC matching).
-- first_seen is the feed's own first-seen date (ThreatFox first_seen; the
-- first sync for feeds without one), so "seen in the last 90 days" is not
-- confused with "imported in the last 90 days".
ALTER TABLE ioc_indicators ADD COLUMN IF NOT EXISTS first_seen TIMESTAMPTZ;
UPDATE ioc_indicators SET first_seen = created_at WHERE first_seen IS NULL;
CREATE INDEX IF NOT EXISTS idx_ioc_prevention ON ioc_indicators (ioc_type, source, confidence) WHERE ioc_type IN ('ip','hash','domain');
