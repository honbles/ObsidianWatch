-- Closing an endpoint alert as a false positive creates a suppression from the alert's own evidence.
-- Alerts record which rule raised them and the evidence (JSON, see api/alert_fp.go), how they were closed
-- (disposition) and the suppression a false-positive close created.
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS rule_id TEXT;
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS evidence JSONB;
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS disposition TEXT;
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS suppression_id BIGINT;
CREATE INDEX IF NOT EXISTS idx_alerts_rule_active ON alerts (rule_id) WHERE status IN ('open', 'acknowledged');

-- Suppressions can match a file hash, an IP, a domain (DNS query or subdomain) or the matched threat-intel
-- indicator, and remember the alert they were created from.
ALTER TABLE endpoint_suppressions ADD COLUMN IF NOT EXISTS file_hash TEXT NOT NULL DEFAULT '';
ALTER TABLE endpoint_suppressions ADD COLUMN IF NOT EXISTS ip TEXT NOT NULL DEFAULT '';
ALTER TABLE endpoint_suppressions ADD COLUMN IF NOT EXISTS dns_domain TEXT NOT NULL DEFAULT '';
ALTER TABLE endpoint_suppressions ADD COLUMN IF NOT EXISTS indicator TEXT NOT NULL DEFAULT '';
ALTER TABLE endpoint_suppressions ADD COLUMN IF NOT EXISTS source_alert_id BIGINT;
