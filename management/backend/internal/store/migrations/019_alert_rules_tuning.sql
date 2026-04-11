-- 019_alert_rules_tuning.sql
-- Disable overly broad default alert rules that cause noise
-- These fire on every high-severity event — the detection engine (MITRE sigs)
-- already handles this more precisely. Users can re-enable via Settings.

-- Disable "High Severity Event" — too broad, fires on every severity>=4 event
-- The detection engine covers this with specific MITRE-mapped signatures
UPDATE alert_rules SET enabled = FALSE 
WHERE name = 'High Severity Event' AND created_by = 'system';

-- Disable "Process Execution Alert" — fires on every high-severity process
-- Way too noisy on active hosts. Detection engine has specific process rules.
UPDATE alert_rules SET enabled = FALSE 
WHERE name = 'Process Execution Alert' AND created_by = 'system';

-- Disable "Suspicious Network" — fires on every high-severity network event
-- Detection engine has specific network signatures (port scan, C2, etc.)
UPDATE alert_rules SET enabled = FALSE 
WHERE name = 'Suspicious Network' AND created_by = 'system';

-- Keep enabled (these are specific and useful):
-- "Critical Event" (severity=5 only — rare)
-- "Privileged Logon" (logon events specifically)

-- Add missing columns if not already present (from previous sessions)
ALTER TABLE alert_rules ADD COLUMN IF NOT EXISTS os_match          TEXT NOT NULL DEFAULT '';
ALTER TABLE alert_rules ADD COLUMN IF NOT EXISTS command_line_match TEXT NOT NULL DEFAULT '';
ALTER TABLE alert_rules ADD COLUMN IF NOT EXISTS src_ip_match      TEXT NOT NULL DEFAULT '';
ALTER TABLE alert_rules ADD COLUMN IF NOT EXISTS dst_ip_match      TEXT NOT NULL DEFAULT '';
ALTER TABLE alert_rules ADD COLUMN IF NOT EXISTS dns_match         TEXT NOT NULL DEFAULT '';
ALTER TABLE alert_rules ADD COLUMN IF NOT EXISTS source_match      TEXT NOT NULL DEFAULT '';
ALTER TABLE alert_rules ADD COLUMN IF NOT EXISTS updated_at        TIMESTAMPTZ NOT NULL DEFAULT NOW();
