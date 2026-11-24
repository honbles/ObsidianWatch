-- OTX pulse metadata on IOCs (false-positive reduction, workstream A3).
-- confidence is now derived from the pulse instead of a fixed 70; pulse_size lets
-- operators see which sandbox/dump pulses are feeding the table.
ALTER TABLE ioc_indicators ADD COLUMN IF NOT EXISTS pulse_id   TEXT NOT NULL DEFAULT '';
ALTER TABLE ioc_indicators ADD COLUMN IF NOT EXISTS pulse_name TEXT NOT NULL DEFAULT '';
ALTER TABLE ioc_indicators ADD COLUMN IF NOT EXISTS pulse_size INT  NOT NULL DEFAULT 0;
