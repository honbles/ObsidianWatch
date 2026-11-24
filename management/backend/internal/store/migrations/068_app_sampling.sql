-- Application Monitoring: per-service trace sampling policy (APM spec item 13). JSON with optional baseline_pct
-- (0-100; absent = the agent default), error_max_per_min (0 = keep all) and max_per_flush (0 = default). The agent
-- pulls it with the other service settings every five minutes.
ALTER TABLE service_settings ADD COLUMN IF NOT EXISTS sampling JSONB NOT NULL DEFAULT '{}';
