-- Application Monitoring: per-service SLO settings (APM spec item 15). JSON with optional window_days (7 or 28),
-- availability_target_pct and latency_target_pct. Absent values default from the service's error budget and latency
-- target: availability = 100 - error budget (99.9 when none is set), latency 95 percent under the target.
ALTER TABLE service_settings ADD COLUMN IF NOT EXISTS slo JSONB NOT NULL DEFAULT '{}';
