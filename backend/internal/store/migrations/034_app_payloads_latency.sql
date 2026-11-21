-- Application Monitoring: request latency beside each sampled payload, for the per-route review page.
ALTER TABLE app_payloads ADD COLUMN IF NOT EXISTS duration_ms DOUBLE PRECISION NOT NULL DEFAULT 0;
CREATE INDEX IF NOT EXISTS idx_app_payloads_route ON app_payloads (service_id, method, route, time DESC);
