-- Application Monitoring: non-HTTP work (APM spec item 7). One row per service, operation (a job or a message
-- consumer) and minute: runs, failures, a latency histogram and sketch, and the time of the last run in the minute.
CREATE TABLE IF NOT EXISTS app_operations (
  minute           TIMESTAMPTZ NOT NULL,
  service_id       BIGINT      NOT NULL REFERENCES services(id) ON DELETE CASCADE,
  kind             TEXT        NOT NULL,            -- job | consumer
  name             TEXT        NOT NULL,
  runs             BIGINT      NOT NULL DEFAULT 0,
  failures         BIGINT      NOT NULL DEFAULT 0,
  duration_buckets JSONB       NOT NULL DEFAULT '[]',
  sketch           JSONB,
  sketch_calls     BIGINT      NOT NULL DEFAULT 0,
  last_run         TIMESTAMPTZ NOT NULL,
  PRIMARY KEY (service_id, kind, name, minute)
);
CREATE INDEX IF NOT EXISTS idx_app_operations_recent ON app_operations (service_id, kind, name, minute DESC);
