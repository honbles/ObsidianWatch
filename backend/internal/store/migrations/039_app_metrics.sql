-- Application Monitoring: runtime and pool metrics (APM spec item 3). One row per instance, series and minute with
-- last, min, max, sum and count, so a chart can show the level (last), the extremes (min, max) and the mean (sum/count).
-- Names come from an allowlist and attr holds only allowlisted enumerations (a state, a pool or space name).
CREATE TABLE IF NOT EXISTS app_metrics (
  minute     TIMESTAMPTZ      NOT NULL,
  service_id BIGINT           NOT NULL REFERENCES services(id) ON DELETE CASCADE,
  instance   TEXT             NOT NULL,
  name       TEXT             NOT NULL,
  attr       TEXT             NOT NULL DEFAULT '',
  unit       TEXT             NOT NULL DEFAULT '',
  identity   TEXT             NOT NULL DEFAULT 'asserted',
  last       DOUBLE PRECISION NOT NULL,
  min        DOUBLE PRECISION NOT NULL,
  max        DOUBLE PRECISION NOT NULL,
  sum        DOUBLE PRECISION NOT NULL,
  count      BIGINT           NOT NULL,
  PRIMARY KEY (service_id, instance, name, attr, minute)
);
CREATE INDEX IF NOT EXISTS idx_app_metrics_name ON app_metrics (service_id, name, minute DESC);
