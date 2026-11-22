-- Application Monitoring: where a route's time goes, and what the database is asked (APM spec items 1 and 2).
-- Names and numbers only. app_db_stats.text is a literal-free statement fingerprint and is empty unless the
-- service's db_statement_mode is "fingerprint". Per-minute rows; pruned with the other short-lived stats.

CREATE TABLE IF NOT EXISTS app_route_children (
  minute     TIMESTAMPTZ      NOT NULL,
  service_id BIGINT           NOT NULL REFERENCES services(id) ON DELETE CASCADE,
  route      TEXT             NOT NULL,
  method     TEXT             NOT NULL,
  kind       TEXT             NOT NULL,   -- db | http | queue | client
  target     TEXT             NOT NULL,   -- db.system, peer.service or server.address
  name       TEXT             NOT NULL,   -- span name template
  calls      BIGINT           NOT NULL DEFAULT 0,
  total_ms   DOUBLE PRECISION NOT NULL DEFAULT 0,
  PRIMARY KEY (service_id, route, method, minute, kind, target, name)
);
CREATE INDEX IF NOT EXISTS idx_app_route_children_min ON app_route_children (minute);

CREATE TABLE IF NOT EXISTS app_db_stats (
  minute      TIMESTAMPTZ      NOT NULL,
  service_id  BIGINT           NOT NULL REFERENCES services(id) ON DELETE CASCADE,
  system      TEXT             NOT NULL,
  operation   TEXT             NOT NULL,
  tbl         TEXT             NOT NULL,
  fingerprint TEXT             NOT NULL DEFAULT '',
  text        TEXT             NOT NULL DEFAULT '',
  calls       BIGINT           NOT NULL DEFAULT 0,
  errors      BIGINT           NOT NULL DEFAULT 0,
  total_ms    DOUBLE PRECISION NOT NULL DEFAULT 0,
  duration_buckets JSONB       NOT NULL DEFAULT '[]',
  PRIMARY KEY (service_id, minute, system, operation, tbl, fingerprint)
);
CREATE INDEX IF NOT EXISTS idx_app_db_stats_min ON app_db_stats (minute);

CREATE TABLE IF NOT EXISTS app_route_n1 (
  minute     TIMESTAMPTZ NOT NULL,
  service_id BIGINT      NOT NULL REFERENCES services(id) ON DELETE CASCADE,
  route      TEXT        NOT NULL,
  method     TEXT        NOT NULL,
  count      BIGINT      NOT NULL DEFAULT 0,
  PRIMARY KEY (service_id, route, method, minute)
);
CREATE INDEX IF NOT EXISTS idx_app_route_n1_min ON app_route_n1 (minute);
