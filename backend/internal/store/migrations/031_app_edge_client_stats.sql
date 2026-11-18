-- Application Monitoring: per-range dependency counts and per-client failure counters.

-- Hourly deltas per dependency, so the service map can show calls in a time range
-- (service_edges only holds cumulative counters). 90-day retention (app_retention.go).
CREATE TABLE IF NOT EXISTS app_edge_stats (
  hour         TIMESTAMPTZ NOT NULL,
  src_service  BIGINT      NOT NULL,
  dst_kind     TEXT        NOT NULL,
  dst_name     TEXT        NOT NULL,
  source       TEXT        NOT NULL,
  calls        BIGINT      NOT NULL DEFAULT 0,
  errors       BIGINT      NOT NULL DEFAULT 0,
  PRIMARY KEY (hour, src_service, dst_kind, dst_name, source)
);
CREATE INDEX IF NOT EXISTS idx_app_edge_stats_src ON app_edge_stats (src_service, hour DESC);

-- Per-minute FAILURE counters per client address and route, the input of the
-- source-based rules (A01 login failure burst, A09 injection attempts, A13 rate-limit abuse).
-- Only failures are recorded (401/403, 429, other 4xx, 5xx, or a span exception); the agent caps the
-- distinct keys per service per minute. client_ip is the application-reported client address and
-- peer_ip the direct network peer; both follow the service's client-address storage mode.
-- 7-day retention (app_retention.go).
CREATE TABLE IF NOT EXISTS app_client_stats (
  minute           TIMESTAMPTZ NOT NULL,
  service_id       BIGINT      NOT NULL,
  route            TEXT        NOT NULL,
  method           TEXT        NOT NULL,
  client_ip        TEXT        NOT NULL DEFAULT '',
  peer_ip          TEXT        NOT NULL DEFAULT '',
  exc_type         TEXT        NOT NULL DEFAULT '',
  failures         BIGINT      NOT NULL DEFAULT 0,
  status_401_403   BIGINT      NOT NULL DEFAULT 0,
  status_429       BIGINT      NOT NULL DEFAULT 0,
  status_4xx_other BIGINT      NOT NULL DEFAULT 0,
  status_5xx       BIGINT      NOT NULL DEFAULT 0,
  PRIMARY KEY (minute, service_id, route, method, client_ip, peer_ip, exc_type)
);
CREATE INDEX IF NOT EXISTS idx_app_client_stats_svc ON app_client_stats (service_id, minute DESC);
CREATE INDEX IF NOT EXISTS idx_app_client_stats_client ON app_client_stats (client_ip, minute DESC);
