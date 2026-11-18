-- Application Monitoring: service model written by the ingest backend (POST /api/v1/app/batch).
-- Shapes follow Application Monitoring Spec v0.2 section 4 and 5. Service identity is
-- (name, environment). Host identity is stamped by the backend from the registered agent,
-- process and container identity by the agent; the instrumented application never supplies them.
CREATE TABLE IF NOT EXISTS services (
  id           BIGSERIAL   PRIMARY KEY,
  name         TEXT        NOT NULL,
  environment  TEXT        NOT NULL DEFAULT 'default',
  source       TEXT        NOT NULL DEFAULT 'discovered',          -- discovered | otel
  first_seen   TIMESTAMPTZ NOT NULL,
  last_seen    TIMESTAMPTZ NOT NULL,
  attrs        JSONB       NOT NULL DEFAULT '{}',                  -- language, route_overflow, trace_drops, ...
  UNIQUE (name, environment)
);
CREATE INDEX IF NOT EXISTS idx_app_services_last_seen ON services (last_seen DESC);

-- One running copy of a service. pid + proc_start identify a process (pid alone is reused);
-- they default to 0 / epoch for instances whose process is unknown. identity is
-- 'verified' (bound to the sending process) or 'asserted' (cannot raise high-severity alerts alone).
CREATE TABLE IF NOT EXISTS service_instances (
  id            BIGSERIAL   PRIMARY KEY,
  service_id    BIGINT      NOT NULL REFERENCES services(id) ON DELETE CASCADE,
  agent_id      TEXT        NOT NULL,
  host          TEXT        NOT NULL,
  container_id  TEXT        NOT NULL DEFAULT '',
  pid           INT         NOT NULL DEFAULT 0,
  proc_start    TIMESTAMPTZ NOT NULL DEFAULT 'epoch',
  instance_ref  TEXT        NOT NULL DEFAULT '',                   -- service.instance.id as reported
  version       TEXT        NOT NULL DEFAULT '',
  listen        JSONB       NOT NULL DEFAULT '[]',
  instrumented  BOOLEAN     NOT NULL DEFAULT FALSE,
  identity      TEXT        NOT NULL DEFAULT 'verified',
  attrs         JSONB       NOT NULL DEFAULT '{}',                 -- language, sdk, exe
  first_seen    TIMESTAMPTZ NOT NULL,
  last_seen     TIMESTAMPTZ NOT NULL,
  stopped_at    TIMESTAMPTZ
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_app_instances_proc ON service_instances (service_id, agent_id, container_id, pid, proc_start);
CREATE INDEX IF NOT EXISTS idx_app_instances_agent ON service_instances (agent_id);
CREATE INDEX IF NOT EXISTS idx_app_instances_seen  ON service_instances (last_seen DESC);

CREATE TABLE IF NOT EXISTS service_edges (
  src_service  BIGINT      NOT NULL REFERENCES services(id) ON DELETE CASCADE,
  dst_kind     TEXT        NOT NULL,                               -- service | database | queue | external
  dst_name     TEXT        NOT NULL,                               -- host / peer service / db system; never a URL path or query
  source       TEXT        NOT NULL,                               -- ebpf | otel
  calls        BIGINT      NOT NULL DEFAULT 0,
  errors       BIGINT      NOT NULL DEFAULT 0,
  first_seen   TIMESTAMPTZ NOT NULL,
  last_seen    TIMESTAMPTZ NOT NULL,
  PRIMARY KEY (src_service, dst_kind, dst_name, source)
);
CREATE INDEX IF NOT EXISTS idx_app_edges_seen ON service_edges (last_seen DESC);

-- Route templates only, never concrete paths. Survives the 90-day statistics retention.
CREATE TABLE IF NOT EXISTS service_routes (
  service_id   BIGINT      NOT NULL REFERENCES services(id) ON DELETE CASCADE,
  route        TEXT        NOT NULL,
  method       TEXT        NOT NULL,
  first_seen   TIMESTAMPTZ NOT NULL,
  last_seen    TIMESTAMPTZ NOT NULL,
  PRIMARY KEY (service_id, route, method)
);

-- Source for deploy markers.
CREATE TABLE IF NOT EXISTS service_versions (
  service_id   BIGINT      NOT NULL REFERENCES services(id) ON DELETE CASCADE,
  version      TEXT        NOT NULL,
  first_seen   TIMESTAMPTZ NOT NULL,
  last_seen    TIMESTAMPTZ NOT NULL,
  instances    INT         NOT NULL DEFAULT 0,
  PRIMARY KEY (service_id, version)
);

-- Learned baselines for first-seen rules (destination | listener | export_user | admin_user).
CREATE TABLE IF NOT EXISTS app_baselines (
  service_id   BIGINT      NOT NULL REFERENCES services(id) ON DELETE CASCADE,
  kind         TEXT        NOT NULL,
  key          TEXT        NOT NULL,
  stats        JSONB       NOT NULL DEFAULT '{}',
  samples      BIGINT      NOT NULL DEFAULT 0,
  first_seen   TIMESTAMPTZ NOT NULL,
  updated      TIMESTAMPTZ NOT NULL,
  PRIMARY KEY (service_id, kind, key)
);

-- Per-minute RED statistics. duration_buckets holds 12 counts for upper bounds (ms)
-- 5,10,25,50,100,250,500,1000,2500,5000,10000,+Inf. 90-day retention (app_retention.go).
CREATE TABLE IF NOT EXISTS app_route_stats (
  minute           TIMESTAMPTZ NOT NULL,
  service_id       BIGINT      NOT NULL,
  route            TEXT        NOT NULL,
  method           TEXT        NOT NULL,
  calls            BIGINT      NOT NULL DEFAULT 0,
  errors           BIGINT      NOT NULL DEFAULT 0,
  status_2xx       BIGINT      NOT NULL DEFAULT 0,
  status_401_403   BIGINT      NOT NULL DEFAULT 0,
  status_429       BIGINT      NOT NULL DEFAULT 0,
  status_5xx       BIGINT      NOT NULL DEFAULT 0,
  duration_buckets JSONB       NOT NULL DEFAULT '[]',
  PRIMARY KEY (minute, service_id, route, method)
);
CREATE INDEX IF NOT EXISTS idx_app_route_stats_service ON app_route_stats (service_id, minute DESC);

-- Sampled traces, 7-day retention. spans <= 64 KB.
CREATE TABLE IF NOT EXISTS app_traces (
  trace_id     TEXT        PRIMARY KEY,
  service_id   BIGINT      NOT NULL,
  agent_id     TEXT        NOT NULL,
  started      TIMESTAMPTZ NOT NULL,
  duration_ms  INT         NOT NULL DEFAULT 0,
  root_route   TEXT        NOT NULL DEFAULT '',
  status       TEXT        NOT NULL DEFAULT '',
  keep_reason  TEXT        NOT NULL DEFAULT 'baseline',            -- error | slow | security | baseline
  span_count   INT         NOT NULL DEFAULT 0,
  spans        JSONB       NOT NULL DEFAULT '[]'
);
CREATE INDEX IF NOT EXISTS idx_app_traces_started ON app_traces (started DESC);
CREATE INDEX IF NOT EXISTS idx_app_traces_service ON app_traces (service_id, started DESC);
