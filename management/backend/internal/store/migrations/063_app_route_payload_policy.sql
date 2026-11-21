-- Application Monitoring: per-route payload review and masking policy (payload capture design, step 2).
-- Written only by the management API. A route with no row here has not been reviewed: the agent forwards
-- no parameter values for it and the ingest backend stores none. reviewed_names are the parameter names the
-- admin saw when saving; a name that is not in that list (a new field) stays withheld until reviewed.
-- No foreign key: the two backends migrate independently (same pattern as service_settings).
CREATE TABLE IF NOT EXISTS app_route_payload_policy (
  service_id      BIGINT      NOT NULL,
  route           TEXT        NOT NULL,
  method          TEXT        NOT NULL,
  reviewed_names  JSONB       NOT NULL DEFAULT '[]',
  masked          JSONB       NOT NULL DEFAULT '[]',
  reviewed_by     TEXT        NOT NULL DEFAULT '',
  reviewed_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (service_id, route, method)
);

-- Audit trail of every save: who changed which route's policy, and when.
CREATE TABLE IF NOT EXISTS app_route_payload_policy_log (
  id              BIGSERIAL   PRIMARY KEY,
  service_id      BIGINT      NOT NULL,
  route           TEXT        NOT NULL,
  method          TEXT        NOT NULL,
  reviewed_names  JSONB       NOT NULL,
  masked          JSONB       NOT NULL,
  changed_by      TEXT        NOT NULL DEFAULT '',
  changed_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_app_payload_policy_log ON app_route_payload_policy_log (service_id, changed_at DESC);
