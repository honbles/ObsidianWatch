-- Application Monitoring: sampled request parameters from routes an admin has reviewed (payload capture
-- design, step 2). Only parameters the admin left unmasked are stored, and only after the ingest code has
-- checked them against the saved policy again. Short retention (app_retention.go, default 7 days).
CREATE TABLE IF NOT EXISTS app_payloads (
  id          BIGSERIAL   PRIMARY KEY,
  service_id  BIGINT      NOT NULL REFERENCES services(id) ON DELETE CASCADE,
  agent_id    TEXT        NOT NULL DEFAULT '',
  time        TIMESTAMPTZ NOT NULL,
  route       TEXT        NOT NULL,
  method      TEXT        NOT NULL,
  status      INT         NOT NULL DEFAULT 0,
  trace_id    TEXT        NOT NULL DEFAULT '',
  params      JSONB       NOT NULL DEFAULT '{}',
  withheld    JSONB       NOT NULL DEFAULT '[]'
);
CREATE INDEX IF NOT EXISTS idx_app_payloads_svc ON app_payloads (service_id, time DESC);
