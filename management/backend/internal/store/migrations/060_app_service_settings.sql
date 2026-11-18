-- Application Monitoring: analyst-managed settings, written only by the management API.
-- service_id refers to services(id), which the ingest migration creates. No foreign key,
-- because the two backends migrate independently and in either order.
-- criticality lives here (not on services) so severity weighting reads one table.
CREATE TABLE IF NOT EXISTS service_settings (
  service_id         BIGINT      PRIMARY KEY,
  exposure           TEXT        NOT NULL DEFAULT 'unknown',   -- internet | internal | unknown
  criticality        TEXT        NOT NULL DEFAULT 'normal',    -- low | normal | high | critical
  data_sensitivity   TEXT        NOT NULL DEFAULT 'normal',    -- normal | sensitive | regulated
  owner              TEXT        NOT NULL DEFAULT '',
  notify_route       TEXT        NOT NULL DEFAULT '',
  trusted_proxies    JSONB       NOT NULL DEFAULT '[]',        -- CIDRs whose forwarded client address is trusted
  login_routes       JSONB       NOT NULL DEFAULT '[]',
  export_routes      JSONB       NOT NULL DEFAULT '[]',
  public_routes      JSONB       NOT NULL DEFAULT '[]',
  latency_target_ms  INT,
  error_budget_pct   NUMERIC,
  maintenance        JSONB       NOT NULL DEFAULT '[]',
  store_client_ip    TEXT        NOT NULL DEFAULT 'full',      -- full | truncated | off
  cleartext_users    BOOLEAN     NOT NULL DEFAULT FALSE,       -- opt-in cleartext user identifiers (spec section 9)
  learning_started   TIMESTAMPTZ,
  updated_by         TEXT        NOT NULL DEFAULT '',
  updated_at         TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Manual merges: treat service alias_id as service canonical_id.
CREATE TABLE IF NOT EXISTS app_service_merges (
  alias_id      BIGINT      PRIMARY KEY,
  canonical_id  BIGINT      NOT NULL,
  created_by    TEXT        NOT NULL DEFAULT '',
  created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_app_merges_canonical ON app_service_merges (canonical_id);
