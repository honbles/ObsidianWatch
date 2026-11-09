-- Shared foundation: per-rule enable / observe mode / tunables / allowlist,
-- optionally scoped (scope_kind '' = global; 'service', 'site', 'probe', 'host').
CREATE TABLE IF NOT EXISTS rule_settings (
  rule_id    TEXT        NOT NULL,
  scope_kind TEXT        NOT NULL DEFAULT '',
  scope_id   TEXT        NOT NULL DEFAULT '',
  enabled    BOOLEAN     NOT NULL DEFAULT TRUE,
  observe    BOOLEAN     NOT NULL DEFAULT TRUE,   -- new rules start in observe mode
  params     JSONB       NOT NULL DEFAULT '{}',   -- tunable thresholds and windows
  allowlist  JSONB       NOT NULL DEFAULT '[]',
  updated    TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_by TEXT        NOT NULL DEFAULT '',
  PRIMARY KEY (rule_id, scope_kind, scope_id)
);
