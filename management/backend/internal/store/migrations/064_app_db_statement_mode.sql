-- Application Monitoring: whether the agent may forward a literal-free fingerprint of database statements.
-- off (default): only operation and table names leave the host. fingerprint: literals are stripped on the host first.
ALTER TABLE service_settings ADD COLUMN IF NOT EXISTS db_statement_mode TEXT NOT NULL DEFAULT 'off';
