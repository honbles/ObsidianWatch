-- 005_enterprise.sql — enterprise features

-- Force password change on first login
ALTER TABLE users ADD COLUMN IF NOT EXISTS password_changed BOOLEAN NOT NULL DEFAULT FALSE;
-- Existing users (non-default) are considered already changed
UPDATE users SET password_changed = TRUE WHERE username != 'admin';

-- Alert rules — configurable trigger conditions
CREATE TABLE IF NOT EXISTS alert_rules (
    id          BIGSERIAL   PRIMARY KEY,
    name        TEXT        NOT NULL,
    description TEXT        NOT NULL DEFAULT '',
    enabled     BOOLEAN     NOT NULL DEFAULT TRUE,
    event_type  TEXT        NOT NULL DEFAULT '',   -- '' = any
    severity    SMALLINT    NOT NULL DEFAULT 1,    -- minimum severity
    host_match  TEXT        NOT NULL DEFAULT '',   -- '' = any, supports ILIKE
    user_match  TEXT        NOT NULL DEFAULT '',
    process_match TEXT      NOT NULL DEFAULT '',
    created_by  TEXT        NOT NULL DEFAULT 'system',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Seed default rules
INSERT INTO alert_rules (name, description, severity, event_type, created_by) VALUES
  ('High Severity Event',      'Trigger on any event with severity >= 4',          4, '',        'system'),
  ('Critical Event',           'Trigger on any critical severity event (5)',        5, '',        'system'),
  ('Privileged Logon',         'Alert on any logon event with high severity',       4, 'logon',   'system'),
  ('Suspicious Network',       'Alert on high-severity network activity',           4, 'network', 'system'),
  ('Process Execution Alert',  'Alert on high-severity process execution',          4, 'process', 'system')
ON CONFLICT DO NOTHING;

-- Audit log — who did what and when
CREATE TABLE IF NOT EXISTS audit_log (
    id          BIGSERIAL   PRIMARY KEY,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    username    TEXT        NOT NULL,
    action      TEXT        NOT NULL,  -- login, logout, ack_alert, close_alert, create_alert, change_password, create_user, delete_user
    target      TEXT        NOT NULL DEFAULT '',
    detail      TEXT        NOT NULL DEFAULT '',
    ip_address  TEXT        NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_audit_log_time     ON audit_log (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_log_username ON audit_log (username);
