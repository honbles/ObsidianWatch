-- 011_settings.sql
-- Stores platform settings editable from the UI — no yaml restart required.

CREATE TABLE IF NOT EXISTS settings (
    key         TEXT PRIMARY KEY,
    value       TEXT NOT NULL DEFAULT '',
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Pre-populate SMTP keys with empty defaults
INSERT INTO settings (key, value) VALUES
    ('smtp.enabled',      'false'),
    ('smtp.host',         ''),
    ('smtp.port',         '587'),
    ('smtp.username',     ''),
    ('smtp.password',     ''),
    ('smtp.from',         ''),
    ('smtp.to',           ''),
    ('smtp.min_severity', '4'),
    ('smtp.use_tls',      'true')
ON CONFLICT (key) DO NOTHING;
