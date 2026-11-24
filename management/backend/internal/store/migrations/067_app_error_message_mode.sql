-- Application Monitoring: whether the agent may forward a masked error message with an error group.
-- off (default): no message leaves the host. masked: digits, quoted strings, emails, uuids and long opaque strings are replaced first.
ALTER TABLE service_settings ADD COLUMN IF NOT EXISTS error_message_mode TEXT NOT NULL DEFAULT 'off';
