-- 033_endpoint_suppressions.sql (D-10) — endpoint rule suppressions / allowlist
CREATE TABLE IF NOT EXISTS endpoint_suppressions (
    id           BIGSERIAL PRIMARY KEY,
    rule_id      TEXT NOT NULL DEFAULT '',   -- exact sig ID or prefix; '' = any rule
    host         TEXT NOT NULL DEFAULT '',   -- exact host; '' = any host
    process_name TEXT NOT NULL DEFAULT '',   -- exact process name (case-insens.); '' = any
    reason       TEXT NOT NULL,
    created_by   TEXT NOT NULL DEFAULT '',
    expires_at   TIMESTAMPTZ,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
