-- 004_ip_columns_to_text.sql
-- Changes src_ip and dst_ip from INET to TEXT.
--
-- Reason: the DNS collector stores queried hostnames (e.g. "google.com")
-- in dst_ip for searchability. INET rejects non-IP strings causing HTTP 500
-- on every batch that contains a DNS event.
--
-- TEXT is strictly more flexible — valid IPs still store and compare correctly.
-- The existing INET indexes are dropped and recreated as plain btree TEXT indexes.

-- Drop the old INET indexes first (required before altering column type)
DROP INDEX IF EXISTS idx_events_src_ip;
DROP INDEX IF EXISTS idx_events_dst_ip;

-- Alter column types
ALTER TABLE events
    ALTER COLUMN src_ip TYPE TEXT USING src_ip::TEXT,
    ALTER COLUMN dst_ip TYPE TEXT USING dst_ip::TEXT;

-- Recreate indexes as TEXT btree
CREATE INDEX IF NOT EXISTS idx_events_src_ip ON events (src_ip, time DESC) WHERE src_ip IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_events_dst_ip ON events (dst_ip, time DESC) WHERE dst_ip IS NOT NULL;
