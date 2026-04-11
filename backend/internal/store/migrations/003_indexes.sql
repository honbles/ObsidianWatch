-- 003_indexes.sql
-- Additional indexes to support query patterns from the v0.2.0 collectors:
-- DNS, FIM, health heartbeats, applog, full XML-parsed event log fields,
-- and the management platform alert/stats queries.

-- ── Event Log / general ────────────────────────────────────────────────────

-- Channel name (Security, System, DNS-Client, etc.)
CREATE INDEX IF NOT EXISTS idx_events_channel
    ON events (channel, time DESC)
    WHERE channel IS NOT NULL;

-- Windows Event ID — very common filter in security investigations
CREATE INDEX IF NOT EXISTS idx_events_event_id
    ON events (event_id, time DESC)
    WHERE event_id IS NOT NULL;

-- ── Identity ───────────────────────────────────────────────────────────────

-- Domain — filter all events for a specific AD domain
CREATE INDEX IF NOT EXISTS idx_events_domain
    ON events (domain, time DESC)
    WHERE domain IS NOT NULL;

-- Logon session ID — correlate all events in a logon session
CREATE INDEX IF NOT EXISTS idx_events_logon_id
    ON events (logon_id, time DESC)
    WHERE logon_id IS NOT NULL;

-- ── Process ────────────────────────────────────────────────────────────────

-- PID — correlate process events by PID across sources
CREATE INDEX IF NOT EXISTS idx_events_pid
    ON events (pid, time DESC)
    WHERE pid IS NOT NULL;

-- Command line full-text search (pg_trgm trigram index for LIKE/ILIKE)
CREATE EXTENSION IF NOT EXISTS pg_trgm;

CREATE INDEX IF NOT EXISTS idx_events_command_line_trgm
    ON events USING gin (command_line gin_trgm_ops)
    WHERE command_line IS NOT NULL;

-- ── File / FIM ─────────────────────────────────────────────────────────────

-- File path — FIM and file access events
CREATE INDEX IF NOT EXISTS idx_events_file_path
    ON events (file_path, time DESC)
    WHERE file_path IS NOT NULL;

-- File path trigram for LIKE searches (e.g. WHERE file_path ILIKE '%system32%')
CREATE INDEX IF NOT EXISTS idx_events_file_path_trgm
    ON events USING gin (file_path gin_trgm_ops)
    WHERE file_path IS NOT NULL;

-- ── Registry ───────────────────────────────────────────────────────────────

-- Registry key — filter/search registry change events
CREATE INDEX IF NOT EXISTS idx_events_reg_key
    ON events (reg_key, time DESC)
    WHERE reg_key IS NOT NULL;

-- ── Network / DNS ──────────────────────────────────────────────────────────

-- Protocol — filter TCP vs UDP
CREATE INDEX IF NOT EXISTS idx_events_proto
    ON events (proto, time DESC)
    WHERE proto IS NOT NULL;

-- Destination port — common pivot for lateral movement detection
CREATE INDEX IF NOT EXISTS idx_events_dst_port
    ON events (dst_port, time DESC)
    WHERE dst_port IS NOT NULL;

-- Source port
CREATE INDEX IF NOT EXISTS idx_events_src_port
    ON events (src_port, time DESC)
    WHERE src_port IS NOT NULL;

-- ── Management platform queries ─────────────────────────────────────────────

-- Composite: agent + severity + time — drives the alert engine query
CREATE INDEX IF NOT EXISTS idx_events_agent_severity
    ON events (agent_id, severity, time DESC);

-- Composite: event_type + severity + time — drives dashboard stat queries
CREATE INDEX IF NOT EXISTS idx_events_type_severity
    ON events (event_type, severity, time DESC);

-- host + time — drives per-host timeline queries
CREATE INDEX IF NOT EXISTS idx_events_host_time
    ON events (host, time DESC);

-- ── JSONB raw payload ──────────────────────────────────────────────────────

-- GIN index on the raw JSONB column — enables @>, ?, ?| operators
-- Useful for querying applog / health / DNS fields stored in raw
CREATE INDEX IF NOT EXISTS idx_events_raw_gin
    ON events USING gin (raw)
    WHERE raw IS NOT NULL;
