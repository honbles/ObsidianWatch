-- 008_more_indexes.sql (H-07)
-- file_hash is matched against IOC hash lists and VirusTotal queues; no index existed.
CREATE INDEX IF NOT EXISTS idx_events_file_hash
    ON events (file_hash, time DESC) WHERE file_hash IS NOT NULL;

-- Substring (ILIKE '%x%') filters on the most-searched text columns.
-- pg_trgm is already required by 003_indexes.sql.
CREATE INDEX IF NOT EXISTS idx_events_host_trgm
    ON events USING gin (host gin_trgm_ops);
CREATE INDEX IF NOT EXISTS idx_events_process_trgm
    ON events USING gin (process_name gin_trgm_ops) WHERE process_name IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_events_user_trgm
    ON events USING gin (user_name gin_trgm_ops) WHERE user_name IS NOT NULL;

-- Per-host cursor reads by engines (host-scoped, ordered by ingest time).
CREATE INDEX IF NOT EXISTS idx_events_host_ingested
    ON events (host, ingested_at DESC);
