-- 005_agent_location.sql
-- Adds GPS/IP geolocation fields to the agents table.

ALTER TABLE agents
    ADD COLUMN IF NOT EXISTS lat               DOUBLE PRECISION,
    ADD COLUMN IF NOT EXISTS lng               DOUBLE PRECISION,
    ADD COLUMN IF NOT EXISTS location_accuracy DOUBLE PRECISION,
    ADD COLUMN IF NOT EXISTS location_source   TEXT,
    ADD COLUMN IF NOT EXISTS location_city     TEXT,
    ADD COLUMN IF NOT EXISTS location_country  TEXT,
    ADD COLUMN IF NOT EXISTS location_updated  TIMESTAMPTZ;
