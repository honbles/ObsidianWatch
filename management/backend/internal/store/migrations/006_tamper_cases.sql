-- 006_tamper_cases.sql

-- Enable pgcrypto for gen_random_bytes (safe to run multiple times)
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- Tamper protection: install key per agent
ALTER TABLE agents ADD COLUMN IF NOT EXISTS install_key   TEXT;
ALTER TABLE agents ADD COLUMN IF NOT EXISTS tamper_locked BOOLEAN NOT NULL DEFAULT FALSE;

-- Generate keys for existing agents that don't have one
UPDATE agents SET install_key = encode(gen_random_bytes(16), 'hex') WHERE install_key IS NULL;

-- Case / assignment columns on alerts
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS assigned_to   TEXT;        -- username assigned
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS case_notes    TEXT;        -- analyst notes
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS closed_by     TEXT;        -- who closed
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS closed_at     TIMESTAMPTZ;
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS review_comment TEXT;       -- comment on close

-- Pre-generate install keys for any existing agents
CREATE INDEX IF NOT EXISTS idx_agents_install_key ON agents(install_key);
