-- 008_detection_signatures.sql
-- Stores enabled/disabled state for built-in detection signatures.
-- Also allows overriding severity per signature.

CREATE TABLE IF NOT EXISTS detection_signatures (
    id          TEXT PRIMARY KEY,          -- e.g. "T1059.001"
    enabled     BOOLEAN NOT NULL DEFAULT TRUE,
    severity    INT,                       -- NULL = use built-in default
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Index for fast lookup
CREATE INDEX IF NOT EXISTS idx_detection_signatures_enabled ON detection_signatures(enabled);
