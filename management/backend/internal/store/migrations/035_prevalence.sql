-- P-02: fleet prevalence / first-seen for binaries (hash, image path, process name).
CREATE TABLE IF NOT EXISTS prevalence (
    key        TEXT        NOT NULL,
    host       TEXT        NOT NULL,
    first_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    seen_count BIGINT      NOT NULL DEFAULT 1,
    PRIMARY KEY (key, host)
);
CREATE INDEX IF NOT EXISTS idx_prevalence_key ON prevalence (key);
CREATE INDEX IF NOT EXISTS idx_prevalence_last_seen ON prevalence (last_seen);
