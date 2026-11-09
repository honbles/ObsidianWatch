-- 031_lr_transcripts.sql (F-04) — Live Response session transcripts
CREATE TABLE IF NOT EXISTS lr_transcripts (
    id         BIGSERIAL PRIMARY KEY,
    session_id BIGINT NOT NULL,
    ts         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    direction  TEXT NOT NULL,          -- 'in' (analyst keystrokes) | 'out' (terminal output)
    data       BYTEA NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_lr_transcripts_session ON lr_transcripts (session_id, id);
