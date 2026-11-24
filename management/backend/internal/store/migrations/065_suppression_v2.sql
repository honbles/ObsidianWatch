-- 065_suppression_v2.sql - suppression v2 (FP-reduction workstream C).
-- Existing rows keep their old behaviour (rule_id prefix match); new rows default to exact.
ALTER TABLE endpoint_suppressions ADD COLUMN IF NOT EXISTS match_mode       TEXT    NOT NULL DEFAULT 'prefix';
ALTER TABLE endpoint_suppressions ALTER COLUMN match_mode SET DEFAULT 'exact';
ALTER TABLE endpoint_suppressions ADD COLUMN IF NOT EXISTS image_path_glob  TEXT    NOT NULL DEFAULT '';
ALTER TABLE endpoint_suppressions ADD COLUMN IF NOT EXISTS parent_process   TEXT    NOT NULL DEFAULT '';
ALTER TABLE endpoint_suppressions ADD COLUMN IF NOT EXISTS user_name        TEXT    NOT NULL DEFAULT '';
ALTER TABLE endpoint_suppressions ADD COLUMN IF NOT EXISTS cmdline_contains TEXT    NOT NULL DEFAULT '';
ALTER TABLE endpoint_suppressions ADD COLUMN IF NOT EXISTS file_path_glob   TEXT    NOT NULL DEFAULT '';
ALTER TABLE endpoint_suppressions ADD COLUMN IF NOT EXISTS permanent        BOOLEAN NOT NULL DEFAULT FALSE;

-- Suppressed matches are counted per suppression / host / day so a bad
-- suppression is discoverable instead of silently hiding alerts.
CREATE TABLE IF NOT EXISTS endpoint_suppression_hits (
    suppression_id BIGINT NOT NULL,
    host           TEXT   NOT NULL DEFAULT '',
    day            DATE   NOT NULL,
    hits           BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY (suppression_id, host, day)
);
