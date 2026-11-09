-- G-45: CSPM results used to overwrite the previous scan in `settings`. Keep a
-- compact history (severity counts per scan) so trends and regressions show.
CREATE TABLE IF NOT EXISTS cloud_scan_history (
    id           BIGSERIAL PRIMARY KEY,
    provider     TEXT        NOT NULL,
    connector_id BIGINT      NOT NULL,
    scanned_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    critical     INT NOT NULL DEFAULT 0,
    high         INT NOT NULL DEFAULT 0,
    medium       INT NOT NULL DEFAULT 0,
    low          INT NOT NULL DEFAULT 0,
    passed       INT NOT NULL DEFAULT 0,
    total        INT NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_cloud_scan_history_conn ON cloud_scan_history (connector_id, scanned_at DESC);
