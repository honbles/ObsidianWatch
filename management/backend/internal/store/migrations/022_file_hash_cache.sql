-- 022_file_hash_cache.sql
-- Cache VirusTotal results for file hashes
-- Hashes never change so results are permanent

CREATE TABLE IF NOT EXISTS file_hash_cache (
    hash            TEXT PRIMARY KEY,
    hash_type       TEXT NOT NULL DEFAULT 'sha256', -- sha256, md5, sha1
    file_name       TEXT,                           -- most common filename seen
    vt_score        SMALLINT,                       -- malicious engines count (NULL = not checked yet)
    vt_total        SMALLINT,                       -- total engines
    vt_verdict      TEXT,                           -- 'clean', 'malicious', 'suspicious', 'undetected', 'queued'
    vt_family       TEXT,                           -- malware family if detected
    vt_checked_at   TIMESTAMPTZ,                    -- when VT was last queried
    first_seen      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    host_count      INT NOT NULL DEFAULT 1,         -- how many hosts this hash was seen on
    event_count     INT NOT NULL DEFAULT 1          -- total times seen
);

CREATE INDEX IF NOT EXISTS idx_hash_verdict  ON file_hash_cache (vt_verdict);
CREATE INDEX IF NOT EXISTS idx_hash_queued   ON file_hash_cache (vt_verdict) WHERE vt_verdict = 'queued';
CREATE INDEX IF NOT EXISTS idx_hash_seen     ON file_hash_cache (last_seen DESC);
