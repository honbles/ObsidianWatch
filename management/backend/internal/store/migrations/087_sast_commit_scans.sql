-- Commit scans in the SAST tab. A scan of one exact commit is stored as
-- branch '@<sha>' (see 081). These columns record which branch the commit was
-- picked from (for "compare with branch"), its message and author, and
-- whether it is pinned (a pinned commit scan is never pruned).
ALTER TABLE sast_results ADD COLUMN IF NOT EXISTS of_branch      TEXT    NOT NULL DEFAULT '';
ALTER TABLE sast_results ADD COLUMN IF NOT EXISTS commit_message TEXT    NOT NULL DEFAULT '';
ALTER TABLE sast_results ADD COLUMN IF NOT EXISTS commit_author  TEXT    NOT NULL DEFAULT '';
ALTER TABLE sast_results ADD COLUMN IF NOT EXISTS pinned         BOOLEAN NOT NULL DEFAULT FALSE;

-- The old Commit Scan (pattern matching of synced commit diffs) is replaced
-- by commit scans in SAST; its results table goes.
DROP TABLE IF EXISTS code_scan_results;
