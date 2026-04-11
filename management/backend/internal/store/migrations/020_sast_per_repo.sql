-- 020_sast_per_repo.sql
-- Persist SAST results per repo+branch instead of per connector

-- Add repo and branch columns
ALTER TABLE sast_results ADD COLUMN IF NOT EXISTS repo   TEXT NOT NULL DEFAULT '';
ALTER TABLE sast_results ADD COLUMN IF NOT EXISTS branch TEXT NOT NULL DEFAULT '';
ALTER TABLE sast_results ADD COLUMN IF NOT EXISTS engine TEXT NOT NULL DEFAULT 'semgrep';

-- Clean up duplicates before adding unique constraint
-- Keep only the latest result per connector+repo+branch
DELETE FROM sast_results WHERE id NOT IN (
    SELECT MAX(id) FROM sast_results GROUP BY connector_id, repo, branch
);

-- Now safe to add unique constraint
ALTER TABLE sast_results DROP CONSTRAINT IF EXISTS sast_results_connector_repo_branch_key;
ALTER TABLE sast_results ADD CONSTRAINT sast_results_connector_repo_branch_key
    UNIQUE (connector_id, repo, branch);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_sast_connector_repo
    ON sast_results (connector_id, repo, scanned_at DESC);
CREATE INDEX IF NOT EXISTS idx_sast_connector_time
    ON sast_results (connector_id, scanned_at DESC);
