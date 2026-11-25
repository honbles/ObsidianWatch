-- The commit each SAST result was taken from, so a service's deployed commit
-- can be matched to a scan. Scans of one exact commit (for a deployed service)
-- are stored with branch '@<sha>'.
ALTER TABLE sast_results ADD COLUMN IF NOT EXISTS commit_sha TEXT NOT NULL DEFAULT '';
CREATE INDEX IF NOT EXISTS idx_sast_results_commit ON sast_results (connector_id, repo, commit_sha) WHERE commit_sha <> '';
