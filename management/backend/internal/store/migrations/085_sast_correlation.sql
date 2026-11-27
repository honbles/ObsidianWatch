-- AI correlation of multi-engine SAST results: when a result is correlated,
-- findings holds the correlated findings and raw_findings the engines' own.
ALTER TABLE sast_results ADD COLUMN IF NOT EXISTS raw_findings JSONB;
ALTER TABLE sast_results ADD COLUMN IF NOT EXISTS correlation JSONB;
