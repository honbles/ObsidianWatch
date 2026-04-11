-- 017_ai_analysis_cache.sql
-- Cache AI analysis results on alerts and agents (vuln scans)
-- so they load instantly on re-open without re-running the AI.

ALTER TABLE alerts ADD COLUMN IF NOT EXISTS ai_analysis JSONB;
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS ai_analysed_at TIMESTAMPTZ;
