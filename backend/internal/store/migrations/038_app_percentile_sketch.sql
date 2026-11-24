-- Application Monitoring: a mergeable latency sketch beside the 12-bucket histogram (APM spec item 6).
-- sketch_calls is how many of the row's calls the sketch covers. A row is sketch-complete only when
-- sketch_calls = calls (agents older than this feature send no sketch), and readers use the sketch for a range only
-- when every row in it is complete; otherwise they fall back to the histogram.
ALTER TABLE app_route_stats ADD COLUMN IF NOT EXISTS sketch       JSONB;
ALTER TABLE app_route_stats ADD COLUMN IF NOT EXISTS sketch_calls BIGINT NOT NULL DEFAULT 0;
