-- 010_path_indexes.sql (Alert Graph: file -> process joins)
-- Find the process that wrote a file later executed (and the processes that
-- ran a file a lineage wrote) by exact path. Expression is capped at 512 chars
-- so very long paths can never exceed the btree row-size limit on insert.
CREATE INDEX IF NOT EXISTS idx_events_agent_filepath
    ON events (agent_id, left(lower(file_path), 512), time DESC)
    WHERE file_path IS NOT NULL AND event_type = 'file';
CREATE INDEX IF NOT EXISTS idx_events_agent_imagepath
    ON events (agent_id, left(lower(image_path), 512), time DESC)
    WHERE image_path IS NOT NULL AND event_type = 'process';
