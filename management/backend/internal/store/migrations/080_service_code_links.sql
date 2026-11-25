-- Application ↔ code: an analyst links a repository branch to a monitored
-- service, so code findings can be read against what that service runs.
-- service_id refers to services(id) in the ingest database (no foreign key:
-- the two databases migrate independently).
CREATE TABLE IF NOT EXISTS service_code_links (
    id            BIGSERIAL   PRIMARY KEY,
    service_id    BIGINT      NOT NULL,
    connector_id  BIGINT      NOT NULL,
    repo          TEXT        NOT NULL,
    branch        TEXT        NOT NULL DEFAULT '',   -- '' = the repository's default branch
    is_default    BOOLEAN     NOT NULL DEFAULT TRUE, -- branch is the default branch (scans stored as HEAD count)
    created_by    TEXT        NOT NULL DEFAULT '',
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (service_id, connector_id, repo)
);
CREATE INDEX IF NOT EXISTS idx_service_code_links_repo ON service_code_links (connector_id, repo);

-- The process a runtime package was seen in, so a package can be attributed to
-- one service instance (agent + pid) and not only to a host.
ALTER TABLE runtime_packages ADD COLUMN IF NOT EXISTS pid INT NOT NULL DEFAULT 0;
CREATE INDEX IF NOT EXISTS idx_runtime_packages_agent ON runtime_packages (agent_id, last_seen DESC);
