-- 015_devops_connectors.sql
-- DevOps connector table for GitHub, GitLab, Azure DevOps

CREATE TABLE IF NOT EXISTS devops_connectors (
    id              BIGSERIAL PRIMARY KEY,
    provider        TEXT NOT NULL,          -- github | gitlab | azuredevops
    org             TEXT NOT NULL,          -- org/group/project name
    label           TEXT NOT NULL DEFAULT '',
    credentials     JSONB NOT NULL DEFAULT '{}', -- token, webhook_secret etc (encrypted in app)
    status          TEXT NOT NULL DEFAULT 'pending', -- pending | connected | error
    last_sync       TIMESTAMPTZ,
    last_error      TEXT,
    event_count     BIGINT NOT NULL DEFAULT 0,
    sync_cursor     TEXT NOT NULL DEFAULT '',  -- last processed event cursor/timestamp
    webhook_secret  TEXT NOT NULL DEFAULT '',  -- HMAC secret for webhook validation
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_devops_connectors_provider ON devops_connectors (provider);

-- devops_commits stores commit metadata + diff for code audit
CREATE TABLE IF NOT EXISTS devops_commits (
    id              TEXT PRIMARY KEY,   -- SHA
    connector_id    BIGINT REFERENCES devops_connectors(id) ON DELETE CASCADE,
    repo            TEXT NOT NULL,
    branch          TEXT NOT NULL,
    author_name     TEXT NOT NULL DEFAULT '',
    author_email    TEXT NOT NULL DEFAULT '',
    author_username TEXT NOT NULL DEFAULT '',
    message         TEXT NOT NULL DEFAULT '',
    url             TEXT NOT NULL DEFAULT '',
    files_changed   INT NOT NULL DEFAULT 0,
    additions       INT NOT NULL DEFAULT 0,
    deletions       INT NOT NULL DEFAULT 0,
    diff_summary    JSONB NOT NULL DEFAULT '[]', -- [{file, additions, deletions, patch}]
    pushed_at       TIMESTAMPTZ NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_devops_commits_connector  ON devops_commits (connector_id, pushed_at DESC);
CREATE INDEX IF NOT EXISTS idx_devops_commits_author     ON devops_commits (author_username);
CREATE INDEX IF NOT EXISTS idx_devops_commits_repo       ON devops_commits (repo, pushed_at DESC);
