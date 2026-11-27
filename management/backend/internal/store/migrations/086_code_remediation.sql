-- Code automation remediation: agent jobs carry a payload (the PR comment
-- that mentioned the agent); fix pull requests opened by the agent; the
-- result of setting up a protected branch (webhook, branch protection).
ALTER TABLE code_scan_jobs ADD COLUMN IF NOT EXISTS payload JSONB;

CREATE TABLE IF NOT EXISTS code_fix_prs (
    id            BIGSERIAL PRIMARY KEY,
    connector_id  BIGINT NOT NULL REFERENCES devops_connectors(id) ON DELETE CASCADE,
    repo          TEXT NOT NULL,
    base_branch   TEXT NOT NULL,
    head_branch   TEXT NOT NULL,
    number        TEXT NOT NULL DEFAULT '',
    url           TEXT NOT NULL DEFAULT '',
    group_key     TEXT NOT NULL,
    title         TEXT NOT NULL,
    fingerprints  JSONB NOT NULL DEFAULT '[]',
    findings      JSONB NOT NULL DEFAULT '[]',
    model         TEXT NOT NULL DEFAULT '',
    status        TEXT NOT NULL DEFAULT 'open',   -- open | merged | closed
    agent_replies INT NOT NULL DEFAULT 0,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_code_fix_prs_branch ON code_fix_prs (connector_id, repo, base_branch, status);
CREATE UNIQUE INDEX IF NOT EXISTS uq_code_fix_prs_number ON code_fix_prs (connector_id, repo, number) WHERE number <> '';

CREATE TABLE IF NOT EXISTS code_repo_setup (
    connector_id  BIGINT NOT NULL REFERENCES devops_connectors(id) ON DELETE CASCADE,
    repo          TEXT NOT NULL,
    branch        TEXT NOT NULL,
    ok            BOOLEAN NOT NULL DEFAULT FALSE,
    steps         JSONB NOT NULL DEFAULT '[]',
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (connector_id, repo, branch)
);
