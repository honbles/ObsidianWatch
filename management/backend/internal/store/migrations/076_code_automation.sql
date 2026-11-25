-- Code step 3: scan jobs (on push, on schedule, on pull/merge request, manual)
-- and per-PR check state so comments are not repeated.
CREATE TABLE IF NOT EXISTS code_scan_jobs (
    id            BIGSERIAL PRIMARY KEY,
    connector_id  BIGINT NOT NULL REFERENCES devops_connectors(id) ON DELETE CASCADE,
    kind          TEXT NOT NULL,              -- branch | pr
    trigger       TEXT NOT NULL,              -- push | schedule | pr | manual
    repo          TEXT NOT NULL,
    ref           TEXT NOT NULL DEFAULT '',   -- branch name, or PR number for kind=pr
    base_branch   TEXT NOT NULL DEFAULT '',
    head_ref      TEXT NOT NULL DEFAULT '',
    head_sha      TEXT NOT NULL DEFAULT '',
    status        TEXT NOT NULL DEFAULT 'queued', -- queued | running | done | failed
    blocked       BOOLEAN NOT NULL DEFAULT FALSE,
    finding_count INT NOT NULL DEFAULT 0,
    error         TEXT,
    result        JSONB,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    started_at    TIMESTAMPTZ,
    finished_at   TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_code_scan_jobs_queue ON code_scan_jobs (status, id);
CREATE INDEX IF NOT EXISTS idx_code_scan_jobs_conn ON code_scan_jobs (connector_id, created_at DESC);
-- One queued/running job per target and commit.
CREATE UNIQUE INDEX IF NOT EXISTS uq_code_scan_jobs_active
    ON code_scan_jobs (connector_id, kind, repo, ref, head_sha) WHERE status IN ('queued', 'running');

CREATE TABLE IF NOT EXISTS code_pr_checks (
    connector_id  BIGINT NOT NULL REFERENCES devops_connectors(id) ON DELETE CASCADE,
    repo          TEXT NOT NULL,
    pr            TEXT NOT NULL,
    last_sha      TEXT NOT NULL DEFAULT '',
    last_state    TEXT NOT NULL DEFAULT '',
    commented     JSONB NOT NULL DEFAULT '[]', -- finding keys already posted inline
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (connector_id, repo, pr)
);
