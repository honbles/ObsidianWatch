-- Issues created on the Git platform from SAST findings: one per problem
-- (rule, or package version) per repository, and the findings it covers.
CREATE TABLE IF NOT EXISTS code_finding_issues (
    connector_id  BIGINT NOT NULL REFERENCES devops_connectors(id) ON DELETE CASCADE,
    repo          TEXT NOT NULL,
    group_key     TEXT NOT NULL,
    issue_ref     TEXT NOT NULL,          -- number / iid / work item id
    issue_url     TEXT NOT NULL,
    fingerprints  JSONB NOT NULL DEFAULT '[]',
    created_by    TEXT NOT NULL DEFAULT '',
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (connector_id, repo, group_key)
);
