-- Code step 5: analyst triage decisions on code findings, triage rules
-- learned from them, and cached AI fix suggestions.
CREATE TABLE IF NOT EXISTS code_finding_triage (
    connector_id  BIGINT NOT NULL REFERENCES devops_connectors(id) ON DELETE CASCADE,
    repo          TEXT NOT NULL,
    fingerprint   TEXT NOT NULL,
    rule_id       TEXT NOT NULL,
    file          TEXT NOT NULL DEFAULT '',
    status        TEXT NOT NULL,          -- false_positive | accepted_risk | confirmed
    reason        TEXT NOT NULL DEFAULT '',
    decided_by    TEXT NOT NULL DEFAULT '',
    decided_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (connector_id, repo, fingerprint)
);
CREATE INDEX IF NOT EXISTS idx_code_triage_rule ON code_finding_triage (connector_id, rule_id);

CREATE TABLE IF NOT EXISTS code_triage_rules (
    id            BIGSERIAL PRIMARY KEY,
    connector_id  BIGINT NOT NULL REFERENCES devops_connectors(id) ON DELETE CASCADE,
    repo          TEXT NOT NULL DEFAULT '',   -- '' = every repository of the connector
    rule_id       TEXT NOT NULL,
    path_prefix   TEXT NOT NULL DEFAULT '',   -- '' = any file
    status        TEXT NOT NULL,              -- false_positive | accepted_risk
    reason        TEXT NOT NULL DEFAULT '',
    created_by    TEXT NOT NULL DEFAULT '',
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at    TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_code_triage_rules_conn ON code_triage_rules (connector_id);

CREATE TABLE IF NOT EXISTS code_fix_cache (
    key         TEXT PRIMARY KEY,
    body        JSONB NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
