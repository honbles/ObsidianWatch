-- 042_agent_identity.sql  (spec A1, A4)
-- Enrollment tokens and certificate-backed agent identities. The same file is
-- shipped as management migration 070 so either service can create it first.

CREATE TABLE IF NOT EXISTS agent_enrollment_tokens (
    id          BIGSERIAL   PRIMARY KEY,
    token_hash  TEXT        NOT NULL UNIQUE,      -- sha256 hex; plain token shown once
    label       TEXT        NOT NULL DEFAULT '',
    created_by  TEXT        NOT NULL DEFAULT '',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at  TIMESTAMPTZ NOT NULL,
    max_uses    INTEGER     NOT NULL CHECK (max_uses > 0),
    uses        INTEGER     NOT NULL DEFAULT 0,
    revoked_at  TIMESTAMPTZ,
    revoked_by  TEXT
);

CREATE TABLE IF NOT EXISTS agent_identities (
    agent_id        TEXT        PRIMARY KEY,      -- random "ag-…", never the hostname
    hostname        TEXT        NOT NULL DEFAULT '',
    os              TEXT        NOT NULL DEFAULT '',
    token_id        BIGINT      REFERENCES agent_enrollment_tokens(id) ON DELETE SET NULL,
    enrolled_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    enrolled_from   TEXT        NOT NULL DEFAULT '',
    cert_serial     TEXT        NOT NULL,
    cert_not_after  TIMESTAMPTZ NOT NULL,
    renewed_at      TIMESTAMPTZ,
    revoked_at      TIMESTAMPTZ,
    revoked_by      TEXT,
    revoke_reason   TEXT
);

CREATE INDEX IF NOT EXISTS idx_agent_identities_revoked ON agent_identities(revoked_at) WHERE revoked_at IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_agent_identities_host ON agent_identities(hostname);

-- Public certificate of the agent CA. The private key stays on the ingest
-- backend; management reads this row to verify tunnel client certificates.
CREATE TABLE IF NOT EXISTS agent_ca (
    id          SMALLINT    PRIMARY KEY CHECK (id = 1),
    cert_pem    TEXT        NOT NULL,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
