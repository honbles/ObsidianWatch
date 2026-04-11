-- 008_live_response.sql
-- Live Response: stores agent service account credentials and session history.

CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- Live response credentials per agent
-- The password is stored bcrypt-hashed — plaintext never touches the DB.
CREATE TABLE IF NOT EXISTS lr_credentials (
    agent_id      TEXT        PRIMARY KEY REFERENCES agents(id) ON DELETE CASCADE,
    username      TEXT        NOT NULL,
    password_hash TEXT        NOT NULL,   -- bcrypt hash
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Session history / audit trail
CREATE TABLE IF NOT EXISTS lr_sessions (
    id            BIGSERIAL   PRIMARY KEY,
    agent_id      TEXT        NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    initiated_by  TEXT        NOT NULL,   -- analyst username
    session_token TEXT        NOT NULL UNIQUE,
    protocol      TEXT        NOT NULL,   -- 'ssh' | 'rdp'
    status        TEXT        NOT NULL DEFAULT 'pending',  -- pending | active | closed | failed
    started_at    TIMESTAMPTZ,
    ended_at      TIMESTAMPTZ,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_lr_sessions_agent    ON lr_sessions(agent_id);
CREATE INDEX IF NOT EXISTS idx_lr_sessions_token    ON lr_sessions(session_token);
CREATE INDEX IF NOT EXISTS idx_lr_sessions_created  ON lr_sessions(created_at DESC);
