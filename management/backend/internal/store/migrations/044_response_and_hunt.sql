-- 044: one-click response actions and fleet threat hunting

-- Every action an analyst (or the reconciler) sends to an agent, with outcome.
CREATE TABLE IF NOT EXISTS response_actions (
    id            TEXT PRIMARY KEY,
    agent_id      TEXT NOT NULL,
    hostname      TEXT NOT NULL DEFAULT '',
    action        TEXT NOT NULL,
    params        JSONB NOT NULL DEFAULT '{}',
    status        TEXT NOT NULL DEFAULT 'pending',   -- pending | queued | sent | ok | failed | timeout
    message       TEXT NOT NULL DEFAULT '',
    result        JSONB,
    requested_by  TEXT NOT NULL DEFAULT '',
    reason        TEXT NOT NULL DEFAULT '',
    alert_id      TEXT NOT NULL DEFAULT '',
    requested_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    completed_at  TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_response_actions_agent ON response_actions (agent_id, requested_at DESC);
CREATE INDEX IF NOT EXISTS idx_response_actions_recent ON response_actions (requested_at DESC);

-- What we WANT (desired_isolated) and what the agent last REPORTED. On every
-- tunnel (re)connect the server reconciles the two, so isolating or releasing
-- an offline host still takes effect when it comes back.
CREATE TABLE IF NOT EXISTS agent_response_state (
    agent_id          TEXT PRIMARY KEY,
    desired_isolated  BOOLEAN NOT NULL DEFAULT FALSE,
    desired_ttl_min   INTEGER NOT NULL DEFAULT 0,
    desired_expires_at TIMESTAMPTZ,                 -- when a timed isolation should end (server-side clock)
    isolated          BOOLEAN NOT NULL DEFAULT FALSE,
    isolated_since    TIMESTAMPTZ,
    expires_at        TIMESTAMPTZ,
    quarantined       INTEGER NOT NULL DEFAULT 0,
    reported_at       TIMESTAMPTZ
);

-- Live fleet queries ("which hosts run X right now?").
CREATE TABLE IF NOT EXISTS fleet_hunts (
    id            TEXT PRIMARY KEY,
    name          TEXT NOT NULL DEFAULT '',
    kind          TEXT NOT NULL,
    match         TEXT NOT NULL DEFAULT '',
    path          TEXT NOT NULL DEFAULT '',
    requested_by  TEXT NOT NULL DEFAULT '',
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    completed_at  TIMESTAMPTZ,
    agents_total  INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_fleet_hunts_created ON fleet_hunts (created_at DESC);

CREATE TABLE IF NOT EXISTS fleet_hunt_results (
    hunt_id       TEXT NOT NULL REFERENCES fleet_hunts(id) ON DELETE CASCADE,
    agent_id      TEXT NOT NULL,
    hostname      TEXT NOT NULL DEFAULT '',
    os            TEXT NOT NULL DEFAULT '',
    status        TEXT NOT NULL DEFAULT 'pending',   -- pending | ok | failed | offline | timeout
    message       TEXT NOT NULL DEFAULT '',
    columns       JSONB NOT NULL DEFAULT '[]',
    rows          JSONB NOT NULL DEFAULT '[]',
    row_count     INTEGER NOT NULL DEFAULT 0,
    truncated     BOOLEAN NOT NULL DEFAULT FALSE,
    completed_at  TIMESTAMPTZ,
    PRIMARY KEY (hunt_id, agent_id)
);
