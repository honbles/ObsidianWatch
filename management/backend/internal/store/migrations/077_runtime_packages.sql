-- Code step 4: packages seen in running service processes (from the Linux
-- agent's runtime_inventory events), for runtime reachability of dependency
-- vulnerabilities.
CREATE TABLE IF NOT EXISTS runtime_packages (
    ecosystem   TEXT NOT NULL,
    name_key    TEXT NOT NULL,      -- normalised name for matching
    name        TEXT NOT NULL,
    version     TEXT NOT NULL,
    agent_id    TEXT NOT NULL,
    host        TEXT NOT NULL DEFAULT '',
    service     TEXT NOT NULL DEFAULT '',
    container   TEXT NOT NULL DEFAULT '',
    exe         TEXT NOT NULL DEFAULT '',
    evidence    TEXT NOT NULL,      -- loaded | deployed
    first_seen  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (ecosystem, name_key, version, agent_id, service, container, exe)
);
CREATE INDEX IF NOT EXISTS idx_runtime_packages_lookup ON runtime_packages (ecosystem, name_key, version, last_seen DESC);
CREATE INDEX IF NOT EXISTS idx_runtime_packages_seen ON runtime_packages (last_seen);
