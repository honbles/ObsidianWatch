-- Application Monitoring: error tracking (APM spec item 4). One row per error group, keyed by a fingerprint the agent
-- computes from the exception type, the top in-app stack frames and the route. Names, counts and a scrubbed sample only:
-- the message is empty unless the service allows masked messages; frames hold a function and a short file:line.
CREATE TABLE IF NOT EXISTS error_groups (
  id               BIGSERIAL   PRIMARY KEY,
  service_id       BIGINT      NOT NULL REFERENCES services(id) ON DELETE CASCADE,
  fingerprint      TEXT        NOT NULL,
  type             TEXT        NOT NULL DEFAULT '',
  route            TEXT        NOT NULL DEFAULT '',
  method           TEXT        NOT NULL DEFAULT '',
  frame            TEXT        NOT NULL DEFAULT '',        -- top in-app frame
  frames           JSONB       NOT NULL DEFAULT '[]',
  message          TEXT        NOT NULL DEFAULT '',
  first_seen       TIMESTAMPTZ NOT NULL,
  last_seen        TIMESTAMPTZ NOT NULL,
  count            BIGINT      NOT NULL DEFAULT 0,
  first_version    TEXT        NOT NULL DEFAULT '',
  last_version     TEXT        NOT NULL DEFAULT '',
  status           TEXT        NOT NULL DEFAULT 'open',    -- open | resolved | ignored
  assignee         TEXT        NOT NULL DEFAULT '',
  resolved_version TEXT        NOT NULL DEFAULT '',        -- the version running when it was resolved
  regressed        BOOLEAN     NOT NULL DEFAULT FALSE,
  regressed_at     TIMESTAMPTZ,
  sample_traces    JSONB       NOT NULL DEFAULT '[]',
  UNIQUE (service_id, fingerprint)
);
CREATE INDEX IF NOT EXISTS idx_error_groups_service ON error_groups (service_id, last_seen DESC);

CREATE TABLE IF NOT EXISTS error_group_hours (
  group_id BIGINT      NOT NULL REFERENCES error_groups(id) ON DELETE CASCADE,
  hour     TIMESTAMPTZ NOT NULL,
  count    BIGINT      NOT NULL DEFAULT 0,
  PRIMARY KEY (group_id, hour)
);
CREATE INDEX IF NOT EXISTS idx_error_group_hours_hour ON error_group_hours (hour);
