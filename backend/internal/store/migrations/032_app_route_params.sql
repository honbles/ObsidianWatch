-- Application Monitoring: request parameter NAMES seen per route template (payload capture design, step 1).
-- Names and counts only. Values are never sent by the agent and are never stored. The inventory is kept as long
-- as the route is; the number of names per route is capped by the ingest code.
CREATE TABLE IF NOT EXISTS service_route_params (
  service_id  BIGINT      NOT NULL REFERENCES services(id) ON DELETE CASCADE,
  route       TEXT        NOT NULL,
  method      TEXT        NOT NULL,
  name        TEXT        NOT NULL,
  requests    BIGINT      NOT NULL DEFAULT 0,
  first_seen  TIMESTAMPTZ NOT NULL,
  last_seen   TIMESTAMPTZ NOT NULL,
  PRIMARY KEY (service_id, route, method, name)
);
