-- Application Monitoring: the API a service DECLARES (OpenAPI / Swagger), so routes and fields can be reviewed and
-- masked before any traffic arrives. Declared fields live in service_route_params next to observed ones:
--   source   observed | declared | both
--   location query | path | header | body ('' when unknown)
-- Declared routes live in service_declared_routes, NOT in service_routes, so a declared route is never mistaken
-- for traffic (no "new route" signal, no first_seen from a spec).
ALTER TABLE service_route_params ADD COLUMN IF NOT EXISTS source   TEXT NOT NULL DEFAULT 'observed';
ALTER TABLE service_route_params ADD COLUMN IF NOT EXISTS location TEXT NOT NULL DEFAULT '';

CREATE TABLE IF NOT EXISTS service_declared_routes (
  service_id  BIGINT      NOT NULL REFERENCES services(id) ON DELETE CASCADE,
  route       TEXT        NOT NULL,
  method      TEXT        NOT NULL,
  summary     TEXT        NOT NULL DEFAULT '',
  declared_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (service_id, route, method)
);

-- One loaded spec per service: where it came from and what it held.
CREATE TABLE IF NOT EXISTS service_openapi (
  service_id BIGINT      PRIMARY KEY REFERENCES services(id) ON DELETE CASCADE,
  title      TEXT        NOT NULL DEFAULT '',
  version    TEXT        NOT NULL DEFAULT '',
  source_ref TEXT        NOT NULL DEFAULT '',
  routes     INT         NOT NULL DEFAULT 0,
  params     INT         NOT NULL DEFAULT 0,
  loaded_by  TEXT        NOT NULL DEFAULT '',
  loaded_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
