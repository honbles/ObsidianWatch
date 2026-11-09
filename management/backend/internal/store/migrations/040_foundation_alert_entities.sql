-- Shared foundation (owned by the integration owner; do not edit in a side branch).
-- Links an alert to the entities it concerns, across layers.
-- kind values are a closed registry, see internal/api/entity_kinds.go.
CREATE TABLE IF NOT EXISTS alert_entities (
  alert_id BIGINT NOT NULL,
  kind     TEXT   NOT NULL,
  key      TEXT   NOT NULL,
  PRIMARY KEY (alert_id, kind, key)
);
CREATE INDEX IF NOT EXISTS idx_alert_entities_entity ON alert_entities (kind, key);
