// Where an alert-entity chip links to. Closed registry; mirrors
// management/backend/internal/api/entity_kinds.go. Each build adds its own
// kinds only inside its marked block.
export const ENTITY_ROUTES = {
  host: (key) => `/agents?host=${encodeURIComponent(key)}`,
  user: (key) => `/search?q=${encodeURIComponent(key)}`,
  ip: (key) => `/search?q=${encodeURIComponent(key)}`,
  // [NET-ENTITY-BEGIN]
  device: (key) => `/network/devices/${encodeURIComponent(key)}`,
  observer: (key) => `/network/devices/${encodeURIComponent(key)}`,
  site: (key) => `/network/sites/${encodeURIComponent(key)}`,
  // [NET-ENTITY-END]
  // [APP-ENTITY-BEGIN]
  service: (key) => `/applications/services/${encodeURIComponent(key)}`,
  service_instance: (key) => `/applications/instances/${encodeURIComponent(key)}`,
  route: (key) => `/applications/routes/${encodeURIComponent(key)}`,
  // [APP-ENTITY-END]
}
export const entityHref = (kind, key) => (ENTITY_ROUTES[kind] ? ENTITY_ROUTES[kind](key) : null)
