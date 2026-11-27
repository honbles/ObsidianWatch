-- Application records in the event store (app.request, app.payload, app.error, app.operation and the app.*
-- service events) are searched by application: app:<service> in the console compiles to
-- raw->'app'->>'service'. A partial index keeps that fast without touching host events.
CREATE INDEX IF NOT EXISTS idx_events_app_service ON events (((raw->'app'->>'service')), time DESC)
  WHERE event_type LIKE 'app.%';
