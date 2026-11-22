# Application Monitoring - read API (management backend, `/api/v1/app/*`)

All routes are authenticated like the rest of `/api/v1`; viewers are read-only. `from` / `to` are RFC3339
(default: last 24 h, maximum range 90 days, `from` must precede `to`). Times are UTC.

| Route | Purpose |
|---|---|
| `GET /services` | Services active in the range: tier (0 discovered, 1 OTel, 2 OTel plus security-helper events in the last 14 days), live instance count, versions/edges/routes counts, settings, and a `red` summary (omitted when there was no traffic). Filters `q`, `environment`, `limit`. |
| `GET /services/{id}` | One service: instances (identity `verified`/`asserted`), versions, edges, settings. |
| `PUT /services/{id}/settings` | **Admin only.** Exposure, criticality, data sensitivity, owner, trusted proxies, login/export/public routes, latency target, error budget, maintenance windows, client-IP mode. `reset_learning: true` restarts the learning clock. |
| `GET /services/{id}/red` | RED time series: calls, errors, 2xx / 401-403 / 429 / 5xx, p50/p95/p99. `step` (seconds, multiple of 60, widened automatically so a series never exceeds 2000 points), `route` + `method` filter. Also returns `totals`. |
| `GET /services/{id}/openapi`, `POST` (`{spec}` or `{url}`, optional `base_path`), `DELETE` | **Admin only.** The service's declared API (OpenAPI 3.x or Swagger 2.0, JSON or YAML, 5 MB). A URL is fetched by the management server; loopback and link-local addresses are refused. |
| `GET /services/{id}/payloads` | **Admin only.** Captured requests of reviewed routes: `route`, `method`, `status` (`200` or `2xx`..`5xx`), `limit` (max 200), `offset`; returns `total` and `has_more`, with latency and trace id. |
| `GET /services/{id}/routes` | Route inventory with per-route RED for the range. Routes with no traffic in the range are listed with `active: false`. With a spec loaded, each route has `declared`, `observed` and `not_in_spec`, declared-only routes are included, and each field has `source` (observed, declared, both), `location` and `undocumented`. |
| `GET /services/{id}/edges` | Dependencies seen in the range with `range_calls` / `range_errors` (hourly resolution) beside the cumulative `calls` / `errors`; `new` marks edges first seen inside the range. |
| `GET /map` | Estate dependency graph: services (resolved from `peer.service`), databases, queues, external hosts; calls/errors in the range (hourly resolution); `new` flag; `reachable_from_internet` per service. |
| `GET /overview` | Posture and changes for the Overview page. |
| `GET /services/{id}/alerts`, `/events` | Alerts linked to the service entity; `app.security` events (filter `event_name`). |
| `GET /instances/{id}` | Resolves a `service_instance` entity key to its service. |
| `GET /traces` | Sampled traces (no spans): `service_id`, `route`, `status` (ok/error), `reason` (error/slow/security/baseline), `min_duration_ms`, `limit`. |
| `GET /traces/{trace_id}` | One trace with its spans. Traces are kept for 7 days. |

**Percentiles** are estimated from 12 histogram buckets (upper bounds 5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000,
10000 ms, then open-ended) by linear interpolation. When a percentile falls in the open-ended bucket the API returns
10000 with `over_range: true` rather than inventing a figure.

**Batch ingest** (agent only, ingest backend): `POST /api/v1/app/batch`; see `agent-otlp.md`.

**Agent endpoints (ingest backend, API-key authenticated):** `POST /api/v1/app/batch` and `GET /api/v1/app/agent-config?agent_id=` (per-service settings; registered agents only).
