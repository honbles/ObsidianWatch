# Application Monitoring - UI (`/applications`)

Pages live in `management/frontend/src/pages/app/*.route.jsx`. Each file exports `default` (the page) and `appPath`
(its route); `App.jsx` registers them with `import.meta.glob` inside the `[APP-ROUTES]` marker, so no import line outside the
marker was needed. If you prefer explicit imports, replace that block with one `<Route>` per file.

| Route | Page |
|---|---|
| `/applications` | Overview: coverage, exposure, open alerts by service, what changed, deploys, services needing attention |
| `/applications/services` | Services list with filters; admins can bulk-set exposure and criticality (current settings are merged, never wiped) |
| `/applications/services/:key` | Service detail (`:key` is a numeric id or the entity key `name\|environment`). Tabs via `?tab=`: overview, routes, dependencies, instances, security, traces, alerts, settings. Deep links: `&trace=<id>`, `&route=<template>`, `&instance=<id>` |
| `/applications/map` | Dependencies: estate map with filters (environment, internet-reachable, new in range), exposure paths, edge table |
| `/applications/coverage` | What each service tells us and what is missing for the next tier |
| `/applications/settings` | Per-service tuning and learning status, rule catalogue |
| `/applications/instances/:id`, `/applications/routes/:key` | Entity-chip targets; redirect into the service detail. Route key: `name\|environment\|METHOD /template` |

Learning (spec 10.1 defaults): a service is "ready" after at least 7 days **and** 1000 requests since learning started;
after 7 days with fewer requests it shows "Learning, low traffic".

Components for other pages: `components/app/AppHostApplications.jsx` takes `{agentId}` (mount on the host page).
Time range, tables and states use the shared `useTimeRange`, `DataTable`, `StateBlock`.

## Tiers and Coverage
T0: discovered from the host only (listening ports, connections, process starts). T1: OpenTelemetry received. T2: OpenTelemetry plus security-helper events received in the last 14 days. There is no T3. A service shows "not set up" on Coverage for whatever it lacks, and a T0 service has no request baseline, so its Learning column reads "Host only" instead of a request count.
