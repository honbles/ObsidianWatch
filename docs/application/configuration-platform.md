# Application monitoring: server and console configuration

Settings that live on the server: per-service settings, what the agents pull from them, review of request fields, API specs, detection rules, and retention. Agent-side build options are in [deployment.md](deployment.md). How each value is used is in [capability.md](capability.md).

Roles: viewers read everything except captured request samples and API specs; analysts can also triage error groups; admins change everything below.

## 1. Per-service settings

Where: service page → **More → Settings** tab. Also reachable from **Applications → Settings** (click a service). Saving needs the admin role.
API: `PUT /api/v1/app/services/{id}/settings` (admin). The body replaces the whole settings object: a field you leave out goes back to its default. The console always sends every field.

Settings are stored in `service_settings` in the management database. A service with no saved settings uses the defaults and is not listed in what agents pull (section 2).

| Field (UI label) | JSON key | Values | Default | Used by |
|---|---|---|---|---|
| Exposure | `exposure` | `internet`, `internal`, `unknown` | `unknown` | alert weighting (+1 for internet), dependency map reachability. With `unknown` the console infers a value from the client addresses of failed requests in the last 7 days and shows the reason |
| Criticality | `criticality` | `low`, `normal`, `high`, `critical` | `normal` | alert weighting (+1 for high and critical) |
| Data sensitivity | `data_sensitivity` | `normal`, `sensitive`, `regulated` | `normal` | shown only; no rule reads it |
| Owner | `owner` | text ≤ 128 | empty | shown |
| Operational notification route | `notify_route` | text ≤ 256 | empty | appended to the body of APM-O alerts as "Notification route: ..." (no message is sent) |
| Client IP storage | `store_client_ip` | `full`, `truncated`, `off` | `full` | agent client-address mode (pulled; stricter of build and console wins) |
| (cleartext user ids) | `cleartext_users` | bool | false | agent sends helper user, session and object ids unhashed |
| Trusted proxies | `trusted_proxies` | IPs or CIDRs, ≤ 200 | empty | A01, A09, A13: the forwarded client address is used only when the direct peer is in this list |
| Login routes | `login_routes` | route templates, ≤ 200 | empty | A01. When empty, routes containing `login`, `signin`, `sign-in`, `/token` or `/auth` count |
| Export routes | `export_routes` | route templates | empty | shown and tagged; no rule reads it today |
| Public routes | `public_routes` | route templates | empty | A08 notes that authentication is not expected |
| Latency target (ms) | `latency_target_ms` | 0–600 000 | none | agent slow-trace threshold (pulled), Apdex, latency SLO |
| Error budget (%) | `error_budget_pct` | 0–100 | none | APM-O01 threshold (else 5 %); availability SLO target = 100 − budget (else 99.9 %) |
| Maintenance windows | `maintenance` | list of `{start, end, reason}`, ≤ 50 | none | silences APM-O rules and APP-X06 while open |
| Database statements | `db_statement_mode` | `off`, `fingerprint` | `fingerprint` | agent sends literal-free statement fingerprints (pulled) |
| Error messages | `error_message_mode` | `off`, `masked` | `off` | agent sends scrubbed error messages (pulled) |
| Ordinary traces kept (%) | `sampling.baseline_pct` | 0–100 | agent default (1) | agent baseline sampling (pulled) |
| Error traces per minute (max) | `sampling.error_max_per_min` | 0–100 000 (0 = no cap) | 0 | agent (pulled) |
| Traces per flush (max) | `sampling.max_per_flush` | 0–5 000 (0 = 500) | 0 | agent (pulled) |
| Availability target (%) | `slo.availability_target_pct` | > 0 and < 100 | 100 − error budget, else 99.9 | SLO tab, APM-O13 |
| Latency target share (%) | `slo.latency_target_pct` | > 0 and < 100 | 95 | SLO tab, APM-O13 (needs a latency target) |
| Window | `slo.window_days` | 7 or 28 | 28 | SLO tab, APM-O13 |
| Restart learning | `reset_learning` | bool (input only) | – | sets `learning_started` to now: first-seen rules and learning-based rules start over |

Validation errors come back as HTTP 400 with a message such as `trusted_proxies must be CIDRs or addresses`.

**Bulk edit.** On **Applications → Services** an admin can select several services and set exposure and criticality in one step. The console reads each service's settings and sends them back with the two fields changed.

Implemented in: `management/backend/internal/api/app_services.go`, `app_exposure.go`, `app_slo.go`; `management/frontend/src/components/app/AppServiceSettingsForm.jsx`; migrations `060`, `064`/`066`, `067`, `068`, `069`.

## 2. What reaches the agents

Agents pull `GET /api/v1/app/agent-config` from the ingest backend 2 s after start and then every 5 minutes. A change saved in the console takes effect on each agent within about 5 minutes, without a rebuild.

Pulled per service: `store_client_ip`, `cleartext_users`, `latency_target_ms`, `db_statement_mode`, `error_message_mode`, `sampling`, and the reviewed routes with their allowed field names.

Rules applied by the agent:

- Client address: the stricter of the build value (`client_ip_default` or `client_ip_by_service`) and the pulled value. You can make it stricter from the console, never looser than the build.
- Cleartext user ids: the pulled value decides when the service has saved settings; otherwise the build list `cleartext_services`.
- Statement fingerprints, error messages and sampling are applied only for services with saved settings. A service that has a reviewed route but no saved settings gets its reviewed routes and nothing else.
- Allowed field names are filtered again through the always-masked list.

Until the first successful pull, and whenever pulling fails, the build configuration alone applies (no fingerprints, no messages, default sampling, no payload values).

Every agent receives the settings and reviewed routes of all services, not only its own.

Implemented in: `backend/internal/api/app_agentconfig.go`, `backend/internal/store/app_store.go` (`AppRemoteConfig`), `agents/linux/internal/otel/remoteconfig.go`, `service.go`.

## 3. Request fields: review, masking, capture

The agent always reports the names of query-string and helper-body fields per route. It sends values only for routes an admin has reviewed.

**Single route.** Service page → **Endpoints** → a route with fields → **Review**. The review page lists every field with its request count and state. Tick the fields to mask and save. Unticked fields are approved. Always-masked names cannot be unticked. API: `PUT /api/v1/app/services/{id}/payload-policy`.

**Revoke.** On the review page, or `DELETE /api/v1/app/services/{id}/payload-policy?route=<route>&method=<METHOD>`. The server stops storing values at once; the agent stops sending after its next pull.

**Bulk.** On the Endpoints tab the review bar offers "Approve all":

```
POST /api/v1/app/services/{id}/payload-policy/bulk
{"scope": "needs_review" | "needs_review_and_new_fields", "mode": "capture" | "names_only"}
{"routes": [{"method": "POST", "route": "/signup"}], "mode": "capture" | "names_only"}
```

`capture` approves every field except the always-masked ones. `names_only` marks the route reviewed with every field masked, so no value leaves the host. Existing masks are kept. At most 1 000 routes per request. Each route is audit-logged.

**Captured samples.** Route review page, or `GET /api/v1/app/services/{id}/payloads` (admin). At most 5 samples per route per agent flush. Kept 7 days (`app.retention_payload_days`).

States you will see: `needs_review` (fields, no review), `reviewed`, `new_fields` (a field appeared after the review; it is withheld until you review again). Per field: `always_masked`, `pending`, `new`, `masked`, `captured`.

Implemented in: `app_payload_policy.go`, `app_payload_bulk.go`, `app_payload_names.go`; frontend `pages/app/AppRouteReview.route.jsx`, `tabs/AppTabRoutes.jsx`.

## 4. API specification (OpenAPI)

Service page → **Endpoints** → **API spec** → **Load a spec**. Upload a JSON or YAML file, or give a URL the management server can reach (loopback and link-local addresses are refused). Optional path prefix (`base_path`) when the application serves a different prefix from the spec's server URL. Admin only.

```
POST   /api/v1/app/services/{id}/openapi   {"spec": "<text>"} or {"url": "https://..."}, optional "base_path"
GET    /api/v1/app/services/{id}/openapi
DELETE /api/v1/app/services/{id}/openapi
```

Effects: declared routes appear before traffic and can be reviewed straight away; observed routes the spec lacks are flagged "not in spec"; observed fields the spec lacks on a declared route are flagged undocumented. Limits: 5 MB, 500 routes, 100 fields per route, depth 4; no external `$ref`.

A review saved on a declared route in `{id}` style is sent to agents in both `{id}` and `:id` style. If the framework uses a different parameter name (`{productId}` against `:id`), the agent will not match it; review again after traffic arrives.

Implemented in: `app_openapi.go`, `app_openapi_parse.go`.

## 5. Detection rules: observe mode, promotion, tuning, allowlists

All 27 application rules (APP-H, APP-A, APP-X, APM-O) start in **observe mode**: the alert is created with severity Info and its body says "Mode: observe". The rule list is visible on **Applications → Settings** and **Applications → Coverage**; neither page can change a rule.

To promote, disable, tune or allowlist a rule, an admin calls the rule settings API of the management backend:

```
GET /api/v1/rules/meta          rule catalogue with tunables and defaults
GET /api/v1/rules/settings      saved settings
PUT /api/v1/rules/settings      save one setting (admin)
```

Body of `PUT`:

```json
{
  "rule_id": "APP-A01",
  "scope_kind": "service",
  "scope_id": "orders-api|production",
  "enabled": true,
  "observe": false,
  "params": {"threshold": 30, "window_min": 5},
  "allowlist": ["10.0.0.0/8", "203.0.113.7"]
}
```

- `scope_kind` empty and `scope_id` empty set the rule for all services. A service row (`"service"`, `"<service.name>|<environment>"`) overrides it for that service. Host-wide findings of APP-H11 use only the global row.
- **Always send `"enabled": true`** unless you want to disable the rule; a missing `enabled` is saved as false.
- A row replaces the whole setting at its scope: include every param and allowlist entry you want to keep.
- Allowlist entries match case-insensitively, or as a CIDR for addresses. What is compared depends on the rule: client addresses (A01, A09, A13), process names and `parent>child` pairs (H01), tool names (H02), paths (H03, H07), destinations and IPs (H04, H05, H06), privilege change values (H08), routes (A08).
- The tunable keys and defaults per rule are in the table in [capability.md](capability.md) section 11.2.

Severity after promotion: base severity, +1 internet-facing, +1 high or critical criticality, −1 degraded input, capped at Medium when the identity is asserted. APM-O rules are not weighted.

Implemented in: `management/backend/internal/api/rule_gate.go`, `rule_meta_handlers.go`, `app_rules_meta.go`, `app_rules_core.go`.

## 6. Learning

Rules that compare with "what the service did while learning" (H04, H06, H08, A08) wait until the learning period is over: 7 days since the service was first seen (or since "Restart learning"), plus 200 recorded outbound destinations for H04/H06 and 1 000 requests for A08. O03, O06, O08 and O13 wait 24 hours; O14 and the weekly baseline of O03 need about three weeks. While waiting, Coverage counts the rule as skipped with reason "learning".

Use **Restart learning** after a large change (new architecture, migration) so the first-seen rules do not treat everything as new.

## 7. Retention

The management backend purges application data at start and every 6 hours. Values are read from the `settings` table of the management database; there is no console control or API for them. Set them in SQL, for example:

```sql
INSERT INTO settings (key, value) VALUES ('app.retention_trace_days', '14')
ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value;
```

| Key | Default (days) | Data |
|---|---|---|
| `app.retention_stats_days` | 90 | per-minute route statistics, hourly dependency statistics, sampling counters, jobs, slow downstream calls, database statistics, N+1 counts, runtime metrics, hourly error counts; error groups not seen for that long |
| `app.retention_trace_days` | 7 | sampled traces |
| `app.retention_client_days` | 7 | per-client failure counters (also the input of exposure inference) |
| `app.retention_payload_days` | 7 | captured request samples |

Non-numeric or non-positive values fall back to the default. Service, instance, route, dependency, version and field-name inventories are kept.

If `backend_db` is a different database from the management database, the purge cannot find the application tables and logs `app retention purge failed` (see [capability.md](capability.md) defect D5).

Implemented in: `management/backend/internal/store/app_retention.go`, `management/backend/cmd/server/main.go`.

## 8. Error group triage

Service page → **Errors** → a group. Set status (`open`, `resolved`, `ignored`) and assignee. Admin and analyst roles.

```
PATCH /api/v1/app/errors/{id}   {"status": "resolved", "assignee": "alice"}
```

Resolving records the version the group last failed in. A later failure in a different version reopens it as regressed (APM-O09). Ignored groups never raise APM-O08. Groups of a service that does not set `service.version` never regress.
