# Payload capture: design of record

Status: agreed direction, not built. The event lock (OTP before viewing) is on the roadmap and is not part of the first build.

## Principle

Payloads (request and response bodies, query strings) are captured in full by default, but never from a route an admin has not reviewed. Everything else about the service (route statistics, errors, latency, dependencies, security detections, alerts) works from the first request.

## Route lifecycle

1. **Discovered.** The first request to a route template creates the route. The agent records parameter and field names only (never values) and reports them with counts. No payload event leaves the host for this route.
2. **Pending review.** The route shows in the Routes tab as "needs review", with its parameter names (query, form, JSON fields, nested paths such as `user.address.zip`) and the number of requests held back.
3. **Reviewed.** The admin marks fields to mask (or none) and saves. The saved policy is pushed to the agent. From then on the agent forwards payloads for that route with the masked fields removed on the host.
4. **Drift.** A field name that was not present at review time is withheld (treated as masked) until the admin reviews it, and the route shows "new field". A new route template starts at step 1.

## Rules that always apply

- Masking is enforced on the agent. The server never receives a masked value.
- A fixed deny list of names is masked on every route and cannot be unmasked (password, passwd, secret, token, authorization, cookie, api_key, card, cvv, ssn and similar), together with a value-pattern pass for bearer tokens and card numbers.
- Size caps per payload, JSON and form content types only, binary and multipart file contents never captured.
- Retention for payload events is short and set per service (default 7 days).
- Policy changes are audit-logged (who, route, fields, time).

## Constraints from the data source

- OpenTelemetry auto-instrumentation exposes the query string (`url.query`, or `http.target` and `http.url` in older conventions). The agent reads these only to extract parameter names and discards the rest but not request or response bodies.
- Bodies need the application security helper, a framework hook, or a tap at a reverse proxy or WAF. Query-string capture and parameter-name discovery can ship first and need no application change.

## Build order

1. Route parameter-name discovery on the agent, batch format, ingest table and migration, Routes tab "needs review" state. **Built** (query-string names only; form and JSON field names arrive with step 4). Until step 2 exists every route with parameters shows "needs review".
2. Per-route masking policy: API, UI, push to agent, enforcement and held-back counter. **Built** for query-string parameters (see below).
3. Agent-side injection signatures **(built)** on parameters (verdict plus redacted snippet), which also closes the Node A09 gap.
4. Body capture through the helper, a framework hook or a proxy tap.
5. Roadmap: event lock (OTP) before viewing payloads, with every view audit-logged.

## What step 2 does today

- **Review.** Routes tab, Review on a route: tick the parameters to mask, save. Admin only. Every save and revoke is written to `app_route_payload_policy_log` and to the server log.
- **Delivery.** The ingest backend sends each agent the reviewed routes with an allow list (reviewed, not masked, not on the deny list) in the agent-config the agent already polls. An entry that exists only to carry routes is marked `policy_only` and never overrides the service's privacy settings.
- **Enforcement, three times over.** The agent forwards values only for allow-listed names, never a denied name, never a credential-looking value (JWT, bearer or basic credentials, private key, long opaque token, card number), at most 5 samples per route per flush. The ingest API drops denied names and credential-looking values again. The ingest store checks the saved policy a third time and stores nothing for a route without one, whatever an agent sent.
- **Storage and access.** `app_payloads`, 7 days by default (`app.retention_payload_days`). Listing needs the admin role. The OTP event lock is not built; when it exists it should guard the listing endpoint and the Review panel's samples.
- **New fields.** A name that was not among the names the admin saw is withheld, and the route shows "new fields".
- **Revoking** a review deletes the policy; agents stop forwarding on their next config pull (up to 5 minutes), and the ingest store stops accepting immediately.
- **Limits.** Query-string parameters only. Request and response bodies need step 4. Nested names such as `user.address.zip` arrive with bodies.

## What step 3 does today

- The agent scans every query-string value of every request, including routes nobody has reviewed, against signatures for SQL, script (XSS), command, path traversal, template and JNDI injection. Values are decoded up to twice, so double-encoded attacks are still seen.
- A hit is not stored as a value. It becomes the exception type of that request's per-client record (`param.sql-injection` and so on), so rule APP-A09 counts it by client and route and the trace is kept. A request that returned 200 still counts, because an attempt that worked is the worst case.
- This works for any framework that gives the agent `url.query`, which closes the gap where Node produced no injection exceptions.
- Limits: query strings only until body capture exists; a repeated parameter name is judged on its first value; patterns favour few false positives over catching everything, so treat a quiet A09 as not proof of no attack.
