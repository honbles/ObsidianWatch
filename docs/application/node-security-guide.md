# Securing a Node.js application with ObsidianWatch

This guide takes a Node.js developer from nothing to every capability the platform offers for an application: routes and health, dependencies, injection detection, login and abuse detection, request fields with masking, and the host-level view. Each step says what you get, what to change and how to check it. Do the steps in order; each one works without the next.

Contents: 1 What you get, 2 Agent, 3 Level 1 traces (path A manual SDK or path B auto-instrumentation), 4 Level 2 request fields, 5 Level 3 security events, 5b Jobs and consumers, 6 Console setup, 7 Review and masking, 8 Detections, 9 Other frameworks, 10 Containers, 11 What leaves the host, 12 Verify, 13 Troubleshooting, 14 Checklist.

## 1. What you get at each level

| Level | You add | You get |
|---|---|---|
| 0 | the agent with the app-server profile (install it, change nothing in the app) | the service is discovered from the host: listening ports, container, image, connections, process starts (Tier 0). No code change. |
| 1 | OpenTelemetry traces | route templates and their health (calls, errors, latency), dependencies, query-string field names, injection signatures on query values, error and traffic alerts. |
| 2 | `ow-payload.js` | request body field names for every route, and values for routes an admin has reviewed. Mass-assignment and body-borne injection detection. |
| 3 | `ow-security.js` | login success and failure, authorization denials, input rejections, rate-limit hits: the events the login-abuse and authorization rules read. |

Levels 1 to 3 together make a Tier 1 or Tier 2 service. Without level 3 you still get traces, route health and exception-based detections.

## 2. The agent

1. In the console open Agent Builder and tick **Enable the app-server profile**. Build and install the agent on the host that runs the application. The agent then listens on `127.0.0.1:4318` (OTLP over HTTP, protobuf or JSON). gRPC is not supported. The agent never listens on a routable address.
2. The application and the agent must run on the same host (or share the agent's Unix socket, section 10).
3. Do **not** set `host.*`, `container.*` or `k8s.*` attributes. The agent works out which host, process and container are sending, and discards what you set.
4. Check: `curl -s -o /dev/null -w '%{http_code}\n' -X POST -H 'Content-Type: application/json' -d '{}' http://127.0.0.1:4318/v1/traces` prints an HTTP status (any), not `000`.

A rebuilt agent is needed for new capabilities (request fields, injection signatures). Per-service settings and review decisions are pulled by the agent every 5 minutes and do not need a rebuild.

## 3. Level 1: traces

OpenTelemetry has to be started **before** your framework is loaded, so it is not part of your app code. It goes in a small file that Node loads first with `--require`. There are two ways to get that file. Pick one.

- **Path A, manual SDK.** You add one file, `instrumentation.js`, that lists exactly what to instrument.
- **Path B, auto-instrumentation.** You add no file to your code at all. You install one package and set environment variables. Use this when you cannot or do not want to edit the app, or want every library instrumented.

Both give the same data. Path A is more explicit; path B needs nothing but a start command. If you will also use level 2 (request fields), read section 4 before choosing: it needs one small file on path B too.

### Path A: manual SDK

**Files you end up with** (your project root is the folder that holds `package.json`):

```
your-app/
├── package.json          CHANGED: new dependencies and a new "start" script
├── instrumentation.js    NEW: starts OpenTelemetry (code below)
└── app.js                UNCHANGED at level 1 (your existing entry file)
```

**1. Install**, from the project root:

```
npm install @opentelemetry/sdk-node @opentelemetry/exporter-trace-otlp-http \
  @opentelemetry/instrumentation-http @opentelemetry/instrumentation-express @opentelemetry/resources
```

**2. Create `instrumentation.js`** next to `package.json` with this content. Change the three values marked below.

```js
const { NodeSDK } = require('@opentelemetry/sdk-node')
const { OTLPTraceExporter } = require('@opentelemetry/exporter-trace-otlp-http')
const { HttpInstrumentation } = require('@opentelemetry/instrumentation-http')
const { ExpressInstrumentation } = require('@opentelemetry/instrumentation-express')
const { Resource } = require('@opentelemetry/resources')

new NodeSDK({
  resource: new Resource({
    'service.name': 'orders-api',                       // CHANGE: your service's name; the console groups by it
    'deployment.environment.name': 'production',        // CHANGE: production, staging, test ...
    'service.version': process.env.APP_VERSION || '0',  // CHANGE: your release version (lets the console show deploys)
  }),
  traceExporter: new OTLPTraceExporter({ url: 'http://127.0.0.1:4318/v1/traces' }),
  instrumentations: [new HttpInstrumentation(), new ExpressInstrumentation()],
}).start()
```

**3. Make Node load it first.** You never run `instrumentation.js` yourself, and your app never imports it. Node loads it before your app because of the `--require` flag, and it keeps running inside the same process. In `package.json` change the start script:

```json
"scripts": {
  "start": "node --require ./instrumentation.js app.js"
}
```

Then start the app the way you always do (`npm start`). Putting the file in the root folder is **not** enough on its own; the flag is what loads it. Where the flag goes depends on how you start the app:

| You start the app with | Put this |
|---|---|
| `npm start`, or `node app.js` by hand | `node --require ./instrumentation.js app.js` (in the `start` script, or typed in full) |
| systemd | `ExecStart=/usr/bin/node --require ./instrumentation.js app.js` with `WorkingDirectory=` set to the project root |
| Docker | `CMD ["node", "--require", "./instrumentation.js", "app.js"]`, and make sure `instrumentation.js` is copied into the image |
| pm2 | `pm2 start app.js --node-args="--require ./instrumentation.js"` |
| a process manager you cannot change | set the environment variable `NODE_OPTIONS=--require ./instrumentation.js` for the process |
| `nodemon`, `ts-node`, a build step | `nodemon --require ./instrumentation.js app.js`; for TypeScript compile first and point `--require` at the compiled `.js` file |

If your project uses ES modules (`"type": "module"` in `package.json`), `--require` does not instrument imports. Use the OpenTelemetry ESM loader (`node --import ./instrumentation.mjs --experimental-loader=@opentelemetry/instrumentation/hook.mjs app.js`). That setup is not covered or tested here.

### Path B: auto-instrumentation (no file in your code)

**Files you end up with:** none new. `package.json` changes only by one dependency and the start command. Nothing is added to your source.

**1. Install**, from the project root:

```
npm install @opentelemetry/auto-instrumentations-node @opentelemetry/api @opentelemetry/sdk-node
```

**2. Set these environment variables for the app process.** They are settings of the process, not code, and they do not go in any `.js` file:

```
OTEL_SERVICE_NAME=orders-api
OTEL_RESOURCE_ATTRIBUTES=deployment.environment.name=production,service.version=1.4.2
OTEL_EXPORTER_OTLP_ENDPOINT=http://127.0.0.1:4318
OTEL_EXPORTER_OTLP_PROTOCOL=http/protobuf
OTEL_TRACES_EXPORTER=otlp
OTEL_METRICS_EXPORTER=none
OTEL_LOGS_EXPORTER=none
OTEL_NODE_ENABLED_INSTRUMENTATIONS=http,express
```

**Optional: runtime metrics.** To see event loop delay, heap, CPU and connection pools on the service's Metrics tab and get the saturation alert (APM-O07), set `OTEL_METRICS_EXPORTER=otlp` instead of `none` and add `@opentelemetry/instrumentation-runtime-node` (and the database instrumentation, which reports pool usage). The agent keeps only an allowlist of runtime and pool metrics (names starting `process.`, `nodejs.`, `v8js.`, `jvm.`, `dotnet.`, `db.client.connection`), at most 100 series per instance, with attributes limited to states and pool names; everything else is dropped and counted. Exponential histograms are not accepted: use explicit-bucket histograms.

`http/protobuf` matters: the agent does not accept gRPC. `OTEL_NODE_ENABLED_INSTRUMENTATIONS=http,express` keeps the traces focused; leave it out to instrument everything (databases, Redis and so on), which also gives you more dependency data.

Where the variables go depends on how the app starts:

| You start the app with | Where the variables go |
|---|---|
| a terminal, for a quick test | `export OTEL_SERVICE_NAME=...` lines in the same shell, then start the app |
| systemd | `Environment=OTEL_SERVICE_NAME=orders-api` lines, or `EnvironmentFile=/etc/orders-api.env` containing the lines above |
| Docker | `ENV` lines in the Dockerfile, or `environment:` in docker-compose, or `docker run -e ...` |
| pm2 | the `env:` block of `ecosystem.config.js` |
| a `.env` file | `node --env-file=.env --require ... app.js` (Node 20.6 or newer). A `dotenv` call inside your app is too late: the SDK has already started |

**3. Start the app through the OpenTelemetry register file**, using the same places as in the table in path A:

```
node --require @opentelemetry/auto-instrumentations-node/register app.js
```

That is the whole change: no `instrumentation.js`, no edit to `app.js`.

### What decides the quality of the data

- **Route templates.** The console shows `/orders/:id`, never `/orders/1234`. That comes from the Express instrumentation reading `req.route`. A request that matched no route is counted as `(unmatched)`. If you see raw paths or an "other" bucket, the framework is not instrumented (section 9). A service is limited to 500 distinct routes; beyond that routes collapse into "other" and the Endpoints tab says so.
- **Exception type names.** JavaScript records the error's `name`, which is `"Error"` for most subclasses. Detections that classify exceptions cannot tell a database syntax error from any other error. Set `this.name = 'SqlSyntaxError'` (or similar) in your own error classes, and use `security.inputRejected` (level 3) where the framework would not name the problem.
- **Query strings.** The agent reads `url.query` (or `http.target` on older instrumentations). Field names are kept for every route. Values are scanned in memory for injection signatures (SQL, script, command, path traversal, template, JNDI; double-encoded values included). Only the class label (`param.sql-injection`) leaves the host, as the exception type of that request's per-client record. A request that returned 200 still counts, because an attempt that worked is the worst case.
- **Client address.** Behind a load balancer every request comes from the proxy. Add the proxy's address to the service's **Trusted proxies** in the console (section 6) so the real client is counted. Without it the finding is marked degraded.

**Check.** Send a few requests to the app, wait one to two minutes. In **Applications, Services** the service appears with its environment; the **Endpoints** tab lists templates; **Instances** says **verified** with the node process. If it says **asserted** the agent could not match the sender to a local process (container with its own network namespace): use the Unix socket (section 10).

## 4. Level 2: request fields

What it adds: the names of the fields in JSON and form bodies, per route, so the console can show what a route accepts, and optional capture of reviewed values. It also lets the agent spot injection and mass-assignment (a field such as `role` appearing on a registration route) in bodies.

The helper hands your **parsed** body to the agent on this host as one span attribute. It does not read or buffer the raw stream, needs only `@opentelemetry/api` (already installed with the SDK), and never throws into your request. It takes three steps on both paths: create a helper file, give the HTTP instrumentation its hook, and add one line to your app after the body parser.

**Files you end up with:**

```
your-app/
├── ow-payload.js         NEW: the helper (code below, copy it as it is)
├── instrumentation.js    CHANGED on path A: the hook is added (shown below)
├── ow-instrument.js      NEW on path B only: replaces the register flag (code below)
├── package.json          CHANGED on path B only: the start flag
└── app.js                CHANGED: one `require` and one `app.use` line
```

**Step 1. Create `ow-payload.js`** in the project root, next to `package.json`, with exactly this content. (It is also in the repository at `samples/app/node/ow-payload.js`, but you do not need the repository: copy it from here.)

```js
'use strict'
// ObsidianWatch request-field helper for Node (optional, Express or any framework with a parsed body).
// It hands the PARSED request body to the local agent as one span attribute. The agent decides what
// leaves the host: field names always, values only for routes an admin has reviewed, never fields on the
// deny list (password, token, card ...). Nothing is sent anywhere except the agent on this host.
//
// Use:
//   const payload = require('./ow-payload')
//   new HttpInstrumentation({ requestHook: payload.requestHook })   // remembers the server span
//   app.use(express.json()); app.use(payload.middleware())          // after body parsing

const { trace } = require('@opentelemetry/api')

const MAX_BYTES = 32 * 1024
const SPAN = Symbol('ow.serverSpan')

// HttpInstrumentation requestHook: keep the server span, which is the one the agent reads.
function requestHook(span, request) {
  try { if (request && request.headers) request[SPAN] = span } catch (_) { /* never affect the app */ }
}

// Record a parsed body for a request. Works for any framework: pass the raw Node request (Fastify:
// request.raw, Koa: ctx.req) and its parsed body object.
function record(req, body) {
  try {
    const span = (req && req[SPAN]) || trace.getActiveSpan()
    const ct = String(req && req.headers && req.headers['content-type'] || '')
    if (span && body && typeof body === 'object' && !/multipart|octet-stream/i.test(ct)) {
      const s = JSON.stringify(body)
      if (s && s.length <= MAX_BYTES) span.setAttribute('ow.request.body', s)
    }
  } catch (_) { /* observability must never break a request */ }
}

// Express (or anything that sets req.body): use after the body parser.
function middleware() {
  return function owPayload(req, _res, next) {
    record(req, req.body)
    next()
  }
}

module.exports = { requestHook, middleware, record }
```

**Step 2. Give the HTTP instrumentation the hook.** The agent reads the HTTP *server* span; the hook remembers it so the helper can attach the body to it.

- **Path A.** Edit `instrumentation.js`. Add the `require` line at the top and replace `new HttpInstrumentation()` in the `instrumentations` list:

  ```js
  const payload = require('./ow-payload')
  // ...
  instrumentations: [new HttpInstrumentation({ requestHook: payload.requestHook }), new ExpressInstrumentation()],
  ```

- **Path B.** Create `ow-instrument.js` in the project root. It does what the register file did, plus the hook:

  ```js
  const { NodeSDK } = require('@opentelemetry/sdk-node')
  const { getNodeAutoInstrumentations } = require('@opentelemetry/auto-instrumentations-node')
  const payload = require('./ow-payload')

  new NodeSDK({
    instrumentations: [getNodeAutoInstrumentations({
      '@opentelemetry/instrumentation-http': { requestHook: payload.requestHook },
    })],
  }).start()
  ```

  Then start with `--require ./ow-instrument.js` **instead of** `--require @opentelemetry/auto-instrumentations-node/register`. The environment variables stay exactly as they are; this file reads them.

**Step 3. Edit your app file.** Open the file where you create the Express app (usually `app.js`, `server.js` or `src/index.js`, the one that has `const app = express()`). Add the `require` near the top and the `app.use` line **after** the body parsers and **before** your routes:

```js
const express = require('express')
const payload = require('./ow-payload')            // ADD: path matches where you saved the file

const app = express()
app.use(express.json())                             // your existing body parsers
app.use(express.urlencoded({ extended: false }))
app.use(payload.middleware())                       // ADD: after the parsers, before the routes

app.post('/signup', (req, res) => { /* your routes, unchanged */ })
```

If the helper is placed before the parsers, `req.body` is still empty when it runs and nothing is reported. If your project keeps source under `src/`, save `ow-payload.js` there and adjust the `require` path (for example `require('./ow-payload')` from `src/app.js`), but keep `instrumentation.js` or `ow-instrument.js` where your start command points.

If you cannot edit the app, `samples/app/juice-kit/ow-juice-preload.js` shows how to do step 3 from a preload by wrapping Express's `app.use`; it is written for Juice Shop's parser names and needs adapting to yours.

**How fields are reported.** Nested names are flattened (`address.zip`), an array contributes the shape of its first element (`items[].sku`), at most 4 levels, 50 names per request, 32 KB per body. Multipart and binary bodies are skipped. Query-string and body fields are merged per route.

For other frameworks call `payload.record(rawRequest, parsedBody)` after parsing (section 9).

**Check.** Restart the app, send a POST with a JSON body, wait a minute. The route's **Parameters** column lists the body field names. If a POST route says "no query or body fields seen" the helper is not wired: the hook was not passed, the middleware runs before the parser, or the agent is older than this feature. This setup was run end to end here against Express 4.21 with the SDK 0.57 packages (path A) and the current auto-instrumentation package (path B): the body arrived on the server span.

## 5. Level 3: security events

What it adds: events the rules cannot infer from HTTP status alone (login result, authorization denial, rejected input, rate-limit hit). You call a function at the places where your code already makes that decision.

**Files you end up with:**

```
your-app/
├── ow-security.js        NEW: the helper (code below, copy it as it is)
├── package.json          CHANGED: three more dependencies
└── app.js                CHANGED: init once at startup, then calls in your handlers
```

**1. Install:**

```
npm install @opentelemetry/api-logs @opentelemetry/sdk-logs @opentelemetry/exporter-logs-otlp-http @opentelemetry/resources
```

**2. Create `ow-security.js`** in the project root with exactly this content. It works with OpenTelemetry SDK logs 0.x and 1.x. (It is also in the repository at `samples/app/node/ow-security.js`.)

```js
'use strict'
// ObsidianWatch security helper for Node (optional). Emits the security events the Application rules
// read as OpenTelemetry log records to the local agent. Pass identifiers only, never request bodies,
// parameter values or headers (the agent drops them anyway).
// init() works with sdk-logs 0.x and 1.x; OW_SECURITY_CONSOLE=1 echoes events to stdout for debugging.
const { logs, SeverityNumber } = require('@opentelemetry/api-logs')
const { LoggerProvider, BatchLogRecordProcessor } = require('@opentelemetry/sdk-logs')
const { OTLPLogExporter } = require('@opentelemetry/exporter-logs-otlp-http')

const HELPER_VERSION = 'js-2'
let logger = null

// sdk-logs 0.x processors take (exporter, config); newer ones take ({ exporter, ...config }). Build whichever works.
function makeProcessor(Cls, exporter, config) {
  const legacy = new Cls(exporter, config)
  if (legacy && legacy._exporter) return legacy
  return new Cls(Object.assign({ exporter }, config))
}

function init(resource, endpoint) {
  const processors = [makeProcessor(BatchLogRecordProcessor, new OTLPLogExporter({ url: endpoint }), { scheduledDelayMillis: 1000 })]
  if (process.env.OW_SECURITY_CONSOLE === '1') { // print each security event to stdout as well (debugging)
    const { SimpleLogRecordProcessor, ConsoleLogRecordExporter } = require('@opentelemetry/sdk-logs')
    processors.push(makeProcessor(SimpleLogRecordProcessor, new ConsoleLogRecordExporter(), {}))
  }
  let provider
  if (typeof LoggerProvider.prototype.addLogRecordProcessor === 'function') { // sdk-logs 0.x
    provider = new LoggerProvider({ resource })
    processors.forEach((p) => provider.addLogRecordProcessor(p))
  } else { // sdk-logs 1.x and later: processors go in the constructor
    provider = new LoggerProvider({ resource, processors })
  }
  logs.setGlobalLoggerProvider(provider)
  logger = provider.getLogger('obsidianwatch.security', HELPER_VERSION)
  return provider
}

function emit(eventName, attrs = {}) {
  if (!logger) return
  const attributes = { 'event.name': eventName, helper_version: HELPER_VERSION }
  for (const [k, v] of Object.entries(attrs)) if (v !== undefined && v !== null && v !== '') attributes[k] = String(v)
  logger.emit({ severityNumber: SeverityNumber.WARN, severityText: 'WARN', body: eventName, attributes })
}

// One helper per event name the agent accepts. Attribute names are the ones the agent keeps
// (docs/application/capability.md 4.3); anything else is dropped on the host. user, session and
// object_id are pseudonymised by the agent unless the service is set to cleartext users.
const c = (client) => ({ 'client.address': client })
module.exports = {
  init, emit, HELPER_VERSION,
  login: (outcome, { user, client, route, method, reason, mfa } = {}) =>
    emit('auth.login', { outcome, user, route, method, reason, mfa, ...c(client) }),
  mfa: (outcome, { user, client, route, method, reason } = {}) =>
    emit('auth.mfa', { outcome, user, route, method, reason, ...c(client) }),
  authzDenied: (resourceType, action, { user, route, client, policy } = {}) =>
    emit('authz.deny', { resource_type: resourceType, action, user, route, policy, ...c(client) }),
  inputRejected: (kind, { route, parameter, client } = {}) =>
    emit('input.rejected', { kind, route, parameter, ...c(client) }),
  ssrfBlocked: (targetHost, { route, client, reason } = {}) =>
    emit('ssrf.blocked', { target_host: targetHost, route, reason, ...c(client) }),
  deserializationBlocked: (typeName, { route, client } = {}) =>
    emit('deserialization.blocked', { type_name: typeName, route, ...c(client) }),
  rateLimited: (limitName, { route, client, user } = {}) =>
    emit('ratelimit.hit', { limit_name: limitName, route, user, ...c(client) }),
  adminAction: (action, { user, targetType, targetId, outcome = 'success', route, client } = {}) =>
    emit('admin.action', { action, user, target_type: targetType, target_id: targetId, outcome, route, ...c(client) }),
  dataExport: (objectType, { user, format, rows, bytes, route, client } = {}) =>
    emit('data.export', { object_type: objectType, user, format, rows, bytes, route, ...c(client) }),
  dataAccess: (objectType, objectId, { user, action = 'read', route, client } = {}) =>
    emit('data.access', { object_type: objectType, object_id: objectId, user, action, route, ...c(client) }),
  sessionAnomaly: (kind, { user, session, reason, route, client } = {}) =>
    emit('session.anomaly', { kind, user, session, reason, route, ...c(client) }),
}
```

**3. Initialise it once at startup,** near the top of `app.js` (after the `require` lines, before the routes). The `service.name` and environment must match what you set at level 1, because the console joins events to the service by them:

```js
const security = require('./ow-security')
const res = require('@opentelemetry/resources')
const attrs = {
  'service.name': process.env.OTEL_SERVICE_NAME || 'orders-api',          // same as level 1
  'deployment.environment.name': 'production',                            // same as level 1
}
const resource = res.resourceFromAttributes ? res.resourceFromAttributes(attrs) : new res.Resource(attrs)
security.init(resource, 'http://127.0.0.1:4318/v1/logs')
```

**4. Call it where your code decides.** Use the **route template** (`/invoices/:id`), not the raw URL. Example login handler:

```js
app.post('/login', async (req, res) => {
  const user = await findUser(req.body.email, req.body.password)      // your own code
  security.login(user ? 'success' : 'failure', {
    user: req.body.email,                       // hashed by the agent before it leaves the host
    client: req.socket.remoteAddress,           // or the address your proxy forwards, once trusted
    route: '/login',
  })
  if (!user) return res.status(401).json({ error: 'invalid credentials' })
  res.json({ ok: true })
})

// authorization decision
security.authzDenied('invoice', 'read', { user: req.user.id, route: '/invoices/:id', client: req.socket.remoteAddress })
// validation or WAF-style rejection
security.inputRejected('sqli', { route: '/search', parameter: 'q', client: req.socket.remoteAddress })
// your rate limiter
security.rateLimited('login', { route: '/login', client: req.socket.remoteAddress })
```

Every event name the agent accepts has its own function: `security.mfa`, `dataAccess`, `dataExport`, `adminAction`, `sessionAnomaly`, `ssrfBlocked`, `deserializationBlocked` besides the four above (table in [capability.md](capability.md) section 4.3), or call `security.emit('<event>', { ... })`. Pass identifiers and short labels only, never bodies, parameter values or headers; the agent drops them anyway. User, session and object identifiers are hashed by the agent before they leave the host.

Set `OW_SECURITY_CONSOLE=1` in the app's environment to echo each event to the app's standard output while you test.

**Check.** Log in wrongly a few times. Within a minute or two the service's **Security** tab shows the events. Note that APP-A01 counts 401 and 403 responses from traces (level 1), not these helper events: 20 or more from one client in 5 minutes raise it.

## 5b. Jobs and message consumers (optional)

What it adds: scheduled jobs and queue consumers appear on the service's **Jobs and queues** tab with runs, failures, duration and last run. A job that ran on a steady cadence and then stops raises APM-O10; a job that fails often raises APM-O11 (both start in observe mode).

- **Queue consumers** need nothing from you: instrumentations for Kafka, RabbitMQ, SQS and similar report consumer spans, and the agent groups them by messaging system, queue or topic and operation (ids in names become `?`).
- **Scheduled jobs:** copy `ow-jobs.js` (also at `samples/app/node/ow-jobs.js`) next to `package.json` and wrap the function. It needs only `@opentelemetry/api`.

```js
const { job } = require('./ow-jobs')
const nightly = job('nightly-report', async () => { /* the work */ })
setInterval(nightly, 10 * 60 * 1000)   // or your cron library: cron.schedule('*/10 * * * *', nightly)
```

Use a stable name without ids. A job needs five runs before its cadence is learned, and an alert needs it to be three usual intervals late (and at least five minutes). Only the name leaves the host.

## 6. Console setup for the service

Open the service, **Settings**:

- **Exposure**: internet, internal or unknown. When left at unknown the console infers it from the client addresses it has seen (public addresses mean internet) and shows the reason. Internet-facing raises detection severity by one level.
- **Criticality** and **data sensitivity**: raise severity for services that matter.
- **Trusted proxies**: the addresses of your load balancer or reverse proxy, so the real client is used.
- **Login routes**, **export routes**, **public routes**: list the route templates. With no login route configured, routes that look like a login (`login`, `signin`, `/token`, `/auth`) are used.
- **Client address storage**: full, truncated (/24, /48) or off.
- **Error budget** and **latency target**: drive the error-rate and slow-trace thresholds.

Changes reach the agent within 5 minutes.

## 6a. Declare your API before traffic (OpenAPI)

You do not have to wait for traffic to learn a route's fields. If the application has an OpenAPI or Swagger document, load it: **Applications, Services, the service, Routes, API spec, Load a spec**. Upload the `.json` or `.yaml` file, or give a URL.

- **Getting a document.** Many frameworks generate one: `@nestjs/swagger` (served at `/api-json`), `swagger-jsdoc` or `express-oas-generator` for Express, FastAPI (`/openapi.json`), Spring springdoc (`/v3/api-docs`), ASP.NET Swashbuckle (`/swagger/v1/swagger.json`), flask-smorest. Open the URL in your browser and save the file if the management server cannot reach the application.
- **URL fetch.** The management server fetches the URL itself, so it must be reachable from that server, not from your browser. Loopback and link-local addresses are refused.
- **What is read.** Each path and method, the path, query and header parameter names, and the request-body fields, with nested names such as `securityQuestion.id` and arrays as `items[].sku`. Never examples or defaults. Cookie parameters are skipped. The server path (`/api/v1`) is added in front of each path; use the **Path prefix** box if the application serves a different prefix.
- **What you see.** Declared routes appear as "declared, no traffic yet" and can be reviewed and masked straight away; the agent applies the review as soon as requests arrive. Declared fields not yet seen are shown dashed. When traffic arrives the two are merged (a route written `/users/{id}` joins the observed `/users/:id`).
- **Undocumented fields.** A field seen in traffic that the spec does not list for a route it does list is marked **undocumented** (amber). That is a common sign of mass assignment, for example `role` on a registration route. Routes seen in traffic that the spec does not list are marked **not in spec**.
- **Limits.** Path parameter names that differ between the spec and the framework (`{productId}` against `:id`) still merge, because routes are compared by shape, but a review saved before traffic is applied by the agent only when the route template matches in name too; review again after traffic if the agent keeps withholding. External `$ref` files are not followed. Header and path fields are listed for completeness; the agent does not capture header values.

## 7. Review and masking of request fields

Capture is off by default for values. The lifecycle of a route:

1. **Discovered**: the agent reports field names only. The Endpoints tab shows the names and **needs review**. Everything else about the route works normally.
2. **Review**: an admin opens **Review** on the route (a page of its own). Every field is listed with how many requests carried it. Tick the fields to mask and save. Names such as password, token, secret, authorization, cookie, card, cvv, ssn and otp are always masked and cannot be unticked.
3. **Reviewed**: the policy reaches the agent within 5 minutes. From then the agent forwards the values of fields you left unmasked, up to 5 sampled requests per route per 30 seconds, with status, latency and trace id.
4. **New fields**: a field name that was not on the reviewed list is withheld and the route shows **new fields** until it is reviewed again. A `role` field appearing on a registration route is the typical case.
5. **Revoke** deletes the policy; capture stops at the agent on its next pull and at the server immediately.

Rules that hold whatever an admin chooses: credential-looking values (JWT, bearer or basic credentials, private keys, long opaque tokens, card numbers) are never forwarded, even in a field you left unmasked. The agent, the ingest API, the ingest store and the management API each enforce this independently. Captured samples are kept 7 days by default and are visible to admins only; every save and revoke is audit-logged.

The route page lists every captured request (paged, filter by status), with latency, fields, withheld fields and a link to the trace. The **Events** tab also shows "Request samples" (field names only). Alerts and traces link back to their route's page.

Not captured today: response bodies, and request headers.

## 8. Detections you get

| Rule | Needs | Fires when |
|---|---|---|
| APP-A01 login failure burst | level 1 (401/403 responses; helper events are not read) | 20 or more failures from one client in 5 minutes |
| APP-A09 injection attempts | level 1 (query), level 2 (body) | 3 or more injection-class requests from one client on one route in 5 minutes |
| APP-A13 rate-limit abuse | level 1 (429) | 50 or more 429 responses for one client in 5 minutes |
| APP-A08 new route | level 1 | a route first seen after the learning period |
| APM-O01 error budget | level 1 | error rate above budget over 10 minutes |
| APM-O03 traffic drop, APM-O05 instance silent | level 1 | traffic falls 80 percent, or one instance stops reporting |
| APP-H01..H11 host rules | level 0 | shell from a service process, outbound tools, new web-directory scripts, new destinations, credential reads |
| APP-X02 | levels 0 and 1 | a shell from the service within 15 minutes of an injection alert or 5xx spike: Critical |

All rules start in **observe** mode: alerts are raised at Info until an administrator promotes the rule. Severity then rises with exposure and criticality, and is capped at Medium while the telemetry identity is only **asserted**. Rules and allowlists are tuned per service. See `configuration-platform.md` (rule settings) and `capability.md` (the rule table).

## 9. Other frameworks

| Framework | Routes (level 1) | Request fields (level 2) |
|---|---|---|
| Express | `@opentelemetry/instrumentation-express` | `payload.middleware()` after the body parser. Verified with Juice Shop. |
| Fastify | `@opentelemetry/instrumentation-fastify` | `fastify.addHook('preHandler', async (req) => payload.record(req.raw, req.body))`. Not yet tested. |
| Koa | `@opentelemetry/instrumentation-koa` | `app.use(async (ctx, next) => { payload.record(ctx.req, ctx.request.body); await next() })` after the body parser. Not yet tested. |
| NestJS | the instrumentation of its HTTP adapter (Express or Fastify) | an interceptor or the adapter's hook above. Not yet tested. |
| Plain `http`, Next.js | `@opentelemetry/instrumentation-http` gives a route only if you set `http.route` on the span yourself | `payload.record(req, body)` |

For every framework the helper needs `HttpInstrumentation({ requestHook: payload.requestHook })`, because the agent reads the HTTP **server** span.

## 10. Containers and Kubernetes

The application and the agent share a loopback only when they share a network namespace. For a container with its own namespace, point the exporter at the agent's Unix socket (`app_monitoring.otlp.socket`), mounted into the container; the agent identifies the sender from the socket's peer credentials. On Kubernetes run the agent as a DaemonSet and share a hostPath socket with the pods. Docker with the published port (Juice Shop on `-p 3000:3000`) is seen through `docker-proxy`; the console folds that into the real service and shows the container name and image under **Runtime**.

## 11. What leaves the host

| Data | Leaves the host? |
|---|---|
| Route templates, status codes, timings, exception type names | yes, aggregated every 30 seconds |
| Query-string and body field **names** | yes |
| Field **values** | only for reviewed routes and unmasked fields, never credential-like names or values |
| Injection signature class (`param.sql-injection`) | yes, as a label; the value does not |
| Latency distribution per route per minute: a compact sketch of bin numbers and counts, no request data | yes |
| Where a route's time goes: per route, the slowest downstream calls as a kind (database, HTTP, queue), a target (`postgresql`, `payments`) and a span-name template with ids and numbers replaced by `?` | yes, at most 20 per route per flush |
| Database calls: system, operation (`SELECT`) and table names, with counts, errors and timings | yes, at most 200 distinct per service per flush |
| Database statement | **never raw**. Off by default. When an admin sets the service to "statement fingerprints", the agent strips every literal first (strings, numbers, `IN` lists, comments) and sends only that shape, up to 512 bytes, such as `select * from users where id = ?` |
| Errors: exception type, route, and up to 30 stack frames (function plus a short file path and line; no column, no arguments), grouped by a fingerprint, with a count per 30-second flush and one sample | yes, at most 100 groups per service per flush |
| Error message | **off by default**. If an admin sets the service to "masked message", the agent replaces numbers, quoted text, emails, uuids and long tokens with `?` first |
| Runtime and pool metrics: CPU, memory, event loop delay, heap, garbage collection, connection pool use, per instance per minute (last, min, max, average) | yes, allowlisted names only, at most 100 series per instance; attributes are limited to states and pool names |
| Trace sampling counters: per service and reason, how many traces were completed and how many were kept | yes, two numbers per reason |
| Jobs and consumers: name (job name, or messaging system, queue or topic and operation, ids replaced by `?`), runs, failures, duration sketch, last run | yes, at most 100 names per service; no message content or arguments |
| Span self time and the N+1 flag | yes, numbers and a flag |
| Request headers, response bodies, raw URLs | never |
| User, session, object identifiers from the security helper | hashed by the agent first |
| Client address | per the service's storage mode |

The application sends everything to the agent on the same host. Only the agent talks to the management server, over its existing outbound HTTPS connection.

## 12. Verify end to end

Run the sample that ships with the repo, which is deliberately vulnerable and refuses to start without `OW_ALLOW_VULN_DEMO=1` and binds to `127.0.0.1` only:

```
cd samples/app/node && npm install
OW_ALLOW_VULN_DEMO=1 node app.js
python3 ../attack_sim.py --base http://127.0.0.1:5002
```

Or run Juice Shop with the kit in `samples/app/juice-kit` (README there): `setup`, `start`, `attack`, then `python3 ow-juice-requests.py bodies`. Expect, within a few minutes: the service with a verified instance; routes as templates; `POST /rest/user/login` with a high 401/403 count and its body fields; APP-A01 and APP-A09 alerts at Info; request samples after you review a route and the agent pulls the policy.

## 13. Troubleshooting

| Symptom | Likely cause and fix |
|---|---|
| Service never appears | agent not built with the app-server profile; nothing on `127.0.0.1:4318`; exporter using gRPC (set `http/protobuf`); SDK started after the framework was required |
| Raw paths or an "other" route bucket | the framework is not instrumented, so there is no `http.route`; section 9 |
| Instance says **asserted** | the agent could not match the sender to a local process; use the Unix socket or run the agent in the host pid namespace |
| POST route shows "no query or body fields seen" | level 2 not wired: hook not passed, middleware before the body parser, agent older than this feature, or a multipart body |
| Route shows fields but no Review link | it has no fields. Routes with no query or body fields have nothing to review |
| Reviewed route shows no captured requests | wait up to 5 minutes after saving (the agent pulls the policy), send traffic again, check the status filter and time range; fields that are all masked produce only "withheld" |
| A field shows **new fields** after review | it appeared after the review. Open Review and save again |
| APP-A01 or APP-A09 never fires | rules start in observe mode (Info); few requests; the service has no login route configured and none looks like one; a proxy hides the client (add trusted proxies) |
| Injection alerts but no exception names | expected in Node: errors are named `Error`. The agent detects injection from the parameter values themselves |
| Errors tab empty or every error is one group | the app is not recording exceptions on spans (set the span status and call `span.recordException(err)` for errors you catch yourself). Unnamed classes all report `Error`, so groups are told apart by the stack frames; an error with no stack groups by type and route only, so throw real `Error` objects |
| Error stack frames are all library code | the app's own frames are filtered out only by path (`node_modules` and Node internals are treated as libraries); bundlers that put your code into one file under `node_modules` or a minified path will look like library frames |
| Security tab empty | level 3 not wired, or the logs exporter is pointed at the wrong path (`/v1/logs`) |
| Client address is the load balancer | add it to Trusted proxies |

## 14. Checklist

- [ ] Agent built with the app-server profile and running on the application's host
- [ ] `service.name` and `deployment.environment.name` set; `service.version` set from your build
- [ ] OpenTelemetry started before the framework; OTLP over HTTP to `127.0.0.1:4318`
- [ ] Routes appear as templates; instance is **verified**
- [ ] `ow-payload.js` wired after the body parser; POST routes list their field names
- [ ] Your own error classes set `this.name`
- [ ] `ow-security.js` called from login, authorization, validation and rate-limit code
- [ ] Console: exposure, criticality, trusted proxies, login routes set
- [ ] Routes that take sensitive input reviewed and masked; admins know samples are visible to admins only
- [ ] Rules promoted out of observe mode once the baselines have learned (7 days)
