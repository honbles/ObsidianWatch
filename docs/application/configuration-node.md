# Application monitoring: Node.js

Connect a Node.js application (Express, Fastify, Koa, NestJS, plain `http`) to the local ObsidianWatch agent. The long step-by-step guide with copy-ready helper files is [node-security-guide.md](node-security-guide.md); this page is the reference and lists where that guide and the code differ.

Verified: the Express sample (Express 4.21, OpenTelemetry SDK 0.57) and OWASP Juice Shop with `samples/app/juice-kit` ran against the agent's real Linux receiver.

## Prerequisites

- An ObsidianWatch agent built with the app-server profile on the same host ([deployment.md](deployment.md)), listening on `127.0.0.1:4318`.
- Node.js 18 or later. OpenTelemetry must start before the framework is loaded (`--require`).

## Steps: manual SDK (path A)

```
npm install @opentelemetry/sdk-node @opentelemetry/exporter-trace-otlp-http \
  @opentelemetry/instrumentation-http @opentelemetry/instrumentation-express @opentelemetry/resources
```

`instrumentation.js`:

```js
const { NodeSDK } = require('@opentelemetry/sdk-node')
const { OTLPTraceExporter } = require('@opentelemetry/exporter-trace-otlp-http')
const { HttpInstrumentation } = require('@opentelemetry/instrumentation-http')
const { ExpressInstrumentation } = require('@opentelemetry/instrumentation-express')
const { Resource } = require('@opentelemetry/resources')

new NodeSDK({
  resource: new Resource({
    'service.name': 'orders-api',
    'deployment.environment.name': 'production',
    'service.version': process.env.APP_VERSION || '0',
  }),
  traceExporter: new OTLPTraceExporter({ url: 'http://127.0.0.1:4318/v1/traces' }),
  instrumentations: [new HttpInstrumentation(), new ExpressInstrumentation()],
}).start()
```

Start: `node --require ./instrumentation.js app.js` (or `NODE_OPTIONS=--require ./instrumentation.js`). With `@opentelemetry/resources` 2.x use `resourceFromAttributes({...})` instead of `new Resource({...})`.

## Steps: auto-instrumentation (path B)

```
npm install @opentelemetry/auto-instrumentations-node @opentelemetry/api @opentelemetry/sdk-node
```

```
OTEL_SERVICE_NAME=orders-api
OTEL_RESOURCE_ATTRIBUTES=deployment.environment.name=production,service.version=1.4.2
OTEL_EXPORTER_OTLP_ENDPOINT=http://127.0.0.1:4318
OTEL_EXPORTER_OTLP_PROTOCOL=http/protobuf
OTEL_TRACES_EXPORTER=otlp
OTEL_METRICS_EXPORTER=none
OTEL_LOGS_EXPORTER=none
node --require @opentelemetry/auto-instrumentations-node/register app.js
```

`OTEL_NODE_ENABLED_INSTRUMENTATIONS=http,express` limits instrumentation; leaving it out also instruments database and HTTP clients, which gives dependency and query data.

ES modules (`"type": "module"`) need the OpenTelemetry ESM loader. Not covered or tested.

## What is captured automatically

| Data | Source | Notes |
|---|---|---|
| Routes, RED, status classes | HTTP server span with `http.route` | the Express, Fastify and Koa instrumentations set it; plain `http` and Next.js do not, so their requests are `(unmatched)` unless you set `http.route` yourself |
| Query-string field names, injection signatures | `url.query` or `http.target` | |
| Dependencies, queries, N+1 | client spans from `pg`, `mysql2`, `mongodb`, `ioredis`, `undici`/`http` clients and others | queries and N+1 counts: defect D1 |
| Message consumers | CONSUMER spans from `kafkajs`, `amqplib`, AWS SDK SQS | defect D1 |
| Error groups | `exception` events with V8 stacks (`at f (file.js:N:C)`) | frames under `node_modules/` and `node:` internals are library frames. Defect D1 |
| Instance identity | the `node` process | verified |

## What needs manual work

- **Exception names.** Most JavaScript errors report the type `Error`, so APP-A09 cannot tell a SQL syntax error from others. Set `this.name = 'SqlSyntaxError'` in your own error classes. The agent's parameter-value signatures still catch injection in query strings and helper bodies.
- **Request body fields.** `ow-payload.js` (`samples/app/node/ow-payload.js`) with `HttpInstrumentation({ requestHook: payload.requestHook })` and `app.use(payload.middleware())` after the body parsers. Fastify: `payload.record(req.raw, req.body)` in a `preHandler` hook; Koa: `payload.record(ctx.req, ctx.request.body)`. Bodies up to 32 KiB are read.
- **Jobs.** `ow-jobs.js` wraps a function: `const nightly = job('nightly-report', async () => {...})`. Each run is a root span with `ow.job.name`. Defect D1 currently prevents delivery.
- **Metrics.** `OTEL_METRICS_EXPORTER=otlp` plus `@opentelemetry/instrumentation-runtime-node` gives `nodejs.eventloop.delay.p99`, `v8js.memory.heap.used` and `v8js.memory.heap.limit`, which feed the runtime summary and APM-O07. Use explicit-bucket histograms. Defect D1 currently prevents delivery.

## Security helper (optional, Tier 2)

`ow-security.js` (`samples/app/node/ow-security.js`) needs `@opentelemetry/api-logs`, `@opentelemetry/sdk-logs`, `@opentelemetry/exporter-logs-otlp-http`. Call `security.init(resource, 'http://127.0.0.1:4318/v1/logs')` once with the same `service.name` and environment as the traces, then call the function for the event: `security.login`, `mfa`, `authzDenied`, `inputRejected`, `ssrfBlocked`, `deserializationBlocked`, `rateLimited`, `adminAction`, `dataExport`, `dataAccess`, `sessionAnomaly` (table in [capability.md](capability.md) section 4.3), or `security.emit('<event>', {...})`. Helper version `js-2`; all eleven events were run against the real receiver and stored. `OW_SECURITY_CONSOLE=1` echoes events to stdout.

The events fill the Security tab and make the service Tier 2. Unlike what the Node guide says (section 1 and 5, "20 or more failures from one client in 5 minutes raise APP-A01"), **no rule reads helper events today**: APP-A01 counts 401/403 responses on login routes from the request statistics. Return 401 or 403 on a failed login.

## Containers

For a container with its own network namespace, mount the agent's Unix socket into it. The OTLP HTTP exporter has no documented socket option; use a local forwarder. Over TCP from another network namespace the agent cannot identify the process, so the instance stays **asserted**. Docker with a published port and `--network host` work over loopback.

## Verify

```
cd samples/app/node && npm install
OW_ALLOW_VULN_DEMO=1 node app.js                        # port 5002
python3 ../attack_sim.py --base http://127.0.0.1:5002
```

Then **Applications → Services**, the **Endpoints** tab (templates such as `/orders/:id`), and **Instances** (verified). The sample is intentionally vulnerable and must never be deployed. Juice Shop: see `samples/app/juice-kit/README.md`.

## Troubleshooting

| Symptom | Cause and fix |
|---|---|
| Service never appears | SDK started after Express was required (use `--require`); exporter set to gRPC; wrong URL (`/v1/traces` needed with `url:`) |
| Raw paths or many routes then `other` | no `http.route` (framework not instrumented) |
| Every error is `Error` in one group | unnamed error classes; groups are then told apart by stack frames, and by type and route when there is no stack |
| POST route shows no fields | hook not passed, middleware before the body parser, multipart body, or body JSON over 32 KiB |
| Security tab empty | helper not initialised or logs URL wrong |
