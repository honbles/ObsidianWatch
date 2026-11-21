# Application Monitoring - Node.js setup

Send traces from a Node.js application to the local agent and, optionally, security events. For the full path (agent, traces, request fields and masking, security events, console settings, troubleshooting) see `node-security-guide.md`.

## Before you start
1. The host runs the ObsidianWatch agent built with the **app-server profile** (Agent Builder, "Enable the app-server profile"). The agent then listens on `127.0.0.1:4318` (OTLP over HTTP). gRPC is not supported.
2. The application and the agent run on the same host (or the application uses the agent's Unix socket from a container, see `agent-otlp.md`).
3. You change **no** host or deployment attribute. The agent works out which host, process and container are sending, and discards any `host.*`, `container.*` and `k8s.*` you set.

## What the sample shows
`samples/app/node` is a small application with the routes `/health`, `POST /login`, `/orders/{id}`, `/search` and `/debug/exec`. It is **intentionally vulnerable**: it refuses to start unless `OW_ALLOW_VULN_DEMO=1`, binds `127.0.0.1` only, and must never be deployed. `samples/app/attack_sim.py` drives it through normal traffic, a login brute force, injection attempts, a request burst and a command-execution request, so you can watch the rules fire (`rules.md`: A01, A09, A13, H01, X02). Rules are observe-only until you switch a service to enforce.

## 1. Install
```
npm install @opentelemetry/sdk-node @opentelemetry/exporter-trace-otlp-http @opentelemetry/instrumentation-http @opentelemetry/instrumentation-express @opentelemetry/exporter-logs-otlp-http @opentelemetry/sdk-logs @opentelemetry/api-logs
```

## 2. Configure (traces)
Start the SDK **before** requiring Express (instrumentation patches modules as they load):
```js
const { NodeSDK } = require('@opentelemetry/sdk-node')
const { OTLPTraceExporter } = require('@opentelemetry/exporter-trace-otlp-http')
const { HttpInstrumentation } = require('@opentelemetry/instrumentation-http')
const { ExpressInstrumentation } = require('@opentelemetry/instrumentation-express')
const { Resource } = require('@opentelemetry/resources')
const resource = new Resource({ 'service.name': 'orders-api', 'deployment.environment.name': 'production' })
new NodeSDK({ resource, traceExporter: new OTLPTraceExporter({ url: 'http://127.0.0.1:4318/v1/traces' }),
  instrumentations: [new HttpInstrumentation(), new ExpressInstrumentation()] }).start()
```

## 3. Exception type names (important)
In JavaScript the exception type recorded is the error's `name`, which defaults to `"Error"` even for a subclass. Rules that classify exceptions (A09, injection class) cannot tell a database syntax error from any other error. Set `this.name` in your own error classes (the sample does), and use the security helper's `inputRejected` for anything the framework would not name clearly. This was found while testing the sample.

## 4. Security helper
Copy `samples/app/node/ow-security.js`, call `init(resource, 'http://127.0.0.1:4318/v1/logs')` once, then for example `security.login('failure', { user, client: req.socket.remoteAddress, route: '/login' })`.

## 5. Request fields (optional)
Copy `samples/app/node/ow-payload.js`. Pass `requestHook: payload.requestHook` to `HttpInstrumentation` and add `app.use(payload.middleware())` after `express.json()`. The helper gives the agent the parsed body as one span attribute; nested fields arrive as `address.zip`, arrays as `items[].sku`. The agent forwards field names for every route, and values only after an admin reviews that route (Routes tab, Review). Fields on the deny list, and values that look like credentials, are never forwarded. Multipart and binary bodies are skipped. This needs the agent from this build or later.

## Run the sample
```
cd samples/app/node && npm install
OW_ALLOW_VULN_DEMO=1 node app.js            # port 5002
python3 ../attack_sim.py --base http://127.0.0.1:5002
```

## Checking it works
In the console open **Applications, Services**. Within about a minute you should see the service, its environment, and each route as a **template** (for example `/orders/{id}`), never the raw URL. The instance should say **verified** with the process executable. If it says **asserted**, the agent could not match the sender to a local process (container with its own network namespace, or an agent without the required privilege): use the Unix socket or run the agent in the host pid namespace.

## What is never sent
Headers, response bodies, and parameter or body-field values from any route an admin has not reviewed. Only the parameter and field names are kept, so the console can show which parameters a route takes. Only route templates, status codes, timings, exception type names and the security-event fields below. Identifiers you pass to the helper (user, object id) are hashed by the agent before they leave the host.

## Security helper (optional)
The helper emits events the rules read: `auth.login`, `auth.mfa`, `authz.deny`, `input.rejected`, `ratelimit.hit`, `data.access`, `data.export`, `admin.action`, `session.anomaly`. Call it where your code already makes the decision (login result, validation rejection, rate limiter). It never sends bodies or parameter values. Without it you still get traces, route health and exception-based rules; with it you get login-failure and rejection signals that do not depend on framework error types.

## Proof
`samples/app/verify.sh <port> <command>` starts the agent's real receiver (real process identification), starts the sample, runs `attack_sim.py`, and prints what the receiver decoded: identity, per-route RED, per-client failure counters and security events.

Run on the Linux agent receiver with the real SDK output of this sample: service and environment decoded, identity **verified** (pid and executable), route templates (not raw paths), 25 failed logins counted against `/login`, 6 injection-class exceptions against `/search`, and 32 helper events delivered. Verified with @opentelemetry/sdk-node 0.57 and Express.
