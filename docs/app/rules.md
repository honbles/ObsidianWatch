# Application Monitoring - detection rules (v1)

Eighteen rules, all **observe by default**: a new rule creates its alert but shows it as Info until an administrator
promotes it (Rules settings, `observe = false`). Every rule is enabled/disabled, tuned and allowlisted per service
(`rule_settings`, scope kind `service`, scope id `name|environment`) through `/api/v1/rules/settings`.

## How they run
- **Events** (process, network, file): the foundation's engine calls every registered signature provider once per event,
  after its own-agent-activity filter. `appTap` is registered as one; it returns no signatures and queues the event for the rule
  worker (bounded, non-blocking; drops are counted on the Coverage page).
- **Aggregates**: every minute the worker scans `app_client_stats`, `app_route_stats`, `service_routes` and `service_instances`.
- **Alerts** are created by `CreateAlertDeduped` after `ruleGate` (enabled / observe / allowlist) and the severity weighting below.
  They do not use the engine's signature path, whose severity is static and whose dedup is one alert per host per hour.
- Alert `event_id` is `app:<RULE-ID>:<key>` (the dedup key), the title starts `[<RULE-ID>]`, and the alert is linked to its
  entities: `service`, `service_instance`, `route` (`name|env|METHOD /template`), `host`, `ip` (client address), `user`.

## Severity (spec 10.1)
Base severity per rule, then: **+1** if the service is internet-facing, **+1** if its criticality is high or critical (cap Critical);
**-1** when an input was degraded (e.g. no process ancestry, requests arriving only through an unconfigured proxy); capped at
**Medium** when the telemetry's identity is `asserted`. Operational (APM) rules are not weighted. Observe mode then shows Info.

## Learning and deploys
First-seen rules (H04, H06, H08, A08) alert only after the service has been learning for at least `min_days` (7) **and** has
`min_samples` observations (200 outbound connections, 1000 requests); until then they record into `app_baselines` and stay quiet.
A **deploy window** (default 30 min) opens when a new version appears or an instance restarts while the host ran a package manager;
H03, H04, A08, X06 and O05 are suppressed (and counted as skipped) inside it.

| Rule | Tier | Fires when | Default |
|---|---|---|---|
| APP-H01 | host | a shell/interpreter with no terminal is a descendant of the service's process; **Critical follow-on** if it then connects out or writes a file within 5 min | High |
| APP-H02 | host | curl/wget/nc/… run by a descendant of the service process | High |
| APP-H03 | host | script or executable-permission file created in a web/upload directory, not in a deploy window | High |
| APP-H04 | host | first connection to a destination (DNS name, else /24) not seen while learning | Medium (Low if the domain is known) |
| APP-H05 | host | connection to a public IP with no preceding DNS lookup, or a threat-intel hit (High) | Medium |
| APP-H06 | host | cloud metadata endpoint contacted by a service that did not do so while learning | Medium |
| APP-H07 | host | read of credential/secret files (shadow, ssh keys, cloud credentials, another process's environ) by a non-system reader | High |
| APP-H08 | host | setuid/capability change not in the learned baseline | High |
| APP-H11 | host | mount / namespace / runtime-socket signal from a process that is not the container runtime | Critical |
| APP-A01 | T1 | at least 20 login failures (401/403) from one client address in 5 min | High |
| APP-A08 | T1 | a route first seen after learning, outside a deploy window | Low |
| APP-A09 | T1 | at least 3 injection-class exceptions from one client on one route in 5 min | Medium |
| APP-A13 | T1 | at least 50 rate-limited (429) responses for one client in 5 min | Medium |
| APP-X02 | cross | H01/H02 in a service within 15 min of an A09 alert or a 5xx spike on the same service | Critical |
| APP-X06 | cross | no telemetry for 10 min after real traffic while the service's process is still active and the host is up | Medium |
| APM-O01 | T1 | error rate above the service's error budget (default 5 %) over 10 min, per service or route | High |
| APM-O03 | T1 | traffic 80 % below the usual rate for the window | High |
| APM-O05 | T1 | an instance stopped reporting while the host is up and other instances report | High |

Client address (A01/A09/A13): a forwarded address is used only when the direct peer is in the service's trusted proxies. With no trusted
proxy and every request arriving from a private peer, the peer is counted and the finding is marked **degraded**.
When a service has no login routes configured, routes that look like one (`login`, `signin`, `/token`, `/auth`) are used; with none
recognised A01 is skipped and counted.

## Host event contract (`raw.proc`) - what the eBPF sensor must send
Host events keep their normal types (`process`, `network`, `file`) with `source = "ebpf"` and:

    "raw": {"proc": {
      "ancestors": [{"pid":1234,"name":"java","exe":"/usr/bin/java"}],   // nearest parent first
      "tty": false, "container_id": "<64 hex>",
      "priv_change": {"kind":"setuid|cap","detail":"0"},                 // process events
      "escape": "mount|setns|runtime_socket",                            // any event
      "dns": "api.example.com", "prior_dns": true,                       // network events
      "op": "create|write|read|open|rename", "mode": "0755"              // file events
    }}

Every event also carries `pid` and `ppid`, so the agent's own-activity filter and the lineage match work. Without `ancestors`
(the existing polling collectors) only a direct child of the service process is recognised and the finding is marked degraded.

## Known limits
- X02 needs the application anomaly first and the host execution second; the reverse order is not correlated.
- The H01 follow-on watch is in memory (lost on a backend restart); everything else is stored.
- `CreateAlertDeduped` also applies the foundation's host weighting, so an observe-mode alert on a critical host can show as Low rather than Info.
- Not in v1: H09, H10, H12–H14, A02–A07, A10–A12, A14, A15, X01, X03–X05, O02, O04.
