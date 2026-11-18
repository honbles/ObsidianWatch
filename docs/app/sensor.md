# Application Monitoring - host runtime sensor (Linux)

Part of the **app-server profile** (Agent Builder → "Enable the app-server profile"); off unless selected. It is the agent's
`internal/ebpf` package, started from `app_monitoring.ebpf` (`enabled`, `mode`, `poll_interval`, `environment`, `watch_dirs`, `secret_files`).

## What it reports
Only activity **under a service**: a process whose lineage contains a known service process (a process found listening on a port, or one
that sends OpenTelemetry). Everything else is dropped at the source. Events are ordinary `process` / `network` / `file` events with
`source` = the tier that saw them, `pid` and `ppid`, and the `raw.proc` block the detection rules read (`docs/app/rules.md`). They enter the
agent's **normal event channel** (normaliser, own-activity filter, rate limiter) through the same non-blocking path as `app.security` events.
A per-second budget (300 events) protects the host; drops are counted.

## Tiers (`mode: auto` takes the best that works)
| Tier | Mechanism | Needs | Gaps |
|---|---|---|---|
| `ebpf` | kernel programs (`internal/ebpf/bpf/sensor.bpf.c`), build tag `ebpf` | root, BTF kernel, `github.com/cilium/ebpf`, clang to build | **Not built or tested yet** - see `bpf/README.md`. IPv4 only, `openat` only, `setuid` only |
| `procevent` | netlink proc connector (exec, uid change) + `/proc` polling for connections and listeners + fanotify for files | root in the host pid namespace | connections shorter than the poll interval (2 s) can be missed; a short-lived file writer can exit before it is identified |
| `poll` | `/proc` polling only | nothing (works in containers) | processes or connections that start and end between two polls are missed |

fanotify (file events) needs `CAP_SYS_ADMIN`; where refused the sensor runs without file events and logs why. It watches the default web roots
(`/var/www`, `/srv/www`, nginx html, tomcat webapps) and `watch_dirs` to a depth of 3 (500 directories), for close-after-write, and credential
files (`/etc/shadow`, SSH keys, cloud credentials, `secret_files`) for opens. Marks are on inodes, so the cost is tiny.

## Discovery (Tier 0)
A process with a listening TCP socket that is not a known system daemon is a **discovered service**. Its name comes from what an operator would
call it - the jar, script, module or DLL - never a pid (`internal/ebpf/naming.go`); workers that inherit the listening socket count once. It is
reported as an instance with `source = discovered`, `instrumented = false`, the listening ports and the sensor tier, and appears at Tier 0.
When the same process later sends OpenTelemetry, the instances are **merged by process (agent + pid + start time), not by name**: the
instrumented service keeps the instance, the learned baselines, the analyst's settings and the earlier first-seen date (so learning is not restarted),
and the discovered service is removed.

## Privacy
Command lines are redacted on the host before leaving it (`--password=…`, `--token …`, `KEY=…`, `://user:pw@`, `Bearer …`). The Linux agent had no
redaction of its own, so this is new code (`internal/ebpf/redact.go`); extend `sensitiveWords` for your environment.

## Where it shows
Service detail → **Runtime** (instances with listening ports and sensor tier, and the host activity under the service); Coverage (hosts per
tier, hosts that only poll); detection rules H01–H08 and H11.
