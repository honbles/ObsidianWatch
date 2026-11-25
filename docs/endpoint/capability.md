# Endpoint capability

This page describes, end to end, what the endpoint agents capture on each OS, how events reach the server, how they are checked and stored, how detections and alerts are produced, and what an analyst can do from there (investigate, hunt, respond). It states known limits plainly. Counts were taken from the code, not estimated.

Status labels used below:

- **Verified (Linux)**: run end to end on a real Linux host with the real binaries.
- **Unit-tested**: built and covered by tests, not run on a real host of that OS.
- **Not verified**: neither.

The Windows and macOS agents have been cross-compiled and unit-tested only. macOS is a preview: detective only, built on `eslogger` and polling.

---

## 1. Data flow at a glance

```
collectors ─► normaliser + enricher ─► rate limiter ─► on-disk queue ─► HTTPS POST /api/v1/events (agent certificate)
                                                                         │
backend: certificate check ─► batch checks ─► field caps ─► INSERT events (dedupe on id,time) ─► agents registry
                                                                         │
management: detection engine (woken by each ingested batch, 10 s fallback) · alert-rule engine (30 s) · health engine (60 s) · threat-intel sync (24 h)
                                                                         │
                                         alerts ─► Alerts, graph, incidents, email/syslog/webhook
analyst ─► Events / Search / Hunt ─► Response (actions, live response) over the agent tunnel
```

---

## 2. Collectors per OS

### 2.1 Summary table

| Telemetry | Linux | Windows | macOS |
|---|---|---|---|
| Process start and exit | eBPF kernel sensor (exec with argv, exit); proc connector plus `/proc` poll when eBPF cannot load | Sysmon event 1/5 when running, else Security 4688/4689 (the agent enables the auditing), else ETW Kernel-Process | `sysctl` poll (2 s) plus `eslogger` exec stream when Full Disk Access is granted |
| Command line | yes (argv copied in the kernel with eBPF) | Sysmon or 4688 (enabled by the agent); ETW reads it from the running process | yes |
| Executable SHA-256 | yes (files up to 16 MiB) | Sysmon hashes; agent adds SHA-256 for written files up to 100 MiB | yes |
| Parent process | PPID, parent exe, parent GUID | Sysmon | PPID |
| Network connections | eBPF outbound TCP connects with PID (every attempt); `/proc/net` diff for the rest | iphlpapi table diff with PID; Sysmon event 3 | `netstat` diff, `lsof` for PID |
| DNS names | rarely (see 2.2) | DNS-Client/Operational channel; Sysmon event 22 | `tcpdump` on port 53 (no PID) |
| File integrity | inotify, no writer | ReadDirectoryChangesW, no writer; Sysmon file events carry the process | BSM audit pipe with PID, kqueue fallback |
| Persistence locations | config monitor (inotify) | registry watchers; Sysmon 12/13/14 | config monitor (kqueue) |
| Logs | journald | Event Log channels, Sysmon | unified log (`log stream`) |
| USB | sysfs poll (10 s) | no collector | `system_profiler` poll (15 s) |
| Software install/remove | dpkg log only | no | no |
| Containers | Docker socket | no | no |
| Vulnerability and posture scan | every 5 days | every 5 days | every 5 days |
| Location | IP (ipinfo.io) | IP; GPS/Wi-Fi only if enabled | IP |
| Health heartbeat | 60 s | 60 s | 60 s |
| App log tailing | no | yes (`app_logs`) | no |
| Live response and response actions | yes (opt-in) | yes (opt-in) | yes (opt-in) |
| Tamper event on stop | yes | yes | yes |

### 2.2 Linux

Implemented in: `agents/linux/internal/collector/*`, `agents/linux/cmd/agent/main.go`.

| Collector | Mechanism | What is captured | Limits |
|---|---|---|---|
| Process (`process.go`, `process_bpf_linux.go`) | Kernel tier: an eBPF program (`bpf/proc.bpf.c`, embedded as a prebuilt CO-RE object) on `sched_process_exec`, `sched_process_exit` and `sock/inet_sock_set_state`. Fallback when it cannot load (no BTF, not root, `OW_DISABLE_EBPF=1`): netlink proc connector plus a `/proc` scan every `poll_interval` | `event_type=process`, source `ebpf` or `proc`, action `exec` or `exit`, pid, ppid, name, command line, argv (copied in the kernel, up to 1 KiB, `argv_truncated` when longer), exe path, uid, user name, `parent_exe`, `parent_name`, `process_guid` and `parent_process_guid` (boot id + pid + start time, from the kernel), `cgroup_id`, `exit_code` on exit, `sha256` (by path when the process already exited), `pkg_verified` and `pkg_name`. With eBPF, outbound TCP connects are `network` events with action `connect`, source `ebpf`, and the connecting pid | With eBPF, short-lived processes are captured. In fallback mode an exec is dropped when `/proc/<pid>` is gone before it is read. Executables over 16 MiB are not hashed. Severity is Info. Health reports `process_sensor` (`ebpf` or `proc-connector`). Live-tested on kernel 6.18 (`go test -tags bpflive`); older kernels need BTF (`/sys/kernel/btf/vmlinux`, 5.8+ in practice). |
| Network (`network.go`) | Diff of `/proc/net/tcp`, `tcp6`, `udp`, `udp6` every `poll_interval` | New and closed connections, local and remote address and port, protocol, PID and process name via socket inode | Connections shorter than the interval are usually missed. The agent's own traffic is tagged as self-activity. |
| DNS (`dns.go`) | Every 5 s, first that works: `resolvectl query --cache`, systemd-resolved journal lines, `/proc/net/udp` port 53, dnsmasq/bind/unbound lines in `/var/log/syslog`, `/var/log/messages`, `/var/log/dns.log` | Domain names only from the journal (needs debug logging in systemd-resolved) or syslog parsers. Otherwise only "process X talked to DNS server Y" with no domain. | `resolvectl query --cache` is not a real option, so the first strategy never returns names. On a default Ubuntu host you get resolver IPs, not domains. Domain IOCs and DNS rules therefore rarely fire on Linux. |
| Journal (`journald.go`) | `journalctl --output=json --follow` | SSH logins and failures, `sudo` (success Medium, failure High), `su`, PAM sessions as `logon`; cron as `process`; kernel module loads and OOM kills as `raw` | Needs `journalctl`. |
| FIM (`fim.go`) | inotify on configured directories (recursive walk at start, new subdirectories added) | `event_type=file`, action create, modify, delete, rename_from, rename_to; path; SHA-256 | No writer attribution: pid is always 0 and source is `inotify`. The fanotify code is present but not used. Watch-limit failures in subdirectories are ignored silently. The hash covers only the first 10 MiB of a file, so for larger files it is not the file's SHA-256. Severity High for `/etc/passwd`, `/etc/shadow`, `/etc/sudoers`, `/etc/ssh/sshd_config`, `/etc/ld.so.preload`, `/root/.ssh`; Medium for create/modify in system bin directories and create in `/tmp`; otherwise Info. Under the systemd unit, `/tmp` and `/var/tmp` are private to the service (`PrivateTmp=true`), so those watches are expected to see nothing from the host (not verified on a host). |
| Config monitor (`configmon.go`) | inotify on the parent directory of each watched file, or on watched directories | `event_type=registry` with the path in `reg_key` and `file_path` (so it appears in registry views) | Watching one file reports changes to every other file in the same directory (for example watching `/etc/passwd` reports any change in `/etc`). |
| USB (`usb.go`) | `/sys/bus/usb/devices` every 10 s; first scan is a silent baseline | `event_type=usb`, vendor, product, serial, class; mass storage Low | |
| Software (`software.go`) | Tails `/var/log/dpkg.log` every 15 s | `event_type=software`, install, remove, purge with package and version | Debian and Ubuntu only. RPM and APK hosts get nothing. |
| Containers (`container.go`) | `GET /containers/json` on `/var/run/docker.sock` | Container start events with risks: privileged, host network, host PID, `docker.sock` mount | Docker only. |
| Vulnerability and posture (`vuln.go`, `posture_*.go`) | First scan 30 s after start, then every 5 days | TCP scan of ports 1 to 65535 on the host with banners; UDP probes; installed packages (dpkg, rpm, apk); running services; kernel and OS release; SUID binaries, world-writable directories and other findings; 10 posture checks | One large `vulnerability.scan` event. Results show on the host page; OSV matching covers Debian, Ubuntu, Alpine. |
| Location (`location.go`) | `https://ipinfo.io/json` every 30 minutes, posted to `/api/v1/agents/location` | City-level coordinates | Needs internet access from the host. |
| Health (`health.go`) | Every 60 s | Collectors, events collected, dropped, rate-limit drops, forwarded, queue depth, process sensor, agent memory, goroutines, host CPU, memory, disks, top processes | `forward_errors` is never filled in (always 0). |
| Live response (`live_response.go`) | Tunnel to the backend | `/bin/bash` (or `/bin/sh`) in a PTY as root | Opt-in. |

### 2.3 Windows

Implemented in: `agents/windows/internal/collector/*`, `agents/windows/internal/sysmon/installer.go`, `agents/windows/cmd/agent/main.go`. Unit-tested only.

| Collector | Mechanism | What is captured | Limits |
|---|---|---|---|
| Event Log (`eventlog.go`) | `wevtapi` subscriptions with persisted bookmarks | Event id, time, computer, user and every `EventData` field; well-known Security ids are classified (logon, process, file, registry, network) and some raise severity | Channels from the config; missing channels are skipped. 4688 has a command line only if the audit policy includes it. |
| Sysmon (`sysmon.go`) | `Microsoft-Windows-Sysmon/Operational` | Ids 1 (process create), 3 (network), 5 (terminate), 6 (driver load, High), 7 (image load), 8 (remote thread, High), 9 (raw access read, High), 10 (process access), 11 (file create), 12/13/14 (registry), 15 (stream hash), 17/18 (pipes), 22 (DNS), 23 (file delete); process GUIDs and logon ids are lifted into indexed columns | Depends on Sysmon running. The agent installs Sysmon if missing and replaces any existing Sysmon configuration with its own (version 2). |
| Process (`process.go`, `etwproc.go`) | ETW Microsoft-Windows-Kernel-Process; Toolhelp poll every 5 s if ETW fails. Quiet when Sysmon runs or when the agent enabled 4688/4689 auditing and reads the Security log | Start: new pid, parent pid, image (NT path mapped to a drive letter), command line read from the running process, parent image, `process_guid` (pid + create time). Stop: pid, exit code, image | Without Sysmon the agent turns on the Process Creation and Termination audit subcategories (by GUID, so any display language) and command-line inclusion at every start, including in service mode, so 4688 carries the command line. The ETW command line is empty for processes that exit within the ETW flush delay. Not run on a Windows host yet. |
| Network (`network.go`) | `GetExtendedTcpTable` / `GetExtendedUdpTable` diff every `poll_interval` | Connect and disconnect with owning PID | Short connections are missed; Sysmon 3 covers them when present. |
| DNS (`dns.go`) | `Microsoft-Windows-DNS-Client/Operational` (the agent enables the channel) | Query name, results, process | |
| Registry (`registry.go`) | `RegNotifyChangeKeyValue` per configured key subtree | Key, value, data on change | No writer process. Sysmon 12/13/14 carry it when present. |
| FIM (`fim.go`) | `ReadDirectoryChangesW` | Create, modify, delete, rename | No writer process. |
| File hasher (`filehash.go`) | Worker pool on file events | Adds MD5 and SHA-256 for files just written, up to 100 MiB | |
| App logs (`applog.go`) | File tail with offset state | One event per line (`json`, `text`, `combined`) | Only when `app_logs` is set. |
| Vulnerability and posture (`vuln.go`, `posture_win.go`) | Every 5 days | Port scan, antivirus, firewall, remote access, AutoRun, SMB, accounts, UAC, audit policy; 22 posture checks | |
| Location (`location.go`) | IP geolocation by default; Windows Location API only with `location_precise_positioning: true` | Coordinates and accuracy | |
| Health (`health.go`) | Every 60 s, bypasses the rate limiter | As Linux, plus `sysmon_status` | |
| Live response | Tunnel | `powershell.exe` (or `cmd.exe`) with pipes, as SYSTEM | Not a PTY. |

### 2.4 macOS

Implemented in: `agents/macos/internal/collector/*`, `agents/macos/cmd/agent/main.go`. Unit-tested only; preview.

| Collector | Mechanism | What is captured | Limits |
|---|---|---|---|
| Process (`process.go`, `es_exec.go`) | `sysctl KERN_PROC_ALL` poll every 2 s plus `KERN_PROCARGS2` for argv; `/usr/bin/eslogger exec` when present (macOS 13+) and permitted | pid, ppid, name, command line, path, SHA-256. While `eslogger` is healthy the poller stops reporting new processes so each exec appears once | Without Full Disk Access, or before macOS 13, only polling: short-lived processes are missed. Only the parser has tests. |
| Unified log (`syslog.go`) | `log stream --style json` with predicates for securityd, OpenSSH, authorization, `sudo`, launchd, and messages containing authentication/failed/denied | `event_type=syslog` | |
| Network (`network.go`) | `netstat -anp tcp/udp` diff every 30 s, `lsof` for PID | New connections | Short connections missed. |
| DNS (`dns.go`, `dns_names.go`) | `lsof` port 53 every 10 s; `tcpdump -i any udp dst port 53` for names | Query names (no PID) and process-to-resolver pairs | DoH and DoT are not visible. |
| FIM (`fim_audit.go`, `fim.go`) | `/dev/auditpipe` parsed with `praudit -x`; kqueue fallback | File create, write, delete, rename with PID (audit pipe) | Needs Full Disk Access; the BSM audit subsystem may be unavailable on recent macOS. |
| Config monitor (`configmon.go`) | kqueue `EVFILT_VNODE` | `event_type=config_change` | No built-in rule or Sigma category matches `config_change`, so these events are searchable but never alert (use an alert rule). |
| USB (`usb.go`) | `system_profiler SPUSBDataType -json` every 15 s | Attach events; mass storage Low | |
| Vulnerability and posture | Every 5 days | Port scan, findings, 9 posture checks; a posture regression (SIP, Gatekeeper, FileVault or firewall turned off) emits `config.posture_regression` (rule `M-POSTURE-001`, High) | |
| Location, health | As Linux | | |
| Live response | Tunnel | `/bin/zsh` in a PTY as root | |

### 2.5 Events the agent always produces

| Event | When | Severity |
|---|---|---|
| `health` | Every 60 s | Info |
| `agent.tamper` | When the agent receives a stop signal (service stop, kill TERM, uninstall). Sent directly; queued if the send fails | 4 |
| `vulnerability.scan` | Every 5 days | per finding |
| Location update | Every 30 minutes (separate route, not an event) | |

A `kill -9`, a power cut or a crash produces no tamper event. The silent-agent alert covers those cases.

---

## 3. Normalisation and forwarding

Implemented in: `agents/*/internal/parser/normalizer.go`, `enricher.go`, `agents/*/internal/collector/ratelimit.go`, `agents/*/internal/ownproc`, `agents/*/internal/forwarder/{queue,http,retry}.go`.

### 3.1 Normalise and enrich

- Required fields are filled, missing event types fall back to a default, severity is floored, strings are cleaned, Windows Security event ids are classified, OS names are normalised.
- The enricher overwrites `agent_id`, `host` and `os` with the agent's own values (collectors cannot forge them) and computes a deterministic event id from time, agent, source and record id. The backend uses `(id, time)` to drop duplicates.
- Events from the agent's own process tree are tagged as self-activity and set to Info. The detection engine skips them.

### 3.2 Rate limiting

Per event type and source: at most `max_per_second` events per second (default 500), and duplicate ids within `dedupe_window` (5 s) are dropped. Process, logon and severity 4+ events are never dropped by the cap. Drops are counted in the heartbeat.

### 3.3 The queue

Every event goes to an on-disk queue before it is sent: JSON lines in segment files of 500 events, at most 200 segments (about 100,000 events). Each write is fsynced. `queue.max_rows` is ignored.

Delivery is at least once. The forwarder reads a batch without removing it (peek), sends it, and removes it only after the backend accepted it (ack). A crash or power cut between send and ack sends the batch again, and the backend drops the duplicates by event id. Every `flush_interval` (5 s) the forwarder sends batches of up to `batch_size` (200) until the queue is empty or 50 batches went out.

| Backend answer | What the agent does |
|---|---|
| 2xx | Removes the batch and sends the next. |
| 429, 5xx, network error | Retries up to 8 times with exponential back-off and jitter (0.5 s base, 5 minute cap); then leaves the batch queued for the next flush. |
| 401, 403 | Leaves the batch queued (certificate renewal or a new build fixes it). No retries. |
| 413, 400, 422 | Halves the batch and tries again, down to a single event; only an event refused on its own is dropped (logged with its id). |

### 3.4 Remaining data-loss limits

1. **Eviction.** When the queue exceeds 200 segments, the oldest segment is deleted. Up to 500 events of severity 4 or higher from that segment are copied forward first; the rest are lost and the loss is only logged.
2. **In-memory drops.** If a collector's channel or the kernel ring buffer is full, events are dropped and counted (`events_dropped`).
3. `Retry-After` is not honoured.

### 3.5 Agent id on queued events

The forwarder stamps every queued event with the agent's current id before sending. Events queued under an earlier identity (before a reinstall) are therefore sent under the new one.

---

## 4. Ingest, validation and identity binding

Implemented in: `backend/internal/api/server.go`, `agent_identity.go`, `ingest.go`, `ingest_limits.go`, `ingest_identity.go`, `enroll.go`, `backend/pkg/agentid`, `backend/internal/store/events.go`, `agents.go`. Verified (Linux).

1. **TLS and certificate.** The backend asks for a client certificate and verifies it against the agent CA. Every `/api/` route except `POST /api/v1/enroll` requires a valid, unrevoked agent certificate whose CN equals its single `urn:obsidianwatch:agent:` URI SAN and is a well-formed `ag-` id. Deployment-CA certificates and `X-API-Key` are refused.
2. **Batch binding.** The batch `agent_id` must equal the certificate's id, or the batch is refused with 403. Individual events that name another id are re-attributed to the certificate's agent (logged as `events re-attributed`), not refused.
3. **Size and rate.** Body up to 16 MiB; up to `max_batch_size` (1000) events; `agent_id` up to 128 characters; 500 events/s per agent with a 20,000 burst (429 with `Retry-After: 30`).
4. **Field caps.** Command line 8,192 characters; image, file and registry fields 2,048; names and other short fields 512; `raw` 64 KiB (larger raw data is replaced by `{"truncated":true,...}`).
5. **Clock skew.** Events more than 10 minutes in the future are set to the receive time. `ingested_at` is stored separately, and every engine pages on it.
6. **Process identity.** `process_guid`, `parent_process_guid` and `logon_id` are lifted from the raw payload (Linux and macOS keys, Sysmon `ProcessGuid`, `ParentProcessGuid`, `SourceProcessGuid`, `LogonId`) into indexed columns for the alert graph.
7. **Insert.** Events are inserted with `ON CONFLICT (id, time) DO NOTHING`.
8. **Registry.** The agent row is upserted with host name, OS (from the first event), version, remote IP (from `X-Forwarded-For` only for configured trusted proxies) and event count. A record hidden because the host enrolled again becomes visible when it reports.
9. **Location.** `POST /api/v1/agents/location` is bound to the certificate the same way.
10. **Fleet queries.** `GET /api/v1/events`, `/agents`, `/agents/{id}` and `/metrics` on the backend refuse agent certificates. Because every `/api/` route also requires a certificate, these routes are not usable by anyone; use the management API instead.

The live-response tunnel and the install-key routes (`/api/v1/live-response/agent-tunnel`, `/api/v1/agent/register-key`, `/api/v1/verify-install-key`) are verified here and passed to the management server with the agent id in headers signed with a key derived from `OW_SECRET_KEY`, valid for 60 s. Management accepts nothing else from agents.

---

## 5. Detection pipeline

Implemented in: `management/backend/internal/api/detection_engine.go`, `detection_cache.go`, `cursor_paging.go`, `sigma_eval.go`, `threat_intel_engine.go`, `sig_registry.go`, `linux_fp_rules.go`, `win_fp_rules.go`, `zz_endpoint_rule_meta.go`, `engine_hooks.go`, `rule_gate.go`, `sequence_correlation.go`, `auth_correlation.go`, `prevalence*.go`, `ioc_*.go`, `manual_ioc.go`, `threat_intel_*.go`, `endpoint_suppress.go`, `alerts_engine.go`, `agent_health_engine.go`, `location_travel.go`.

### 5.1 Timing

| Engine | Interval | Reads |
|---|---|---|
| Detection engine | woken by a Postgres NOTIFY from the backend after each inserted batch (300 ms debounce); also every 10 s (`OW_DETECTION_INTERVAL_SECONDS`, 2 to 300) as a fallback | pages of 5,000 new events by `ingested_at` cursor until caught up (at most 20 pages per pass); first run looks back 2 h. Rule states, IOCs, Sigma rules and settings are reloaded at most every 10 s |
| Alert-rule engine | every 30 s | up to 2,000 events per cycle, own cursor |
| Agent health engine | every 60 s | agents table and `health` events |
| Threat-intel sync | at start and every 24 h | feeds |

Event-to-alert latency is therefore the agent flush interval (up to 5 s) plus about half a second. Measured end to end with the Linux agent: 0.5 to 2 s from the command to the alert. If notifications are lost, the 10 s timer still applies. Cursors are persisted, so a restart resumes where it stopped.

### 5.2 Order of evaluation per event

For each event in the batch:

1. Auth correlation, location (impossible travel / new country) and sequence correlation observe the event.
2. Skip: `vulnerability.scan` and `health` events, the agent's own processes, self-activity and the agent's own Sysmon.
3. Built-in signatures for the event's OS (5.3). For each match: skip if retired, disabled, or matched by an endpoint suppression; apply the rule gate (disabled, allowlisted, observe mode at Info); then create a deduplicated alert.
4. IOC match (5.6).
5. Sigma rules for the event's category (5.4).

### 5.3 Built-in signatures (counted from code)

Counts are unique rule ids, excluding retired ones.

| Set | Rules | Applied to |
|---|---|---|
| `linuxSignatures` | 34 | Linux (and any event with an unknown OS) |
| `linuxLineageSignatures` | 16 | Linux: lineage and kernel-sensor rules (`linux_lineage_sigs.go`): shell under a web server (`L-T1505.003`) or database (`L-T1190.db`), downloaded file executed from a staging directory, shell connecting out to the internet, memfd or file-descriptor execution, deleted-file execution, kernel-thread disguise, decoded payload piped to a shell, security or audit tooling disabled, firewall flushed, miners, hidden programs in temp directories, `authorized_keys` and sudoers edits, debugger attach, pkexec with empty argv (PwnKit, eBPF only) |
| `macosSignatures` | 31 | macOS |
| `windowsSignatures` | 41 | Windows |
| `windowsTamperSignatures` | 5 | Windows |
| `windowsAccountSignatures` | 4 | Windows |
| `windowsUSBSignatures` | 1 | Windows |
| `remoteSessionSignatures` | 1 | Windows |
| `dcSignatures` | 9 | Windows events of type `ad_object_access`, `ad_change`, `kerberos` |
| `linuxAccountSignatures` | 2 | Linux |
| `usbSignatures` | 1 | Linux, macOS |
| `softwareSignatures` | 2 | Linux |
| `dnsCatSignatures` | 4 | all three |
| `endpointAgentSignatures` | 2 | all three (`AGENT-TAMPER-001`, `M-POSTURE-001`) |
| `imdsSignatures` | 2 | every `network` event |
| **Total endpoint** | **139** | |
| `networkSignatures` | 18 | network-probe events only |

Per OS: Linux 45, macOS 38, Windows 58 (67 for domain-controller event types), plus the 2 metadata-service rules on network events.

Rule quality notes:

- Linux and macOS rules match on executables and argv tokens, not raw substrings (`linux_fp_rules.go`), and Windows has a matching set (`win_fp_rules.go`).
- 16 endpoint rules start in observe mode (stored at Info until promoted): `L-T1611b`, `L-DLP-010`, `L-T1087.001`, `L-T1590`, `L-T1560`, `L-T1222.002`, `L-T1105`, `L-T1548.001b`, `M-T1082`, `W-T1110`, `W-T1021.001`, `W-T1570`, `W-T1057`, `W-T1016`, `W-T1087`, `DC-T1558.001`.
- "Executable run from /tmp, /dev/shm or /var/tmp" (`L-T1059.004b`) is Medium.
- Rules only use fields that the platform's collectors fill. Linux in fallback mode (no eBPF) misses short-lived processes, and Windows without Sysmon depends on 4688 auditing.

### 5.3a Process lineage

Before rules run, the engine attaches each event's ancestors (parent first, up to 8) from a cache of process starts keyed by process GUID, with a pid fallback for sources without GUIDs (4688). Parents it has not seen are read from stored events (up to 300 per pass, 3 levels, last 7 days); misses are not asked again for an hour. On Linux an exec keeps the process GUID, so the cache keeps the images a process ran before (`bash -c cmd` execs `cmd` in place) and counts them as ancestors. Network, file and other events get the lineage of the process that caused them. Every signature, IOC and Sigma alert description ends with `Process chain: systemd → nginx → sh → curl` when ancestors are known.

Implemented in: `management/backend/internal/api/lineage.go`.

### 5.4 Sigma

- Rules come only from a pinned SigmaHQ release (`sigma_core.zip`) whose SHA-256 matches `ti.sigma_pinned_sha256`. Nothing is imported until an admin sets both the tag and the hash.
- Files under `windows/`, `linux/`, `macos/` and categories process_creation, file_event, file_change, network_connection, dns_query, registry_event, registry_set, sysmon and builtin are imported. All levels are imported.
- At evaluation, a rule applies only when its `logsource` product matches the event OS and its category maps to the event type (or to Sysmon event ids), or its service maps to the event channel. Every field the rule references must exist in the event, otherwise it does not match.
- Severity: from the rule level (critical 5, high 4, medium 3, low 2), capped at Low for `experimental` and Medium for `test`; `deprecated`, `unsupported` and `informational` rules never alert. A list of noisy titles is capped at Low and deduplicated per day.
- The number of rules depends on the pinned release and cannot be counted from code. In the review that produced the improvement spec, one release loaded 1,210 rules: 597 process creation, 26 Linux and 0 macOS. Expect Sigma to be Windows-heavy, and to be useful on Windows only with Sysmon.
- Alerts are titled `[Sigma] <title>` and can be suppressed with `SIGMA:<rule id>`.

### 5.5 Correlation

| Type | Rules | Detail |
|---|---|---|
| Sequence (`sequence_correlation.go`) | 3 endpoint (`CORR-SEQ-001` Windows account created then added to a privileged group, 30 min; `CORR-SEQ-002` Linux useradd then privileged group, 30 min; `CORR-SEQ-003` Windows security log cleared within 1 h of an account change), plus 3 AWS | "A then B on the same host within a window". State in memory, saved on shutdown. |
| Authentication (`auth_correlation.go`) | `CORR-AUTH-001` password spray, `-002` brute force, `-003` success after failures, `-004` MFA fatigue | Windows 4624/4625, Linux sshd and sudo, Entra sign-ins. |
| Location (`location_travel.go`) | Impossible travel, new country | Uses agent location history; coarse IP fixes are accuracy-checked. |
| Prevalence (`prevalence*.go`) | Rare binary | Every process and file event records (hash, path, name) per host. A binary seen on one host only, running from a user-writable path, raises a Low alert once the prevalence table has a week of history. |
| Incidents (`incidents.go`) | | Open alerts per host grouped into time-contiguous clusters with a risk score. |

There are no threshold or first-seen rules in the built-in engine; thresholds are available in alert rules (5.8).

### 5.6 IOCs and threat intelligence

Sources: ThreatFox (key), AlienVault OTX (key), abuse.ch Feodo Tracker (no key), Spamhaus BCL (subscription URL as the key), manual IOCs. Synced at start and every 24 h; manual IOCs survive syncs.

| Event | Field checked | Indicator type |
|---|---|---|
| `network` | destination IP | IP |
| `dns` | query name, then its parent domain | domain |
| any event with a command line | URLs, domains and IPs found in the command line | URL, domain, IP |
| `file`, `process`, `sysmon` with a hash | each hash in `file_hash` | hash |

Rules: IOCs below 25 % confidence are ignored, 25 to 49 % are lowered one level. With `ioc_known_good_enabled`, hash hits on OS or package-verified binaries are capped, and hashes seen on at least `ioc_hash_prevalence_hosts` hosts for long enough are lowered one level. Alerts are titled `[THREATFOX] Ip IOC Match - <value>` (or the source name), deduplicated per source, value, host, hour and entity, and suppressible with `IOC:<source>:<type>`. After a sync, retro-hunt searches stored events for the new IOCs (up to 500 alerts, tagged `Retro-hunt`).

Coverage depends on the collectors: Linux DNS rarely has domain names, macOS DNS names have no PID, and Windows file hashes come from the agent's hasher or Sysmon.

DNS categorisation (Quad9, SURBL and similar, no key) and the tiered hash-reputation lookup (Team Cymru, MalwareBazaar, CIRCL, Hybrid Analysis, VirusTotal) run alongside.

### 5.7 Endpoint suppressions

**Suppressions** removes matching detections before an alert is created. A suppression names a rule (exact id or prefix), and optional host, process name, image path glob, parent process, user, command-line substring and file path glob. All conditions must match. A reason is required; expiry is up to 365 days unless marked permanent. Every change is audited. The rule gate (`/api/v1/rules/settings`) offers a second, simpler allowlist per rule.

### 5.8 Alert rules

**Alert rules** are user-defined: event type, minimum severity, substring or regex matches on host, user, process, command line, source and destination IP, DNS, OS and source, exclusions on host, user and process, and an optional threshold (N matches on one host within a window). The engine runs every 30 s and deduplicates per rule, host, hour and entity. The alert takes the event's severity.

### 5.9 Alerts

- Every alert is deduplicated with a key (rule, host, hour, entity fingerprint). A repeat increases the occurrence count. For process alerts, the extra process is linked to the existing alert so the graph still reaches it.
- Email is queued when the severity meets the SMTP minimum; syslog forwarding and webhooks are also available.
- Workflow on **Alerts**: acknowledge, assign, notes, close with review, bulk actions, SLA view.

### 5.10 Agent health and tamper alerts

| Alert | Trigger |
|---|---|
| `Agent offline: <host>` | No event for 10 minutes (Medium; High after 1 hour). Repeats hourly. Hidden (replaced) records are excluded. |
| Collector stopped | A collector present in an earlier heartbeat is missing. |
| Drops rising | 50 or more new dropped events since the previous heartbeat. |
| Queue backing up | `queue_depth` of 2,000 or more, reported in every health event. |
| Sysmon not running | Windows heartbeat `sysmon_status` is not `running`. |
| Engine stalled | A detection or correlation cursor has not moved for 10 minutes. |
| `AGENT-TAMPER-001` | `agent.tamper` event (agent stopping). Medium. |
| Live Response tunnel takeover refused | A second tunnel for the same agent from a different certificate. High. |

---

## 6. Investigation

Implemented in: `events_search.go`, `store/event_query.go`, `graph_alert.go`, `graph_endpoint.go`, `prevalence.go`, `handlers_graph.go`, `nl_search.go`, `scheduled_searches.go`.

- **Events**: raw event browser, export (CSV, JSON), saved queries, scheduled searches.
- **Search**: a KQL-style language compiled to parameterised SQL. Fields: `host`, `os`, `user`, `proc`, `cmd`, `image`, `file`/`path`, `hash`, `reg`, `regvalue`, `domain`, `channel`, `source`, `proto`, `guid`, `logon`, `src`, `dst`, `ip`, `pid`, `ppid`, `port`, `dstport`, `srcport`, `eid`, `sev`, `type`, `time`. Operators `:`, `=`, `!=`, `>`, `>=`, `<`, `<=`; `and`, `or`, `not`/`-`, parentheses, `field:(a or b)`, `*` wildcards. Lookback up to 90 days. No aggregation, regular expressions or CIDR matching. Natural-language search turns a question into this syntax for review.
- **Alert graph**: a process alert is anchored on the exact process instance (GUID) and follows ancestors, descendants and per-process artifacts (files, connections, DNS, registry). Every edge states the evidence that joined it; nothing is joined by time proximity. Linux and macOS GUIDs come from the agent; Windows GUIDs come from Sysmon.
- **Endpoint threat graph** (host page): host, process, DNS, IP, file, registry and logon nodes for one host.
- **Live process list** (host page, admin): read from the host through the tunnel.
- **Prevalence**: how many hosts ran a binary and when it was first seen.
- **Host page in Fleet**: inventory, online state, vulnerabilities (OSV for Debian, Ubuntu and Alpine; NVD fallback), endpoint compliance (Windows 22 checks, macOS 9, Linux 10; unknown values never show as a pass; not run on live hosts), locations, tamper panel.

---

## 7. Hunting

Implemented in: `management/backend/internal/api/hunt.go`, `store/response.go`, `agents/*/internal/response/query*.go`.

### 7.1 History hunt

Runs a Search query over stored events (1 h, 6 h, 24 h, 7 d, 30 d or 90 d) and rolls the hits up per host (up to 300 hosts), 20 s timeout.

### 7.2 Live fleet query (admin)

Asks connected agents one fixed, read-only question. Nothing is executed on the host beyond reading.

| Kind | Answer |
|---|---|
| `processes` | Running processes (pid, ppid, user, name, memory, path, command line) |
| `connections` | Open connections |
| `listening` | Listening ports |
| `persistence` | Run keys, scheduled tasks, services, cron, systemd units, launch agents, SSH keys |
| `software` | Installed software |
| `users` | Local accounts (with admin flag) |
| `file_find` | Files by name or `sha256:<hash>` under an optional path |
| `services` | Services: systemd units with enabled state (init scripts without systemd), Windows services with account and path, launchd jobs |
| `scheduled_tasks` | cron (system, `cron.d`, per-user, `cron.hourly` etc.), systemd timers, `at`; Windows scheduled tasks with actions, run-as, last and next run; macOS cron and scheduled launchd jobs |
| `sessions` | Logged-on users, terminal, since, source address (`who`; `quser` on Windows) |
| `dns_cache` | Windows only: the DNS client cache |
| `browser_extensions` | Chrome, Edge, Brave, Chromium and Firefox extensions per user and profile, with names resolved from locales and their permissions |
| `shell_history` | Last 200 lines per history file per user: bash, zsh, sh, fish, Python, MySQL, psql; PowerShell PSReadLine on Windows |
| `recent_files` | Files changed in the last `hours` (1 to 720, default 24) under Downloads, Desktop, Documents and temp directories, or under a given path; the first 200 are hashed |
| `firewall_rules` | nftables or iptables rules; enabled Windows Firewall rules with program and ports; macOS application firewall state and pf rules |
| `shares` | NFS exports and Samba shares; SMB shares with access; macOS `sharing -l` |
| `certificates` | Locally added CA certificates (Linux trust anchors, Windows LocalMachine Root, CA, My and TrustedPublisher, macOS System keychain), with self-signed flag, expiry and SHA-256 |
| `usb_devices` | Attached USB devices (Linux sysfs, macOS `system_profiler`); on Windows every USB storage device seen, with first and last arrival |
| `drivers` | Linux kernel modules with taint flags; Windows drivers with Authenticode status and signer; macOS loaded kexts |
| `loaded_modules` | Windows and Linux: processes that have a module or shared object whose path contains the required match |
| `named_pipes` | Windows only: pipe names |
| `registry` | Windows only: values and subkeys of one key given as the path (read only) |
| `patches` | Windows only: installed hotfixes |

Kinds that do not exist on a host's OS answer "not available on <os>". The Linux kinds were run on a Linux host; the Windows and macOS kinds compile but have not been run on those systems yet.

Limits: 500 hosts per hunt (connected hosts first), 500 rows per host, 120 s per host. Requires live response in the build.

### 7.3 Offline queue

For hosts that are not connected, choose **skip** or **wait** (1 h, 24 h, 7 d or until done; until done expires after 30 days). Waiting hosts are stored as `queued` and sent the question when their tunnel connects. The result view shows per-host state: answered (`ok`), `failed`, `timeout`, `queued`, `skipped`/`offline`, `expired`. A queued host keeps its queue time, so late answers show when they really ran. Only read-only query kinds can queue; anything else is refused at dispatch. Response actions never queue as hunts.

### 7.4 Library

18 ready-made hunts: 13 history (encoded PowerShell, LOLBin downloads, Office spawning a shell, remote-access tools, shadow-copy deletion, credential dumping, C2-style ports, long DNS names, new services and tasks, startup and Run-key writes, SSH key changes, log clearing, archiving and exfil tools) and 5 live (listening ports, persistence, local administrators, remote-access software, processes from temp or user directories).

---

## 8. Response actions

Implemented in: `management/backend/internal/api/response_actions.go`, `agents/*/internal/response/*`. See also `response-actions.md`.

All actions run from **Response**: pick hosts, pick an action, give a reason, review, run. Admin only. Every action is stored (who, why, parameters, outcome) and written to the audit log. Actions travel over the live-response tunnel, so the build must have live response enabled. Results are accepted only from the tunnel of the agent that was asked. An action times out after 3 minutes.

| Group | Action | Behaviour | Offline host |
|---|---|---|---|
| Network | Isolate | Blocks all traffic except the ObsidianWatch server addresses (resolved and cached at isolation), loopback and DHCP. Optional duration (up to 7 days). Survives agent restarts and reboots. Shows the block page unless `no_block_page`. | Queued: the desired state is stored and applied when the tunnel reconnects (with the time left). |
| | Release isolation | Restores networking, DNS settings and the block page. | Queued the same way. |
| | Block IP / Unblock IP / Blocked IPs | Drops traffic to and from one address. Survives restarts. Loopback, unspecified, multicast, link-local and the server addresses are refused. Up to 1,000 blocks. No TTL. | Refused (needs a live tunnel). |
| Processes | Kill process | One PID, optionally with children; the expected image guards against PID reuse; system processes and the agent are refused. | Refused. |
| | Block program / Unblock / Blocked programs | Removes execute permission (Linux, macOS) or denies Execute to Everyone (Windows), and kills any running instance every second. OS paths and the agent cannot be blocked. Kill after start, not pre-exec. | Refused. |
| Files | Quarantine | Moves a regular file (up to 512 MiB) into the vault with its SHA-256. OS directories, the agent's data and binary are refused. | Refused. |
| | Restore / Delete from vault / Quarantine vault | By quarantine id. | Refused. |
| | Delete file | Permanent; optional expected SHA-256 (deleted only if it still matches). Same refusals as quarantine. | Refused. |
| | File details | Size, mode, modified time, SHA-256. | Refused. |
| | Collect file | Up to 2 MiB, stored with the action; download is admin-only and audited (`GET /api/v1/response/actions/{id}/file`). | Refused. |
| Accounts | Disable account | Linux: `usermod -L -e 1` (also stops SSH key logins) and kills the user's processes. macOS: `pwpolicy disableuser`. Windows: disables the local account, refusing the last enabled local administrator. uid 0 and named system accounts are refused. Domain accounts must be disabled in the directory. | Refused. |
| | Enable account | Reverses it. | Refused. |

Protected OS paths for quarantine, delete and block: `/bin`, `/sbin`, `/usr/bin`, `/usr/sbin`, `/lib`, `/lib64`, `/usr/lib`, `/usr/lib64`, `/boot`, `/etc`, `/System`, `/Library/Apple`, `/usr/libexec`, `C:\Windows`, `C:\Program Files\WindowsApps`.

Mechanisms per OS:

| | Linux | Windows | macOS |
|---|---|---|---|
| Isolation | nftables table `obsidianwatch_isolate` (iptables fallback) | Windows Firewall rules in group `ObsidianWatch-Isolation` | pf ruleset |
| Block page | NAT redirect of DNS to 127.0.0.1:15353 and HTTP to 127.0.0.1:18080 (`obsidianwatch_blockpage`) | adapters' DNS set to 127.0.0.1 (sink on :53, page on :80) | each network service's DNS set to 127.0.0.1 |
| IP block | nftables table `obsidianwatch_ipblock` | Windows Firewall rules | pf |
| Verified | isolation and block page tested in a network namespace (nftables and iptables); IP block and account lock tested live, not under the systemd sandbox | unit-tested | unit-tested |

HTTPS sites cannot show the block page. If port 80 or 53 is in use on Windows or macOS, the page or DNS change is skipped and the result says so.

Linux caution (not verified): under the installed systemd unit (`ProtectSystem=strict`, `ProtectHome=read-only`, `PrivateTmp=true`), file actions outside `/var/lib/obsidianwatch` and `/etc/obsidianwatch`, and `disable_user`, are expected to fail with a read-only file system error, and files in the host's `/tmp` are not visible to the agent.

Not implemented: block by hash, IP block with TTL, protected-range refusal for private networks and the gateway, two-person approval.

---

## 9. Live response shell

Implemented in: `management/backend/internal/api/live_response.go`, `agent_tunnel_identity.go`, `backend/internal/api/agent_tunnel_proxy.go`, `agents/*/internal/collector/live_response.go`.

- Opened from **Response → Live response**. Admin only. The host must be connected.
- The agent keeps one WebSocket tunnel to the backend port with its certificate; the backend verifies it and passes it to management with a signed identity. One tunnel per agent: a second connection is refused (409), logged and alerted, except the same certificate reconnecting.
- Shell: Linux `/bin/bash` (PTY, root), macOS `/bin/zsh` (PTY, root), Windows `powershell.exe` or `cmd.exe` (pipes, SYSTEM).
- Sessions are token-bound, capped at 60 minutes, and the full input and output transcript is stored.
- Revoking the agent's identity closes the tunnel at once.
- Not implemented: command allow or deny lists, non-root shell, approval workflow.

---

## 10. Network probe

Implemented in: `agents/network/*`, `management/backend/internal/api/network_sigs.go`. Status: not supported, never wired end to end, and not buildable here (SNMP and SQLite dependencies are not vendored; the Dockerfile download is commented out).

What the code is written to do:

| Collector | Default | Captures |
|---|---|---|
| Syslog | UDP and TCP :514 | Device syslog lines, parsed; local brute-force counting |
| NetFlow / sFlow | :2055 / :6343 | Flow records and periodic summaries; port-scan, lateral-movement and bandwidth-spike analysis |
| SNMP | poll every 60 s; optional subnet auto-discovery | Device inventory and interface data (v2c, v3) |
| ARP | `eth0`, every 30 s | New devices and ARP spoofing (known MACs list) |
| Analysis engine | SQLite (`/var/lib/obsidianwatch-probe/state.db`, 7 days) | Summaries and device inventory every 5 minutes |

The probe enrolls with a token like an agent and posts to `/api/v1/events` with OS `network-probe`; the detection engine applies only the 18 network signatures to these events. A **Network** page (beta) exists in the console.

---

## 10a. Prevention

Agents match connections, files, processes and DNS answers against a server-published list of malicious IPs, SHA-256 hashes and domains, in audit or enforce mode per type. Linux refuses listed connections in the kernel. Full description: [prevention.md](prevention.md).

## 11. Known limits (from the improvement spec, checked against the current code)

| Spec item | Current state |
|---|---|
| F1 Linux short-lived processes missed | Fixed where eBPF loads (kernel with BTF, root): exec, argv and exit come from the kernel. Fallback mode still drops an exec whose `/proc` entry is gone. |
| F2/F3 shared key, forged agent ids, tunnel takeover | Fixed: per-agent certificates, batch binding, one tunnel per agent. |
| F4 queue can lose data | Fixed: peek, send, ack with fsync; refused batches are bisected (section 3.3). Eviction at 100,000 events remains. |
| F5 Linux FIM without writer attribution | Still true: inotify only, pid 0. The README's fanotify claim is wrong. |
| F6 config monitor over-reports siblings | Still true. |
| F7 Windows relies on Sysmon; existing Sysmon config overwritten | Partly fixed: without Sysmon the agent enables 4688/4689 auditing with command lines, and ETW events carry pid, parent, image and command line. Sysmon config is still overwritten. |
| F8 tamper protection is cooperative | Still true; local key fallback remains when the server is unreachable. |
| F9 detection quality | Partly addressed: `/tmp` exec is Medium, 16 noisy rules observe by default, FP-reduced Linux and Windows matchers. Not re-measured here. |
| F10 Sigma Windows-heavy | Still true in practice; all levels are imported now, damped by rule status. |
| F11 10 s polling, no lineage | Fixed: detection is woken by each ingested batch (about 0.5 s) and rules see process lineage (section 5.3a). |
| F12 hunting narrow | Offline queue fixed; 23 live query kinds (section 7.2). Search has no aggregation, regex or CIDR. |
| F13 role gaps | User list is admin-only now. Analysts can still create, edit and delete alert rules and suppressions. |
| F14 unbuilt or unwired code | The application sensor's eBPF tier (`internal/ebpf`, `-tags ebpf`) is still not built (the endpoint process sensor is a separate, built program); `audit.go` not wired; macOS depends on `eslogger`; Linux DNS `resolvectl` path does not return names. |
| macOS | Preview, detective only. Response actions exist but are unit-tested only. |
