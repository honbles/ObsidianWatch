# Endpoint configuration

This page lists every setting that controls the endpoint agents and what the platform does with endpoint data. Defaults are taken from the code. "Code default" means the value used when the key is absent from the YAML. "Builder" means the value the Agent builder writes into every build.

Implemented in: `agents/{linux,macos,windows}/internal/config/config.go`, `config_app.go`, `agents/*/configs/agent.yaml`, `management/backend/internal/api/agent_builder.go`, `backend/internal/config/config.go`, `backend/docker/server.yaml`.

---

## 1. How agent configuration works

- The Agent builder generates YAML and compiles it into the binary (`EmbeddedConfig`). The endpoint has no configuration file.
- A binary with no embedded YAML (a development build) reads `agent.yaml` from the working directory.
- Code defaults are loaded first, then the YAML is decoded on top. A list in the YAML (FIM directories, config-monitor paths, registry keys, channels) replaces the default list completely.
- The builder writes a fixed set of keys (section 3). To change collectors, paths or intervals for real deployments, edit `buildLinuxYAML`, `buildMacOSYAML` or `buildWindowsYAML` in `agent_builder.go`, rebuild the management image (`docker compose up -d --build mgmt-api`), then build and reinstall the agents. There is no remote configuration for endpoint collectors.
- `forwarder.backend_url` is required and `forwarder.batch_size` must be greater than 0, or the agent refuses to start.

---

## 2. Agent keys

### 2.1 `agent`

| Key | Code default | Effect |
|---|---|---|
| `agent.id` | `""` | Not used as the identity. The enrolled id (`ag-...`) is always used for events. On Linux it is only passed to the installer. |
| `agent.version` | Linux/macOS `0.3.1`, Windows `0.3.2` | Linux and macOS report the version compiled into the binary (`0.3.1`). Windows reports this YAML value; the builder writes `0.2.0` for Windows, so Windows agents show version `0.2.0`. |

### 2.2 `forwarder`

| Key | Code default | Builder | Effect |
|---|---|---|---|
| `backend_url` | none (required) | from Agent builder | Every agent connection: enrollment, events, location, tunnel, install-key calls. |
| `management_url` | `""` | from Agent builder | Only used as an extra host in the isolation allow-list. Agents do not call it. |
| `enroll_token` | `""` | minted per build | Used once to obtain the certificate. A config with `api_key` and no token refuses to start. |
| `ca_cert_pem` | `""` | deployment CA | Trusts the backend's server certificate. Preferred over `ca_file`. |
| `ca_file` | `""` | `""` | Path to the same CA (development builds). |
| `management_ca_cert_pem` | `""` | from Agent builder | Kept for older configurations; not used for any connection now. |
| `management_ca_file` | Windows only, `""` | not written | Not used for any connection now. |
| `allow_insecure_tls` | `false` | not written | Without a CA, TLS fails closed unless this is `true`. Lab use only. Used by location and live response. The event forwarder and enrollment use system roots when no CA is set. |
| `batch_size` | 200 | 200 | Events per POST. Also the Windows dispatcher batch size. |
| `flush_interval` | 5s | 5s | How often the queue is drained. |
| `install_key` | `""` | `""` | Sent with batches; the backend stores it only for legacy reasons. The real key is generated at install. |
| `cert_file`, `key_file` | `""` | not written | Legacy static client certificate. Overridden by the enrolled certificate when one exists. Do not use. |
| `api_key` | `""` | not written | Refused by the servers. Present only so old configs fail with a clear message. |

### 2.3 `queue`

| Key | Code default | Builder | Effect |
|---|---|---|---|
| `db_path` | `/var/lib/obsidianwatch/queue` (Windows `C:\ProgramData\ObsidianWatch\queue`) | same | Directory of segment files (`segments/*.jsonl`). |
| `max_rows` | 100000 | 100000 | Ignored. The cap is fixed in code: 200 segments of 500 events (about 100,000 events). See `capability.md` for the loss behaviour. |

### 2.4 `collector` (shared keys)

| Key | Code default | Builder | Effect |
|---|---|---|---|
| `process.enabled` | true | true | Process collector. |
| `process.poll_interval` | 2s | 2s | Linux `/proc` and macOS `sysctl` poll interval. No effect on Windows. |
| `network.enabled` | true | true | Connection-table collector. |
| `network.poll_interval` | Linux 10s, macOS and Windows 30s | 30s | Diff interval. Connections shorter than this are usually missed. |
| `dns.enabled` | true | true | DNS collector. |
| `fim.enabled` | true | true | File integrity monitoring. |
| `fim.dirs[].path` | per OS (section 4) | per OS | Directory to watch. A file path watches its parent directory. |
| `fim.dirs[].recursive` | per entry | per entry | Watch subdirectories (Linux: one inotify watch per directory, added at start and for new directories). |
| `fim.dirs[].exclude` | per entry | per entry | Glob patterns on the file name. |
| `health.enabled` | true | true | Heartbeat event. |
| `health.interval` | 60s | 60s | Heartbeat interval. |
| `rate_limit.enabled` | true | true | macOS and Windows honour it. Linux always applies the limiter. |
| `rate_limit.max_per_second` | 500 | 500 | Cap per event type and source. Process, logon and severity 4+ events are never dropped by the cap. |
| `rate_limit.dedupe_window` | 5s | 5s | Drops events with the same deterministic id inside the window. |
| `app_logs[]` | `[]` | Windows `[]` | Application log tailing. Only the Windows agent starts it. Fields: `name`, `path`, `format` (`json`, `text`, `combined`), `event_type`, `severity`. Offsets are kept in `<queue dir>\..\applog_state`. |

### 2.5 OS-specific collector keys

| Key | OS | Code default | Builder | Effect |
|---|---|---|---|---|
| `journald.enabled` | Linux | true | true | `journalctl --output=json --follow`. |
| `config_monitor.enabled` | Linux, macOS | true | true | Sensitive-path monitor (inotify on Linux, kqueue on macOS). |
| `config_monitor.paths[]` | Linux, macOS | section 4 | section 4 | Files or directories to watch. |
| `syslog.enabled` | macOS | true | true | `log stream` with security predicates. |
| `event_log.enabled` | Windows | true | true | Event Log subscriptions with bookmarks. |
| `event_log.channels[]` | Windows | Security, System, Application, Windows Defender/Operational, WMI-Activity/Operational, DriverFrameworks-UserMode/Operational | Security, System, Application, PowerShell/Operational, Windows Defender/Operational | Channels to subscribe. Channels that do not exist on the host are skipped. |
| `event_log.poll_interval` | Windows | 5s | 5s | Event Log read interval. |
| `sysmon.enabled` | Windows | true | true | Reads `Microsoft-Windows-Sysmon/Operational`. Sysmon installation happens regardless of this key. |
| `registry.enabled` | Windows | true | true | `RegNotifyChangeKeyValue` watchers. |
| `registry.keys[]` | Windows | 19 keys (section 4) | 10 keys | Keys to watch. |
| `location_precise_positioning` | Windows | false | not written | When true, uses the Windows Location API (GPS, Wi-Fi). Otherwise IP geolocation only. |

Always on, not configurable: vulnerability and posture scan (every 5 days, first scan 30 s after start), location (every 30 minutes, via `https://ipinfo.io`), and on Linux the USB, software (dpkg) and container collectors; on macOS the USB collector.

### 2.6 `live_response`

| Key | Code default | Builder | Effect |
|---|---|---|---|
| `live_response.enabled` | false | builder checkbox, off by default | Opens the tunnel to the backend. Required for the shell, every response action, live hunts and the live process list. |

### 2.6a `prevention`

| Key | Code default | Builder | Effect |
|---|---|---|---|
| `prevention.enabled` | true (when the key is absent) | not written | Turns agent-side prevention off entirely. The mode per type (off, audit, enforce) comes from the server, not from this file. |
| `prevention.kernel` | true | not written | Linux only: allows the eBPF connect block. With it off, IP matches are blocked with `block_ip` after the connection is seen. `OW_DISABLE_EBPF=1` in the service environment has the same effect (and also disables the kernel process sensor). |

Prevention uses the response actions (kill, quarantine, block IP) without needing `live_response.enabled`. See [prevention.md](prevention.md).

### 2.7 `log`

| Key | Default | Effect |
|---|---|---|
| `log.level` | `info` | `debug`, `info`, `warn`, `error`. |
| `log.format` | `json` | Linux and macOS always write JSON to stdout. |

### 2.8 `app_monitoring`

Written only when the app-server profile is selected in the builder. It runs an OTLP receiver on `127.0.0.1:4318` and, on Linux, a host runtime sensor for application services. Keys: `enabled`, `otlp.listen`, `otlp.socket`, `user_hash_key`, `cleartext_services`, `client_ip_default`, `client_ip_by_service`, `slow_ms`, `slow_ms_by_service`, `baseline_sample_pct`, `max_routes_per_service`, `max_open_traces`, `flush_interval`, `settings_poll_interval`, `ebpf.enabled`, `ebpf.mode` (`auto`, `ebpf`, `procevent`, `poll`), `ebpf.poll_interval`, `ebpf.environment`, `ebpf.watch_dirs`, `ebpf.secret_files`. This belongs to application monitoring and is not documented further here. This application sensor's kernel tier is written but has never been built (`agents/linux/internal/ebpf/bpf/README.md`); it uses the proc connector or polling. The endpoint process sensor is separate and does use eBPF (see capability.md, 2.2).

---

## 3. What the Agent builder writes

| Section | Linux | macOS | Windows |
|---|---|---|---|
| Log collector | `journald` on | `syslog` on | `event_log` on, 5 channels |
| Process | on, poll 2s | on, poll 2s | on |
| Network | on, poll 30s | on, poll 30s | on, poll 30s |
| DNS | on | on | on |
| FIM dirs | `/home` (recursive), `/root` (recursive), `/tmp`, `/var/tmp`, `/etc`, `/opt` | `/usr/bin`, `/usr/local/bin`, `/private/tmp` | `System32`, `System32\Tasks` (recursive), `System32\drivers`, `System32\wbem` |
| Config/registry | 7 paths | 5 paths | 10 registry keys |
| Sysmon | n/a | n/a | on |
| Health | 60s | 60s | 60s |
| Rate limit | 500/s, 5s | 500/s, 5s | 500/s, 5s |
| Live response | checkbox | checkbox | checkbox |

Linux builder FIM excludes: `/home` `*.log`, `*.cache`, `.git`; `/root` `*.log`, `.cache`; `/tmp` `*.log`, `*.tmp`. Windows FIM excludes `*.log`, `*.tmp`, `*.etl` on each entry.

Linux builder `config_monitor.paths`: `/etc/passwd`, `/etc/shadow`, `/etc/sudoers`, `/etc/ssh/sshd_config`, `/etc/hosts`, `/etc/systemd/system`, `/root/.ssh`.

macOS builder `config_monitor.paths`: `/etc/passwd`, `/etc/sudoers`, `/etc/ssh/sshd_config`, `/Library/LaunchDaemons`, `/Library/LaunchAgents`.

Windows builder `registry.keys`: `HKLM\...\CurrentVersion\Run`, `RunOnce`, `HKLM\SYSTEM\CurrentControlSet\Services`, `HKCU\...\Run`, `Image File Execution Options`, `Winlogon`, `Windows NT\CurrentVersion\Windows`, `Session Manager`, `Policies\Explorer\Run`, `HKCU\...\RunOnce`.

---

## 4. Code defaults and samples that differ from the builder

These apply only when a key is absent, which never happens for the keys the builder writes. They matter for development builds and for anyone who edits the builder.

| | Linux code default | macOS code default | Windows code default |
|---|---|---|---|
| FIM dirs | `/usr/bin`, `/usr/sbin`, `/usr/local/bin`, `/usr/local/sbin`, `/tmp` (exclude `*.log`), `/var/tmp`, `/home` (recursive), `/etc` | `/usr/bin`, `/usr/sbin`, `/usr/local/bin`, `/bin`, `/sbin`, `/private/tmp` (exclude `*.log`), `/tmp` | builder list plus `SysWOW64`, ProgramData Startup, `C:\Windows\Tasks`, `GroupPolicy`, `GroupPolicyUsers` (recursive) |
| Config/registry | builder list plus `/etc/sudoers.d`, `/etc/cron.d`, `/etc/cron.daily`, `/etc/cron.weekly`, `/etc/crontab`, `/etc/ld.so.preload` | builder list (under `/private/etc`) plus `/System/Library/LaunchDaemons`, `/root/.ssh`, `/Library/StartupItems`, periodic, emond, cron and `at` tabs, loginwindow plist, `/etc/zshrc`, `/etc/zprofile`, `/etc/profile`, `/etc/rc.common`, background task management DB, `/Library/Scripts` | builder list plus `WOW6432Node ...\Run`, `TaskCache\Tree`, `Lsa`, `Print\Monitors`, `rdpwd\StartupPrograms`, `Active Setup\Installed Components`, `User Shell Folders`, `SecurityProviders`, `Windows Defender\Exclusions` |

The sample files `agents/<os>/configs/agent.yaml` show wider lists again (for example Windows DC channels: Directory Service, DNS Server, File Replication Service). Use them as a reference of available keys only.

---

## 5. Differences per OS

| Setting or behaviour | Linux | macOS | Windows |
|---|---|---|---|
| Log source key | `journald` | `syslog` | `event_log`, `sysmon` |
| Persistence monitor key | `config_monitor` (paths) | `config_monitor` (paths) | `registry` (keys) |
| `process.poll_interval` used | yes | yes | no (ETW, WMI fallback every 5 s) |
| `rate_limit.enabled` honoured | no (always on) | yes | yes |
| `app_logs` | ignored | ignored | used |
| `location_precise_positioning` | n/a | n/a | used |
| USB collector | always on | always on | none (PnP events only via the DriverFrameworks channel when subscribed) |
| Software and container collectors | always on | none | none |
| Reported agent version | 0.3.1 | 0.3.1 | YAML value (`0.2.0` from the builder) |
| Identity store | 0600 file | 0600 file | DPAPI machine scope |

---

## 6. Ingest backend (`backend/docker/server.yaml`)

Mounted into the backend at `/app/server.yaml`. Restart the backend after a change.

| Key | Default | Effect |
|---|---|---|
| `server.listen_addr` | `:8443` | Agent port. |
| `server.tls_cert_file`, `tls_key_file` | `certs/server.crt`, `certs/server.key` | Server certificate from `cert-init`. Without TLS no agent can present a certificate, so none can connect. |
| `server.tls_ca_file` | unset | Not used for agents (the agent CA is always used for client certificates). |
| `server.read_timeout`, `write_timeout` | 30s | HTTP timeouts. The tunnel proxy manages its own deadlines. |
| `server.max_batch_size` | 1000 | Larger batches get 413. |
| `server.trusted_proxies` | `[]` | Peers allowed to set `X-Forwarded-For` for the agent's last IP. A proxy in front of the backend must pass TLS through, because the client certificate is required. |
| `server.retention_days` | 90 (valid 7 to 3650) | Event retention. |
| `server.enable_compression` | false | TimescaleDB compression for chunks older than 7 days. |
| `auth.agent_identity.ca_cert_file` | `agent-ca/agent-ca.crt` | Agent CA certificate; created with the key on first start when both are missing. |
| `auth.agent_identity.ca_key_file` | `agent-ca/agent-ca.key` | Agent CA key (0600). Back it up. |
| `auth.agent_identity.cert_ttl` | `720h` (30 days) | Agent certificate lifetime, 1 h to 366 days. Agents renew at half life. Capped at the CA's expiry. |
| `auth.api_keys`, `auth.mtls_enabled` | unset | Ignored; a warning is logged if present. |
| `tunnel.management_url` | `https://mgmt-api:8443` (env `OW_MANAGEMENT_URL` if empty) | Where tunnel and install-key calls are passed. Empty disables them. |
| `tunnel.management_ca_file` | `certs/ca.crt` | Verifies the management certificate. |
| `tunnel.management_server_name` | `127.0.0.1` | A SAN of the management certificate. |
| `tunnel.insecure_skip_verify` | false | Lab only. |

Fixed limits in code: request body 16 MiB; 500 events/s per agent with a burst of 20,000 (429 with `Retry-After: 30`); command line capped at 8,192 characters, paths and registry fields at 2,048, short fields at 512, `raw` at 64 KiB (replaced by a stub when larger); events dated more than 10 minutes in the future are clamped to the receive time; enrollment 20 calls per minute per IP; revocation list reloaded every 15 s.

---

## 7. Management settings that affect endpoints

All of these are admin-only unless stated.

### 7.1 Detection

| Setting | Where | Default | Effect |
|---|---|---|---|
| `OW_DETECTION_INTERVAL_SECONDS` | environment of `mgmt-api` (not in `docker-compose.yml`; add it) | 10 | Detection engine poll interval, clamped to 2 to 300 s. |
| Signature on/off and severity override | **Rules** (`PATCH /api/v1/detections/{id}`) | on | Per built-in rule. |
| Rule settings (enable, observe, allowlist, scope) | `PUT /api/v1/rules/settings` | per rule metadata | Observe mode stores the alert at Info severity. 16 endpoint rules start in observe mode. Allowlist values match host, source IP, destination IP, process name or user name. |
| Backtest | **Rules** (`POST /api/v1/detections/{id}/backtest?hours=24`) | | Counts matches on stored events. |
| `detection.sigma_enabled` | **Rules** (Sigma toggle) | true | Turns all Sigma rules off or on. |
| Sigma rule on/off | **Rules** | on after import | Per rule; survives re-imports. |
| `ti.sigma_pinned_version`, `ti.sigma_pinned_sha256` | Platform settings / intel sources | unset | Sigma is imported only from a pinned SigmaHQ release whose `sigma_core.zip` matches the SHA-256. Without both, no Sigma rules are imported. |
| `detection.business_hours`, `detection.business_tz` | settings table | UTC | Used by business-hours rules. |
| `imds_allowed_processes` | settings table | empty | Extra processes allowed to reach the cloud metadata address (rule `NET-IMDS-001`). |

### 7.2 IOC and threat intelligence

| Setting | Default | Effect |
|---|---|---|
| Intel sources (ThreatFox, OTX, Feodo, Spamhaus BCL, Sigma) | enabled when a key is set; Feodo needs no key | Synced at start and every 24 h, or on demand. |
| `threat_intel.retro_hunt` | on | After a sync, new IOCs are searched in stored events (up to 500 alerts per sync). |
| Manual IOCs | **Rules** / `POST /api/v1/iocs/manual` | Analyst IOCs, treated like feed IOCs. |
| `ioc_known_good_enabled` | true | Lowers hash-IOC hits on package-verified or OS binaries. |
| `ioc_otx_min_confidence` | 70 | OTX matches below this confidence never alert. OTX scores run from 5 to 85: a pulse reaches 70 only when it names an adversary and malware families and has ATT&CK techniques or references. Other feeds are not affected. |
| `imds_allowed_processes` | empty | Comma-separated extra process names allowed to reach the metadata service. Cloud guest agents and their child scripts, the cloud CLIs, and non-interpreter system programs (OS Login lookups from `sshd`, `sudo`, `id`) are always allowed. |
| `ioc_hash_prevalence_hosts` | 3 | Hash IOC severity is adjusted when the hash is seen on at least this many hosts. |
| Confidence | fixed | IOCs below 25 % confidence are ignored; 25 to 49 % are lowered one level. |

### 7.3 Suppressions (**Suppressions**, `/api/v1/suppressions`)

Fields: `rule_id` (a built-in id, `IOC:<source>:<type>` or `SIGMA:<id>`; required), `match_mode` (`exact` or `prefix`, prefix at least a minimum length and matching a registered rule), `host`, `process_name`, `image_path_glob`, `parent_process`, `user_name`, `cmdline_contains`, `file_path_glob`, `reason` (required, 500 characters), expiry in days (at most 365) or `permanent`. All matchers are ANDed; empty means any. The list shows how many alerts each suppression removed in the last 30 days. Any signed-in role except viewer can create, edit and delete suppressions (there is no admin check).

### 7.4 Alert rules (**Alert rules**, `/api/v1/alert-rules`)

Fields: `name`, `enabled`, `event_type`, `severity` (minimum event severity to match), `host_match`, `user_match`, `process_match`, `command_line_match`, `src_ip_match`, `dst_ip_match`, `dns_match`, `os_match`, `source_match`, `match_mode` (`substring` or `regex`), `exclude_host`, `exclude_user`, `exclude_process`, `threshold_count` (0 to 100,000), `threshold_window_sec` (1 to 86,400 when the count is above 1). The engine runs every 30 s. The alert takes the event's severity. **Test** runs a rule against stored events. Any role except viewer can create, edit and delete rules.

### 7.5 Live response and response

| Setting | Effect |
|---|---|
| `live_response.enabled` in the build | The only switch. There is no server-side toggle. |
| Role | Shell sessions, response actions, live hunts, the live process list and collected-file download are admin-only. |
| Session limit | 60 minutes per shell session (hard cap). |
| Action timeout | 3 minutes for an action; the request waits up to 100 s and then returns `sent`. |
| Hunt limits | 500 hosts, 500 rows per host, 120 s per host; offline wait 1 h, 24 h, 7 d or until done (30-day hard expiry). 23 query kinds (see capability.md, 7.2); `recent_files` takes a window of 1 to 720 hours, `registry` a key path, `loaded_modules` a module name. |

### 7.5a Prevention (**Endpoint → Prevention**, `/api/v1/prevention`)

Admin only to change; every change is audited (`prevention.policy.update`). Agents pick a change up at their next fetch (every 15 minutes).

| Setting | Default | Effect |
|---|---|---|
| Mode per type: IP, hash, domain | audit | off, audit (alert only) or enforce. |
| Enforce only on hosts tagged | empty (every host) | Hosts without one of these tags run enforce types in audit. |
| Extra folders to check for new files | none | Added to Downloads, Desktop, temp folders and removable media, for example `/srv/uploads` or `D:\Shares\Incoming`. |
| ThreatFox minimum confidence (API only: `min_confidence`) | 75 | Entries below it are not sent. |
| Maximum age (API only: `max_age_days`) | 90 days | By the feed's first-seen date; manual indicators keep their own expiry. |
| Caps (API only: `max_ips`, `max_hashes`, `max_domains`) | 20,000 IPs, 200,000 hashes, 50,000 domains | Over a cap, manual entries, then the most confident and most recent, are kept. |

The indicators come from ThreatFox, Feodo Tracker, manual IOCs (**Threat intelligence**) and malicious fleet verdicts. OTX is never used for blocking.

### 7.6 Agent health alerts

Fixed in `agent_health_engine.go`: checks every 60 s; silent agent after 10 minutes (Medium, High after one hour); queue depth 2,000 or more; 50 or more new dropped events since the previous heartbeat; a collector missing from the heartbeat; Sysmon not running; a detection engine cursor stalled for 10 minutes. A 10-minute grace period follows a management restart.

### 7.7 Agent builder and enrollment

| Setting | Default | Limits |
|---|---|---|
| Token lifetime | 720 h (30 days) | 1 h to 2,160 h (90 days) |
| Token host limit | 500 | 1 to 100,000 |
| Cached build lifetime | 14 days | |
