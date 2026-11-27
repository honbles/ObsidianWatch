# Endpoint prevention

Agents check what their host does against a list of known-malicious IP addresses, file hashes (SHA-256) and domains that the server publishes. For each type the policy is **off**, **audit** (raise an alert, change nothing) or **enforce** (act as well). The server writes no policy to hosts. The only host changes are the ones the existing response actions make (kill, quarantine, block IP), plus, on Linux, a kernel program that the agent removes when it stops.

Console: **Endpoint → Prevention**. API: `GET /api/v1/prevention` (policy and list contents), `PUT /api/v1/prevention` (admin; audited as `prevention.policy.update`).

Implemented in: `management/backend/internal/api/prevention.go`, `prevention_sigs.go`, `internal/store/prevention.go`, migration `074_prevention.sql`; `agents/*/internal/prevention/`; Linux kernel program `agents/linux/internal/prevention/bpf/block.bpf.c`.

## 1. What each type can and cannot do

| Type | Enforce on Linux | Enforce on Windows and macOS | Limits |
|---|---|---|---|
| IP | eBPF programs on `connect()` and UDP `sendmsg()` (cgroup v2 root) refuse the call with `EPERM` before any packet is sent, for every process. | The address is blocked with the `block_ip` response action as soon as a connection to it is seen. The first connection gets through. | Hard-coded IPs only; a domain that resolves to a new address is covered by the domain type. |
| Hash | A listed program is killed right after it starts and its file is quarantined. New files in watched folders are quarantined once they stop changing. Running processes are swept when a new list arrives. | Same, except that there is no sweep of running processes: they are checked when they start. Without Sysmon the agent hashes the image itself (cached). | The program runs briefly before it is killed. Files over 200 MiB are not checked. Operating-system binaries (`/usr/bin`, `/bin`, `/usr/lib`, `C:\Windows`, `/System` and similar) and the agent are never killed or quarantined; a match there is reported as `failed`. |
| Domain | The addresses in the DNS answer are added to the kernel block for 24 hours. | The addresses are blocked with `block_ip` for 24 hours. | The lookup itself is not prevented, and the connection that follows it may already be under way. Linux rarely records domain names (and Windows only with the DNS-Client channel), so this type mostly alerts. |

Watched folders for new files: Downloads and Desktop of every user, temp directories (`/tmp`, `/var/tmp`, `/dev/shm`; `%TEMP%`, `C:\Windows\Temp`), removable media (`/media/*/*`, `/run/media/*/*`, `/Volumes/*`), and the policy's extra folders (for example `/srv/uploads` or `D:\Shares\Incoming`). They are scanned every 10 seconds, 4 levels deep, 20,000 entries per pass. The first pass only records what exists.

## 2. Where the list comes from

The server builds one list for all agents, rebuilt every 10 minutes and whenever the policy changes:

| Source | Used for | Rule |
|---|---|---|
| ThreatFox | IP, hash, domain | Confidence at least the policy minimum (default 75), first seen (by ThreatFox's own `first_seen`) within the maximum age (default 90 days). |
| Feodo Tracker | IP | The recommended (actively seen) list only, at confidence 90. |
| Manual indicators | all | Always, until their own expiry (default one year). |
| Fleet verdicts | hash | Hashes seen in the fleet that the reputation lookups judged malicious (5 or more engines). |
| AlienVault OTX | never | Community-submitted and noisy: detection only. |

Never sent, whatever a feed says: private, loopback, link-local, carrier-grade NAT, documentation and reserved addresses; public resolvers (Google, Cloudflare, Quad9, OpenDNS and others); domains of large shared platforms (Google, Microsoft, Apple, AWS, Cloudflare, Akamai, GitHub and others) and their subdomains; the empty-file hash. On the agent, the manager's addresses, the host's resolvers (`/etc/resolv.conf`) and private addresses are also never blocked.

Each entry carries its own expiry. The agent drops expired entries itself, so removal works when the server is unreachable. Over a cap (default 20,000 IPs, 200,000 hashes, 50,000 domains), manual entries are kept first, then the most confident and most recently seen; `GET /api/v1/prevention` reports a truncated type. Confidence, age and caps are set through `PUT /api/v1/prevention`; the page shows only the modes, the canary tag and extra folders.

## 3. Delivery and state on the agent

The agent asks `GET /api/v1/agent/prevention` on the backend port with its certificate (the backend forwards the identity to management, like the install-key calls) 20 seconds after start, then every 15 minutes. It sends the version it has; an unchanged list answers with the modes only. The list and modes are saved in the agent's data directory (`prevention.json` under `/var/lib/obsidianwatch` or `C:\ProgramData\ObsidianWatch`), so enforcement continues across restarts and server outages. Addresses blocked with `block_ip` because of a domain answer are remembered and lifted when they lapse; blocks someone else made are never lifted.

Agent configuration (`prevention` in `agent.yaml`, both optional): `enabled` (default true) turns the feature off entirely; `kernel` (default true) disables the Linux kernel program. `OW_DISABLE_EBPF=1` in the service environment disables it as well. The modes always come from the server.

## 4. Canary first

**Enforce only on hosts tagged**: when set, hosts without one of these tags (Fleet → host → tags) run enforce types in audit. Recommended order: everything in audit for a few days, check the alerts, enforce on a `canary` tag, then on everyone. Saving enforce with no canary tag asks for confirmation.

## 5. Alerts

Every match is a `prevention` event (searchable on Events) with `kind`, `indicator`, `mode`, `action` (`audit`, `blocked`, `ip_blocked`, `killed`, `quarantined`, `killed+quarantined`, `failed`), the source and malware family, and the process. Repeats for the same indicator and process are reported once per 10 minutes.

| Rule | Severity | When |
|---|---|---|
| `PREV-IP-1` Connection to a known malicious address blocked | High | IP, stopped |
| `PREV-IP-0` Connection to a known malicious address | High | IP, not stopped (audit or failed) |
| `PREV-HASH-1` Known malicious file stopped | High | hash, killed and/or quarantined |
| `PREV-HASH-0` Known malicious file present or running | Critical | hash, not stopped |
| `PREV-DNS-1` Lookup of a known malicious domain; addresses blocked | Medium | domain, addresses blocked |
| `PREV-DNS-0` Lookup of a known malicious domain | Medium | domain, not blocked |

## 6. Is a host protected? (Fleet → host → Overview → Protection)

`GET /api/v1/agents/{id}/protection` (any signed-in role) combines what the server intends for the host and what the agent reports.

- **Verdict.**
  - *Protected*: files and programs, or at least one other type, are set to stop.
  - *Audit only*: matches are alerted on but nothing is stopped. Also shown when the host's list is more than 2 hours old.
  - *Not protected*: every type is off, or the host's list is empty so nothing can match, for example when the server cannot reach its threat feeds.
  - *Unknown*: the agent has not reported for 10 minutes, or is too old to report.
- **What it does.** The mode each type runs on the host. An asterisk marks a mode the agent has not picked up from the server's policy yet. Also shown: the size and age of the host's list, whether connections are refused in the kernel (Linux), and how many folders are watched for new files.
- **Last 24 hours.**
  - Agent counters, sent in every health heartbeat (`raw.protection`): files checked (watched folders, file events and scans), programs checked (process starts), connections checked, and DNS answers checked.
  - Server counts from prevention events: threats stopped, and threats not stopped.
- **Test protection** (admin; response action `test_protection`). The server sends a one-off random token; the client's input is ignored.
  - The agent puts the token's SHA-256 on its own list for 10 minutes. After one watcher pass, it writes `obsidianwatch-protection-test-<hash>.txt` into a writable watched folder, preferring a temp folder. The file is harmless text.
  - The file watcher must find the file like any new download.
  - **Pass**: a prevention event for that hash arrives within 3 minutes. In enforce mode the file is quarantined; in audit it is reported and removed after 3 minutes.
  - **Fail**: the agent does not answer, files are off, or nothing detects the file.
  - Test events carry `ioc_source` `obsidianwatch-test`. They raise no alert and are not counted as threats.
  - What the test exercises: the watched folders, hashing, matching, the action and delivery to the server. It does not test list download; the list age in *What it does* covers that.
- **Scan** (admin; response action `scan`, parameters `path` or `kind: "whole"`).
  - The agent hashes every file under the folder, or under `/` (every fixed drive on Windows) for the whole disk, and checks each against its list.
  - A whole-disk scan skips virtual and operating-system folders: `/proc`, `/sys`, `/dev`, `/run`, `/snap`, container storage, `/usr`, `/bin`, `/lib`, `/System`, `C:\Windows` and similar.
  - Limits: files over 200 MiB are not hashed; at most 500,000 files; at most 2 hours; it pauses every 200 files to stay in the background. One scan runs at a time per host.
  - Matches go through the normal path: quarantined in enforce, reported in audit, and alerted as `PREV-HASH-*`.
  - At the end the agent sends a `prevention_scan` event with: files scanned, threats found, files unreadable or too large, the duration, and up to 2,000 executables (by execute bit or extension) with their SHA-256.
  - The server queues those executables for the tiered hash reputation lookups (Team Cymru, MalwareBazaar, CIRCL, Hybrid Analysis, VirusTotal if configured). A malicious verdict raises a hash alert.

## 7. Outcome on alerts

Every prevention alert records what the agent did: quarantined, killed, killed and quarantined, blocked, not stopped (audit), or failed.

- The alert list and alert page show a **✓** badge for a stopped threat (quarantined, killed or blocked) and a **! Not stopped** badge otherwise.
- The **Prevention** filter on Alerts selects either group.
- Prevention alerts raised before this version are labelled from their rule: `PREV-*-1` is stopped, `PREV-*-0` is not.

## 8. Not included

Pre-execution blocking of programs (Linux fanotify permission events: a stalled agent could hang program launches), writing firewall rule sets or hosts-file entries, DNS filtering or content categories, device control, and server lockdown. See the decisions in the device management and prevention spec.
