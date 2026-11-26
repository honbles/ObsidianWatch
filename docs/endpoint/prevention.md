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

## 6. Not included

Pre-execution blocking of programs (Linux fanotify permission events: a stalled agent could hang program launches), writing firewall rule sets or hosts-file entries, DNS filtering or content categories, device control, and server lockdown. See the decisions in the device management and prevention spec.
