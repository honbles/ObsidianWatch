# ObsidianWatch

Self-hosted, full-stack SIEM. One repository, one command to deploy.

ObsidianWatch collects security telemetry from **endpoints**, **cloud accounts** and **Git platforms**, runs it through a single **detection engine** (400+ built-in signatures, Sigma, threat-intel IOCs, correlation), and gives analysts one dashboard for alerts, search, posture and response.

## Status

| Module | Status | What it covers |
|---|---|---|
| [Endpoint monitoring](#3-endpoint-monitoring) | ✅ Complete | Linux, Windows, macOS agents |
| [Cloud security](#4-cloud-security) | ✅ Complete | AWS, Azure (incl. Entra ID), GCP: log ingestion, CSPM, CIS, compliance, blast radius |
| [Git and code scanning](#5-git-and-code-scanning) | ✅ Complete | GitHub, GitLab, Azure DevOps: audit, commits, secrets, SAST, SCA, posture |
| [Detection engine](#6-detection-engine) | ✅ Complete | Signatures, Sigma, threat intel, correlation, alerting, AI analysis |
| [Application monitoring](#8-under-development) | 🚧 Under development | |
| [Network monitoring](#8-under-development) | 🚧 Under development | Network probe code exists but is not yet a supported feature |

---

## Contents

1. [Architecture](#1-architecture)
2. [Install the platform](#2-install-the-platform)
3. [Endpoint monitoring](#3-endpoint-monitoring)
4. [Cloud security](#4-cloud-security)
5. [Git and code scanning](#5-git-and-code-scanning)
6. [Detection engine](#6-detection-engine)
7. [Settings and threat intelligence](#7-settings-and-threat-intelligence)
8. [Under development](#8-under-development)
9. [Dashboard reference](#9-dashboard-reference)
10. [Operations](#10-operations)
11. [Development](#11-development)

---

## 1. Architecture

```
 Endpoints (Linux / Windows / macOS)            Cloud (AWS / Azure / GCP)     Git (GitHub / GitLab / ADO)
        │  TLS :8443  (API key + install key)          │  API polling every 5 min      │  polling + webhooks
        ▼                                              ▼                               ▼
 ┌──────────────┐   TimescaleDB   ┌─────────────────────────────────────────────────────────────┐
 │   backend    │ ───────────────►│  Management API (:8444 HTTPS)                               │
 │ event ingest │                 │   detection engine · alert engine · threat intel · AI       │
 └──────────────┘                 │   cloud engine · DevOps engine · SAST · Agent Builder       │
                                  └──────────────────────────┬──────────────────────────────────┘
                                                             ▼
                                              React dashboard (HTTPS :443)
```

| Service | Role | Host port |
|---|---|---|
| `cert-init` | One-shot: generates CA + server certificate for the host IP/domain | – |
| `timescaledb` | Event and platform database (internal network only) | – |
| `backend` | Agent event ingest (TLS, API-key auth, optional mTLS) | `8443` |
| `mgmt-api` | Management API, detection/alert/cloud/DevOps engines, Agent Builder | `8444` |
| `mgmt-ui` | Dashboard (`:80` only redirects to HTTPS) | `443`, `80` |

### Repository layout

```
obsidianwatch/
├── agents/
│   ├── linux/            Linux agent  — systemd service
│   ├── windows/          Windows agent — Windows Service + tamper DACL
│   ├── macos/            macOS agent  — launchd daemon
│   └── network/          Network probe (under development)
├── backend/              Agent ingest server
├── management/
│   ├── backend/          Management API (alerts, detections, cloud, DevOps, AI, Agent Builder)
│   ├── frontend/         React + Tailwind dashboard
│   └── docker/           Management image, server.yaml, Semgrep rules
├── cert-init/            Certificate generator
├── docs/onboarding/gcp/  Terraform for a read-only GCP collector service account
├── docker-compose.yml    Whole stack
└── .env.example          Required secrets
```

---

## 2. Install the platform

**Requirements:** Linux host with Docker + Docker Compose, ports `443`, `80`, `8443`, `8444` reachable from your users and endpoints. Outbound internet is needed for threat-intel feeds, OSV/NVD lookups and cloud/Git API polling.

### 2.1 Configure

```bash
cp .env.example .env
```

Fill in `.env`. Compose refuses to start if a required value is missing.

| Variable | Required | How to generate / purpose |
|---|:---:|---|
| `HOST_IP` | ✅ | Server LAN/public IP. Becomes a SAN in the TLS certificate |
| `DB_PASSWORD` | ✅ | `openssl rand -hex 16` |
| `AGENT_API_KEY` | ✅ | `openssl rand -hex 32`. Shared key agents use to authenticate |
| `JWT_SECRET` | ✅ | `openssl rand -hex 32` (≥ 32 chars). Signs dashboard logins |
| `OW_SECRET_KEY` | ✅ | `openssl rand -base64 32`. Encrypts cloud/Git credentials, API keys and SMTP password at rest (AES-256-GCM). **Back it up separately. Losing it makes stored credentials unrecoverable** |
| `BACKEND_DOMAIN` | – | Domain name agents should use; added to the certificate |
| `EXTRA_SAN_DNS` | – | Extra comma-separated DNS names for the certificate |
| `OW_ALLOWED_ORIGINS` | – | Extra browser origins allowed to open WebSockets |

Services refuse to start if they detect placeholder values such as `changeme`.

### 2.2 Start

```bash
sudo docker compose up -d --build
sudo docker compose ps
sudo docker compose logs cert-init
```

The first build compiles the management image (Go, Semgrep and, best-effort, CodeQL) and takes several minutes.

### 2.3 First login

1. Open `https://<server-ip>` (self-signed certificate unless you supplied a domain).
2. The **setup wizard** appears before login. Fields:

| Field | Required | Notes |
|---|:---:|---|
| Agent API Key | ✅ | Same value as `AGENT_API_KEY` |
| Backend Domain | – | Adds a domain to the certificate SAN; clears the agent cache |
| Backend URL / Management URL | auto | Pre-filled from detected IPs; override if needed |
| Groq API Key | – | AI alert analysis (primary) |
| Anthropic API Key | – | AI alert analysis (fallback) |
| ThreatFox API Key | – | IOC feed |
| OTX API Key | – | AlienVault OTX IOC feed |

3. The first start creates an `admin` account with a **random one-time password**:
   ```bash
   sudo docker compose logs mgmt-api | grep -A4 "First-run admin"
   ```
   Log in and change it immediately.
4. Re-run the wizard any time from **Agent Builder → Reconfigure setup**.

### 2.4 Roles

| Role | Access |
|---|---|
| `admin` | Everything, including Users, Settings, Agent Builder, Live Response |
| `analyst` | Triage alerts, search, investigate |
| `viewer` | Read-only (enforced server-side) |

Notification channels: **SMTP email** (Settings → Email Alerts), plus **syslog forwarding** and **webhooks** (configured through the API, see [7.1](#71-settings-page-admin-only)).

---

## 3. Endpoint monitoring

Agents run as a system service on each host, collect telemetry locally, and forward it over TLS to the backend. Events are buffered in a durable on-disk queue (up to 100,000 rows), so nothing is lost when the backend is unreachable. Each agent applies per-source rate limiting (500 events/s) and a 5 s de-duplication window.

### 3.1 How to get an agent onto an endpoint

Agents are **compiled by the platform with your configuration embedded** (backend URL, API key, CA certificate). The endpoint needs no config file and no certificate files.

1. In the dashboard open **Agent Builder** (admin only). Fields are pre-filled from setup.
2. Choose a platform and click **Build**. First compile takes 1–2 minutes; later downloads of the same platform are served from cache.

   | Platform key | Output | Target |
   |---|---|---|
   | `linux` | `obsidianwatch-linux-agent` | Linux x86-64 |
   | `windows` | `obsidianwatch-win-agent.exe` | Windows x86-64 |
   | `macos` | `obsidianwatch-macos-agent` | macOS Intel |
   | `macos-arm64` | `obsidianwatch-macos-agent` | macOS Apple Silicon |

   Tick **Enable live response** only if you accept an analyst remote shell on the endpoints (off by default).
3. Download the zip. It contains the binary, `SHA256SUMS`, an `INSTALL.md`, and for macOS an MDM profile `ObsidianWatch-FullDiskAccess.mobileconfig`.
4. Copy the binary to the endpoint and install (below).
5. The agent generates a random **install key**, registers it with the server, and starts collecting. It appears under **Agents** within seconds.

> If you change `HOST_IP`/domain or regenerate certificates, rebuild all agents. The new CA is embedded at build time.

**Linux**
```bash
chmod +x obsidianwatch-linux-agent
sudo ./obsidianwatch-linux-agent install
systemctl status obsidianwatch-agent
sudo journalctl -u obsidianwatch-agent -f
```

**macOS**
```bash
chmod +x obsidianwatch-macos-agent
shasum -a 256 -c SHA256SUMS            # binaries are not yet code-signed or notarized
sudo ./obsidianwatch-macos-agent install
```
Grant **Full Disk Access** to `/usr/local/bin/obsidianwatch-agent` (System Settings → Privacy & Security), or push `ObsidianWatch-FullDiskAccess.mobileconfig` through your MDM (Jamf, Kandji, Intune). Full Disk Access is required for the `eslogger` exec stream and the audit-trail file monitor; without it the agent falls back to polling and kqueue.

**Windows** (elevated PowerShell)
```powershell
.\obsidianwatch-win-agent.exe install
Get-Service ObsidianWatchAgent
Get-Content C:\ProgramData\ObsidianWatch\agent.log -Tail 50
```

Re-running `install` on a host that already has the agent upgrades it in place.

### 3.2 Tamper protection and uninstall

| OS | Protection applied at install |
|---|---|
| Linux | `chattr +i` on binary, unit file and install-key file; systemd `NoNewPrivileges`, `ProtectSystem=strict`, `MemoryMax=256M` |
| macOS | `chflags uchg` on binary, launchd plist and install-key file |
| Windows | Service DACL denies stop/delete to everyone except SYSTEM; binary ACL restricted to SYSTEM + Administrators |

Uninstall needs the **install key** shown on the dashboard (**Agents → shield icon**; the key can be regenerated there). The management server verifies the key and rotates it; the local copy is consulted only if the server is unreachable.

```bash
sudo ./obsidianwatch-linux-agent uninstall     # or macos agent
# Enter install key when prompted
```
```powershell
.\obsidianwatch-win-agent.exe uninstall        # elevated
```

A stop signal reaching an agent (service stop, `kill`, uninstall) sends a final `agent.tamper` event (severity 4) before it exits.

### 3.3 Install locations

| | Linux | macOS | Windows |
|---|---|---|---|
| Binary | `/usr/local/bin/obsidianwatch-agent` | `/usr/local/bin/obsidianwatch-agent` | `C:\Program Files\ObsidianWatch\Agent\agent.exe` |
| Service | `obsidianwatch-agent` (systemd) | `com.obsidianwatch.agent` (`/Library/LaunchDaemons`) | `ObsidianWatchAgent` (auto-start) |
| Install key | `/etc/obsidianwatch/.install_key` | `/etc/obsidianwatch/.install_key` | state file, also on dashboard |
| Queue | `/var/lib/obsidianwatch/` | `/var/lib/obsidianwatch/` | `C:\ProgramData\ObsidianWatch\queue` |
| Log | journald | `/var/log/obsidianwatch/agent.log` | `C:\ProgramData\ObsidianWatch\agent.log` |
| Agent ID | `/etc/machine-id` | hardware UUID | hostname |

### 3.4 Everything the endpoint agents collect

✓ = on by default in Agent Builder output. All collectors can be switched off in the embedded config.

| Telemetry | Linux | Windows | macOS |
|---|:---:|:---:|:---:|
| Authentication, logon, SSH, sudo | ✓ | ✓ | ✓ |
| Process create / terminate | ✓ | ✓ | ✓ |
| Executable SHA-256 at exec time | ✓ | via Sysmon | ✓ |
| Network connections | ✓ | ✓ | ✓ |
| DNS queries | ✓ | ✓ | ✓ |
| File integrity monitoring (FIM) | ✓ | ✓ | ✓ |
| Writer attribution (which process wrote the file) | ✓ | via Sysmon | ✓ |
| Sensitive config / persistence monitoring | ✓ | ✓ (registry) | ✓ |
| Windows Event Log (full field extraction) | – | ✓ | – |
| Sysmon (auto-installed) | – | ✓ | – |
| PowerShell script-block / module logging | – | ✓ | – |
| Windows Defender detections and posture changes | – | ✓ | – |
| WMI persistence, domain-controller channels | – | ✓ | – |
| USB / removable media | ✓ | via PnP events | ✓ |
| Software install / remove | ✓ (dpkg) | – | – |
| Container start events (risky settings) | ✓ (Docker) | – | – |
| Application log tailing | – | ✓ (optional) | – |
| Vulnerability and hygiene scan (every 5 days) | ✓ | ✓ | ✓ |
| Geolocation (every 30 min) | ✓ (IP) | ✓ (GPS/Wi-Fi/IP) | ✓ (IP) |
| Agent health heartbeat (60 s) | ✓ | ✓ | ✓ |
| Live response (analyst shell, opt-in) | ✓ | ✓ | ✓ |
| Tamper / shutdown signal | ✓ | ✓ | ✓ |

#### Linux

| Collector | Mechanism | Detail |
|---|---|---|
| Process | Netlink proc connector (real time) + `/proc` poll every 2 s | PID, PPID, command line, exe path, user, SHA-256 of `/proc/<pid>/exe` (works even if the binary was deleted after launch) |
| Network | `/proc/net/tcp,tcp6,udp,udp6` diff every 30 s | New/closed connections with PID and process name. Connections shorter than the interval can be missed |
| DNS | `resolvectl` → resolved journal → `/proc/net/udp` port-53 → dnsmasq/bind logs | Domain names where available |
| Journald | `journalctl --output=json --follow` | SSH logins/failures, sudo, PAM, `su`, cron, kernel OOM and module loads |
| FIM | fanotify (with PID), inotify fallback | Default paths: `/home` (recursive), `/root` (recursive), `/tmp`, `/var/tmp`, `/etc`, `/opt`. Writer exe, PPID and user resolved from `/proc` |
| Config monitor | inotify | `/etc/passwd`, `/etc/shadow`, `/etc/sudoers`, `/etc/ssh/sshd_config`, `/etc/hosts`, `/etc/systemd/system`, `/root/.ssh` (emitted as `registry`-type events) |
| USB | `/sys/bus/usb/devices` poll | Mass storage = Low severity |
| Software | Tails `/var/log/dpkg.log` | Debian/Ubuntu only; RPM hosts are skipped |
| Containers | Docker Engine socket | Flags privileged, host network/PID, `docker.sock` mounts. Skipped if no socket |
| Vulnerability scan | Every 5 days | Full TCP port scan 1–65535 with banner/version, installed packages (dpkg/rpm/apk), services, kernel/OS, SUID binaries, world-writable dirs |
| Live response | PTY running `/bin/bash` through the management WebSocket tunnel | Opt-in |

**Requirements:** root, kernel ≥ 3.2. `journalctl` for journal collection. Docker socket for container events.

#### Windows

| Collector | Mechanism | Detail |
|---|---|---|
| Event Log | `wevtapi` subscriptions, full XML field extraction | Default channels: Security, System, Application, PowerShell/Operational, Windows Defender/Operational. Extended set in `agents/windows/configs/agent.yaml` adds WMI-Activity, Kerberos, Directory Service, DNS Server and DC channels (skipped silently if not a DC) |
| Sysmon | Sysmon/Operational channel | Event IDs 1, 3, 5, 6, 7, 8, 9, 10, 11, 12–14, 15, 17, 18, 22, 23 mapped to process/network/file/registry/DNS events |
| Process | ETW Kernel-Process, WMI polling fallback | Create/terminate |
| Network | `iphlpapi` TCP/UDP table diff every 30 s | |
| Registry | `RegNotifyChangeKeyValue` | Run/RunOnce, Services, IFEO, Winlogon, Session Manager, Policies\Explorer\Run (default). Wider list in `configs/agent.yaml`: LSA, Print Monitors, Active Setup, Defender Exclusions, Task Cache, SecurityProviders and more |
| DNS | DNS-Client/Operational channel | No Sysmon needed; the agent enables the channel if it is off |
| FIM | `ReadDirectoryChangesW` | `System32`, `System32\Tasks`, `System32\drivers`, `System32\wbem` by default. Wider list adds SysWOW64, Startup folders, GroupPolicy, `C:\Users`, `C:\ProgramData` |
| App logs | File tail (json / text / combined) | Configure `app_logs` in the config; offsets survive restarts |
| Vulnerability scan | Every 5 days | Port scan plus hygiene checks: antivirus, firewall, remote access, AutoRun, SMB, user accounts, UAC, audit policy |
| Location | Windows Location API (GPS → Wi-Fi → IP) | |
| Live response | `cmd.exe` through the management tunnel, runs as SYSTEM | Opt-in |

**Preflight on start:** makes sure the `EventLog` and `WinRM` services are running (re-enabling them if disabled), checks Sysmon, and installs it if missing (downloads from Sysinternals, or bundles it when built with `-tags embed_sysmon`; baseline config version 2). The health heartbeat reports Sysmon state, and the platform alerts when Sysmon is not running, because process detection is largely blind without it.

**Audit settings:** when the agent is run interactively as Administrator it enables Event 4688 command-line logging and PowerShell script-block (4104) and module (4103) logging. For service-only deployments, set the same via Group Policy.

**Requirements:** Windows 10 / Server 2016 or later, Administrator for install.

#### macOS

| Collector | Mechanism | Detail |
|---|---|---|
| Unified log | `log stream` with security predicates | securityd, OpenSSH, authorization/sudo, launchd, crashes |
| Process | `sysctl KERN_PROC_ALL` poll every 2 s + `eslogger` (Endpoint Security) | `eslogger` needs macOS 13+ and Full Disk Access; when healthy it supplies each exec once, otherwise the poller is used. Executable path and SHA-256 recorded |
| Network | `netstat` diff every 30 s | |
| DNS | `lsof` port-53 detection | |
| FIM | OpenBSM `/dev/auditpipe` (PID attribution), kqueue fallback | Default: `/usr/bin`, `/usr/local/bin`, `/private/tmp`. Wider list in `configs/agent.yaml` adds `/usr/sbin`, `/bin`, `/sbin`, `/tmp` |
| Config monitor | kqueue | `/etc/passwd`, `/etc/sudoers`, `/etc/ssh/sshd_config`, LaunchDaemons and LaunchAgents. Wider list adds per-user LaunchAgents, `~/.ssh`, periodic/cron, emond, login hooks, shell profiles |
| USB | `system_profiler SPUSBDataType` every 15 s | |
| Vulnerability scan | Every 5 days | |
| Live response | Shell through the management tunnel | Opt-in |

### 3.5 Changing what the agents collect

The configuration is generated by the Agent Builder (`buildLinuxYAML`, `buildWindowsYAML`, `buildMacOSYAML` in `management/backend/internal/api/agent_builder.go`). To change collectors, FIM paths, registry keys or poll intervals:

1. Edit the matching function (use `agents/<os>/configs/agent.yaml` as the full reference of available options).
2. `sudo docker compose up -d --build mgmt-api`
3. Rebuild the platform in **Agent Builder** and redeploy the binary.

### 3.6 Endpoint features in the dashboard

- **Agents**: inventory, online state, per-host process tree and threat graph, file hashes, location history and impossible-travel, vulnerability results (OSV for Debian/Ubuntu/Alpine, NVD fallback), CIS-style hygiene checks, AI root-cause analysis, install-key and tamper controls.
- **Live Response** (admin): interactive terminal on Linux, Windows and macOS hosts with session transcripts.
- **Endpoint compliance**: host hygiene derived from the agent's scan (a CIS-inspired subset; it cannot see file permissions, sysctl or auditd rules).
- **Fleet prevalence**: how many hosts have run a binary and when it was first seen; one-host-only binaries from user-writable paths raise a low-severity alert once a week of history exists.
- **Agent health alerts**: agent gone silent, collector stopped, queue backing up, drops rising, Sysmon down.

---

## 4. Cloud security

Add connectors under **Cloud → Add connector**. Credentials are encrypted with `OW_SECRET_KEY`. Each connector can be tested before saving; the GCP test reports exactly which permissions are missing.

### 4.1 Connect an account

**AWS**

| Field | Notes |
|---|---|
| Access Key ID / Secret Access Key | Base identity |
| Region | Home region |
| Role ARN (recommended) | The connector assumes this role (STS AssumeRole) for every call |
| External ID | Shared secret from the role's trust policy |
| Account ID | Optional |

Permissions: attach `SecurityAudit` (or `ReadOnlyAccess`) plus `cloudtrail:LookupEvents`, `guardduty:List*/Get*`, `securityhub:GetFindings`, and `s3:ListBucket`/`s3:GetObject` if you read CloudTrail from S3. **AWS Organizations:** use management-account credentials and a read-only role name present in each member account to import every active account as its own connector.

**Azure**

1. Entra ID → App registrations → New registration → create a client secret.
2. Assign the app **Monitoring Reader** and **Reader** on each subscription. Add **Security Reader** for Defender and CIS checks, and **Log Analytics Reader** on a workspace to ingest resource logs.
3. Graph permission `AuditLog.Read.All` for Entra sign-in and audit logs.
4. In ObsidianWatch enter Tenant ID, Client ID, Client Secret, Subscription ID(s) (one, a comma list, or `*` for all enabled), and optionally Log Analytics workspace ID(s).

**GCP**

1. Create a service account, or run the Terraform in `docs/onboarding/gcp/main.tf`:
   ```bash
   cd docs/onboarding/gcp
   terraform init && terraform apply -var project_id=my-proj
   # organisation-wide:
   terraform apply -var project_id=my-proj -var org_id=1234567890
   ```
   It creates a read-only service account with logging viewer, private log viewer, security reviewer and related roles.
2. Create a JSON key **or** (preferred) use Workload Identity Federation by pasting an `external_account` config; the token file must live under `/var/run/secrets/`.
3. Enter the service-account JSON, optional Project ID(s) (comma list, or `*`), and Organization/Folder ID to discover every project under an org or folder. Enable the Cloud Asset and Security Command Center APIs for inventory and SCC findings.

### 4.2 What is ingested (polled every 5 minutes)

| Provider | Sources | Event types |
|---|---|---|
| AWS | CloudTrail (LookupEvents or S3), GuardDuty, Security Hub (High/Critical, GuardDuty excluded to avoid duplicates) | `cloud.cloudtrail`, `cloud.guardduty`, `cloud.securityhub` |
| Azure | Activity Log, Entra sign-ins, Entra directory audit, Defender for Cloud alerts, NSG flow logs, resource diagnostic logs via Log Analytics (Key Vault, AKS, Firewall, App Service) | `cloud.azure_activity`, `cloud.entra_signin`, `cloud.entra_audit`, `cloud.azure_defender`, `cloud.azure_nsg_flow` |
| GCP | Cloud Audit Logs (Admin, Data Access, System Event), VPC Flow, Cloud DNS, Cloud IDS, GKE audit, Cloud Run, Load Balancer/Cloud Armor, policy-denied, Security Command Center findings | `cloud.gcp_audit`, `cloud.gcp_vpc_flow`, `cloud.gcp_dns`, `cloud.gcp_ids`, `cloud.gcp_gke_audit`, `cloud.gcp_cloud_run`, `cloud.gcp_lb_armor`, `cloud.gcp_policy_denied`, `cloud.gcp_scc` |

Expect **5–20 minutes** end to end because of provider log delay (see [latency](#68-latency-expectations)).

### 4.3 Posture and assessment (run on demand as background jobs)

| Capability | AWS | Azure | GCP |
|---|:---:|:---:|:---:|
| **CSPM** | IAM account/password policy, root MFA/keys, security groups, S3 public access, CloudTrail coverage, RDS, EBS, KMS rotation, VPC flow logs, public EBS snapshots, role trust policies, GuardDuty/Config/Security Hub enablement | RBAC, NSG, storage, VM, Key Vault, SQL, AKS, logging, Defender plans, Entra ID | Firewall, IAM, buckets, VMs, Cloud SQL, audit logging, service-account keys, KMS rotation, VPC/DNS logging, API keys, Vertex AI |
| **CIS benchmark** | CIS-inspired (own control IDs) | CIS Azure Foundations v2.0 subset | CIS GCP Foundations v2.0 subset |
| **Compliance mapping** | SOC 2, PCI-DSS v4.0, ISO 27001:2022, NIST 800-53 r5 | ✓ | SOC 2, PCI-DSS v4.0, ISO 27001:2022, NIST 800-53 r5 |
| **Asset inventory** | EC2, security groups, VPCs, S3, RDS, Lambda, IAM users/roles | Azure Resource Graph | Cloud Asset Inventory, with change deltas |
| **Blast radius / attack paths** | Internet → open SG → EC2 → role → privilege | SP → role → scope, VM → managed identity, open NSG | SA → VM → project IAM, public buckets, KMS, secrets |
| **Multi-scope** | Organizations import | Many subscriptions | Many projects / org / folder |
| **Suppression rules** | ✓ | ✓ | ✓ |
| **Scan history** | ✓ | ✓ | ✓ |

CIS and compliance results are explicitly labelled as **subsets / indicative mappings, not attestations**; the UI states how many controls were assessed. A check that could not run shows `UNKNOWN` / `NOT_ASSESSED`, never a false pass.

### 4.4 Cloud detections

- 160+ cloud signatures (AWS, Azure, GCP, cross-cloud) with MITRE mapping.
- Stateful **correlation** (`CORR-AZ-*`, `CORR-GCP-*`): new credentials then use from a new IP, privilege-grant bursts, recon bursts, audit logging disabled then sensitive operation, mass deletion, conditional-access disabled then new-country sign-in.
- **Behavioural baselines** (`ANOM-*`): first-seen source IP per principal, first-seen service, many IPs in one hour.
- Typed Entra rules read structured sign-in fields instead of substring matching.
- Auth correlation covers Entra sign-ins alongside endpoint logons.

---

## 5. Git and code scanning

Add connectors under **DevOps → Add connector**.

### 5.1 Connect a platform

| Platform | Credential | Required scopes |
|---|---|---|
| **GitHub** | Personal Access Token; organisation or username | `repo`, `read:org`, `admin:org` (audit log), `read:user` |
| **GitLab** | Access token; optional self-hosted URL | `api`, `read_api`, `read_audit_log` |
| **Azure DevOps** | PAT; organisation; optional project / URL | Code (Read), Project and Team (Read), Auditing (Read) for the audit stream |

Polling runs every 5 minutes. After saving, the dashboard shows a **webhook URL and secret** for real-time delivery (`/api/v1/devops/webhook/{id}`, `/webhook-gitlab/{id}`, `/webhook-azuredevops/{id}`). Add them in the platform's webhook / service-hook settings. Routes fail closed when no secret is configured.

| Platform | Webhook events |
|---|---|
| GitHub | `push`, `repository`, `member`, `org`, `workflow_run`, `team` |
| GitLab | push, merge request, member, group |
| Azure DevOps | `git.push`, `git.pullrequest.merged`, `build.complete`, pipeline run-state |

### 5.2 What is collected

- **Audit events**: member changes, repository visibility, PATs, webhook creation, org/group events. GitLab group audit needs Premium; project events still work on every tier.
- **Commits with diffs**, pipeline runs, CI/CD file changes (flagged as pipeline modification), sensitive-file commits (`.env`, `.pem`, `.key`, `id_rsa`).
- Every event becomes a `devops.*` event and is evaluated by the DevOps signatures (21 rules covering secret exposure, pipeline tampering, visibility and access changes).

### 5.3 Code scanning layers

| Layer | What it does |
|---|---|
| **Secret scanning** | Shared scanner on commit diffs: provider-specific patterns plus entropy/placeholder-filtered generic key patterns. Matches are redacted before storage or AI use. Lines with an ignore marker are skipped |
| **Code scan** (on sync) | Secrets, dependency manifests (`package.json`, `requirements.txt`, `go.mod`, `pom.xml`), dangerous patterns (eval/exec, SQL injection, XSS), sensitive file types, optional AI review summary |
| **SAST** | Per repo, per connector. Downloads one tarball per repo/ref, prioritises risky files, then runs **Semgrep** with the bundled rule set, with **CodeQL** (if the CLI installed during image build) and with 200+ built-in OWASP/CWE regex rules as the fallback when Semgrep is unavailable. Languages: Python, JavaScript/TypeScript, Go, Java, PHP, C/C++ |
| **SCA** | Parses manifests and lockfiles and checks exact name+version pairs against **OSV** (GitHub advisories, PyPI, Go, RustSec and more). A network failure never fails the scan |
| **Posture** (GitHub) | Branch protection, secret scanning / push protection, org 2FA |
| **Unified findings** | `GET /api/v1/findings` and **Insights → Code findings** merge SAST, code scan and posture into one schema, collapsing duplicates by repo, file, line and title |
| **AI explain** | Optional AI summary on code-scan and SAST results (Groq / Anthropic / self-hosted model) |

Scanner subprocesses run with a minimal environment: application secrets (`OW_SECRET_KEY`, API keys, JWT secret, DB password) are never passed to them.

---

## 6. Detection engine

### 6.1 Pipeline

```
 agent / cloud / Git events ─► TimescaleDB ─► detection engine (every 45 s) ─► detections ─► alerts
                                           └► alert-rule engine (every 30 s)  ─► alerts
                                           └► threat-intel match + retro-hunt ─► alerts
                                           └► correlators (auth, sequence, cloud, anomaly) ─► alerts
```

Engines read events through cursors on ingest time, so a restart resumes where it stopped instead of re-scanning or skipping.

### 6.2 Detection sources

| Source | Detail |
|---|---|
| **Built-in signatures** | 400+ rules, per platform: Windows (including Windows tamper, account changes, USB, domain controller, remote sessions), Linux, macOS, endpoint-agent, DNS categorisation, DevOps, AWS, Azure (IAM, compute, data, network, evasion, Defender, audit, Entra), GCP (IAM, credentials, compute, data, network, evasion, persistence, SCC, escalation, policy). Each rule carries severity, category and MITRE ATT&CK technique. Signatures only use fields that platform's collectors actually populate |
| **Sigma rules** | Community rules from SigmaHQ pulled from GitHub, mapped to ATT&CK, toggled globally or per rule in **Detections** |
| **Threat intelligence** | ThreatFox and AlienVault OTX synced on a schedule; IOC matches create detections. IOCs below 25% confidence are ignored. **Retro-hunt**: new IOCs are searched against retained history and alerts are tagged `Retro-hunt` |
| **DNS categorisation** | Quad9, SURBL and similar key-less sources flag malicious/phishing domains |
| **Hash reputation** | Tiered lookup, cheapest first: Team Cymru MHR → MalwareBazaar → CIRCL HASHLOOKUP (also filters known-good files) → Hybrid Analysis (free key) → VirusTotal (optional key). Stops at the first conclusive answer |
| **Custom alert rules** | User-defined rules (field filters, thresholds and windows, business-hours logic) under **Alert Rules**; test before enabling |
| **Auth correlation** | Password spray, brute force, success-after-failures across Windows 4624/4625, Linux sshd/sudo and Entra sign-ins |
| **Sequence correlation** | "A then B on the same entity within a window" rules |
| **Location** | Impossible travel and new-country detection from device location history, accuracy-checked so coarse IP fixes do not trigger |
| **Prevalence** | Rare-binary-on-one-host alerting |
| **Agent health** | Silent agents, stopped collectors, queue/drop growth, Sysmon down |

### 6.3 Alerts and incidents

- Alerts de-duplicate per rule and entity and keep an occurrence count.
- Workflow: acknowledge, assign, notes, close with review, bulk actions, SLA view.
- **Incidents** group open alerts per host into time-contiguous clusters with a risk score.
- Notifications: email (minimum severity configurable), syslog, webhooks.
- **Suppressions** for endpoint, AWS, Azure and GCP findings.

### 6.4 Search and investigation

- **Search**: filter builder over TimescaleDB (event type, process, command line, image, user, IPs, ports, protocol, file path, registry key, channel, event ID, severity, free text, host, agent, time range) with **142 saved queries** across Process, Credential, Network, DNS/Web, File, Registry, Sysmon, User and Linux.
- **Natural-language search**: the model sees only query syntax and field names (never event data); its output is validated against an allowlist and shown for review before you run it. A self-hosted OpenAI-compatible model (Ollama, vLLM, llama.cpp, LM Studio) is preferred when configured, so questions stay on your network.
- Saved and **scheduled searches**, CSV/JSON export, inventory search, identity timeline, threat graphs (endpoint processes, cloud, network).

### 6.5 AI analysis

Groq (primary) → Anthropic (fallback) → built-in rule-based analyser if neither key is set. Available on alerts, cloud findings, vulnerabilities, code findings and agent root-cause analysis. Configure keys in the setup wizard or **Settings → API Keys**.

### 6.6 Rule quality tools

- **Backtest** a built-in signature against recent events before enabling it (`POST /api/v1/detections/{id}/backtest?hours=24`); the count is an upper bound.
- **ATT&CK coverage** (Insights) per platform, built from the live rule set with known telemetry gaps listed.
- **Log sources** health view.

### 6.7 Detection reference

| Dashboard page | Purpose |
|---|---|
| Detections | Signature library, Sigma, threat-intel sources, toggles |
| Alerts / Alert Rules | Triage and custom rules |
| Insights | Inventory, incidents, code findings, log sources, ATT&CK coverage, prevalence, identity timeline, scheduled searches |

### 6.8 Latency expectations

Alert latency = collection delay + provider log delay + evaluation interval.

| Source | Collection | Provider delay |
|---|---|---|
| Endpoint agents | Batches every few seconds | none |
| AWS CloudTrail | Poll every 5 min | 5–15 min (LookupEvents is rate-limited and lags) |
| AWS GuardDuty | Poll every 5 min | minutes after activity |
| Azure Activity / Entra | Poll every 5 min | 2–15 min |
| GCP Audit Logs | Poll every 5 min | typically < 2 min, Data Access up to ~10 min |
| GitHub / GitLab / ADO audit | Poll every 5 min (webhooks for push-type events) | audit API lags up to ~15 min |
| CSPM / CIS / compliance | On demand | point-in-time snapshot |

Endpoints are seconds; cloud and Git audit are **5–20 minutes**. Do not rely on cloud-log detections for sub-minute response. Streaming ingestion (GCP Pub/Sub, AWS EventBridge, Azure Event Hub) is planned.

---

## 7. Settings and threat intelligence

### 7.1 Settings page (admin only)

The Settings page has four tabs: **API Keys**, **Email Alerts**, **Cloud Connectors** (a shortcut to the Cloud page) and **Detections** (a shortcut to the Detections page).

#### API Keys and integrations

Keys are stored encrypted with `OW_SECRET_KEY`, shown masked, and can be replaced or cleared one at a time. Most can also be entered in the setup wizard or in Agent Builder.

| Key | Used for |
|---|---|
| Groq API Key | AI analysis (primary) |
| Anthropic API Key | AI analysis (fallback) |
| Local model URL / name / API key | Self-hosted OpenAI-compatible model (Ollama, vLLM, llama.cpp, LM Studio, LocalAI) for natural-language search. Preferred over hosted providers when set |
| NVD API Key | CVE lookups for vulnerability results. Free key raises the limit from 5 to 50 requests per 30 s |
| VirusTotal API Key + plan | Last tier of file-hash reputation. Plan sets the rate limit: Free 4/min, Standard 500/min, Premium 1000/min. Only high-risk files (downloads, temp directories, executables) are checked |
| ThreatFox API Key | ThreatFox IOC feed (see 7.2) |
| OTX API Key | AlienVault OTX IOC feed (see 7.2) |
| Hybrid Analysis | Fourth step of the hash-reputation lookup (free key), queried before VirusTotal |
| AbuseIPDB, Shodan | Can be saved here, but nothing in the code reads them yet (checked the whole codebase). Reserved for future IP enrichment |

#### Email alerts

SMTP host, port, username, password (or app password), From address, recipient list, TLS on/off, **minimum severity** (1 info to 5 critical) and a **Send test** button. Presets shown in the UI: Gmail (`smtp.gmail.com:587`, app password), Office 365 (`smtp.office365.com:587`), SendGrid (`smtp.sendgrid.net:587`, username `apikey`). Defaults can also be set in the `smtp:` block of `management/docker/server.yaml`.

#### Not on the Settings page

| Setting | Where |
|---|---|
| Syslog forwarding and webhook notifications | API only: `GET/POST /api/v1/settings/syslog`, `/settings/webhooks`, with `/test` variants. No UI tab yet |
| Users and roles | **Users** page |
| Agent URLs, CA certificate, agent API key | Setup wizard / **Agent Builder → Reconfigure setup** |
| Intel source on/off and manual sync | **Detections → Intel Sources** |
| Cloud and Git credentials | **Cloud** and **DevOps** pages |
| Server tuning: CORS origins, timeouts, DB pool, JWT lifetime (default 24 h), SMTP defaults | `management/docker/server.yaml`, then `sudo docker compose restart mgmt-api`. Secrets from `.env` override the placeholder values |

### 7.2 Threat intelligence and IOC matching

**Sources** (Detections → Intel Sources; each can be enabled/disabled and synced on demand):

| Source | Provides | Key |
|---|---|---|
| Abuse.ch ThreatFox | Malware C2 IPs, domains, URLs, file hashes (MD5, SHA-1, SHA-256) | Free key required |
| AlienVault OTX | Community pulses with IPs, domains, hashes | Free key |
| SigmaHQ | Detection **rules**, not IOCs (see 6.2) | None |

IOCs sync **on startup and then every 24 hours**, or when you press sync on a source. After a sync, new IOCs are searched against retained history (retro-hunt, alerts tagged `Retro-hunt`).

**What the engine matches** (runs every 45 s with the rest of detection):

| Event | Field checked | Against |
|---|---|---|
| Endpoint network connection | Destination IP | IP IOCs |
| Endpoint DNS query | Queried domain, then its parent domain (`sub.evil.com` → `evil.com`) | Domain IOCs |
| Endpoint file event | File hash (MD5/SHA-1/SHA-256 as reported) | Hash IOCs |
| Any cloud event | Source IP | IP IOCs |
| GCP VPC flow / GCP DNS | Destination IP / query name | IP / domain IOCs |

Notes:
- Malicious **IP, domain and hash** indicators pulled from ThreatFox and OTX are all checked against the events above, live and in retro-hunt.
- Hash matching needs the agent to report a file hash, so coverage depends on the collector (for example Windows file events via Sysmon).
- **Confidence weighting:** IOCs below 25% confidence are ignored; 25–49% have their severity lowered.
- Alerts read `[THREATFOX] Ip IOC Match — <value>` (or `[OTX]`), de-duplicate per source, value, host, hour and entity, and are emailed when they meet the SMTP minimum severity.
- DNS categorisation (Quad9, SURBL) and the tiered hash-reputation lookup run alongside IOC matching and are described in 6.2.

---

## 8. Under development

**Application monitoring**: in development. Windows agents can already tail application log files (`app_logs`), but a dedicated application-monitoring module is not yet delivered.

**Network monitoring**: in development. A network probe (`agents/network`: syslog listener, NetFlow/sFlow receiver, SNMP poller, ARP monitor, local analysis for port scans, brute force, lateral movement, bandwidth spikes and ARP spoofing) and a **Network** dashboard page exist in the repository, along with 18 network signatures. The probe is **not** part of the supported feature set yet and is not pre-built in the default management image. Do not use it in production.

---

## 9. Dashboard reference

| Page | What it is |
|---|---|
| Dashboard | Fleet and alert overview |
| Events | Raw event browser and export |
| Search | Query builder, saved and natural-language search |
| Agents | Endpoint inventory, device detail, vulnerabilities, tamper keys, locations, threat graph |
| Alerts / Alert Rules | Triage and custom rules |
| Detections | Signatures, Sigma, threat intel |
| Cloud | Connectors, overview, events, CSPM, CIS, compliance, blast radius, deep dive |
| DevOps | Connectors, code changes, code scan, SAST, events, alerts, posture |
| Insights | Cross-cutting analyst views |
| Live Response (admin) | Remote terminal |
| Agent Builder (admin) | Compile and download agents, reconfigure setup |
| Users, Settings (admin) | Accounts; API keys and integrations; email alerts |
| Audit Log | Who did what in the platform |

---

## 10. Operations

### Update

```bash
git pull
sudo docker compose up -d --build
```

Database migrations run automatically at start-up. **Rebuild agents in Agent Builder** after updates that change agent code.

### Regenerate certificates

After changing the server IP or adding a domain:

```bash
sudo docker compose down
sudo docker volume rm obsidianwatch_certs
# update HOST_IP / BACKEND_DOMAIN in .env
sudo docker compose up -d
```

Then rebuild and redeploy all agents.

### Back up

- The `timescale_data` volume (events and platform data).
- `.env`, especially **`OW_SECRET_KEY`** (without it stored credentials cannot be decrypted), kept separately from database backups.
- The `ca-private` volume (CA private key).

### Agent ingest API (for custom integrations)

All routes except `/health` require the API key (`X-API-Key`) or a client certificate when mTLS is enabled.

| Route | Purpose |
|---|---|
| `GET /health` | Liveness |
| `POST /api/v1/events` | Batch event ingest |
| `GET /api/v1/events` | Query events |
| `POST /api/v1/agents/location` | Agent location report |
| `GET /api/v1/agents`, `GET /api/v1/agents/{id}` | Agent registry |
| `GET /api/v1/metrics` | Ingest metrics |

### Troubleshooting

| Symptom | Check |
|---|---|
| Compose refuses to start | A required `.env` value is missing or still a placeholder |
| Dashboard container exits | Certificates missing: `docker compose logs cert-init` |
| Agent not appearing | `curl -k https://<server>:8443/health` from the endpoint; confirm the API key matches; check the agent log (table in 3.3) |
| Agent TLS errors | Certificates were regenerated: rebuild the agent |
| Windows process detection empty | Sysmon not running: check the Sysmon health alert |
| macOS process events delayed | Full Disk Access not granted, so `eslogger` is unavailable and polling is used |
| Cloud connector test fails | Missing permission: the GCP test lists them; for AWS/Azure compare against section 4.1 |
| SAST uses regex rules only | Semgrep/CodeQL failed to install during image build; check the build log |

---

## 11. Development

Each component is an independent Go module (Go 1.25; the dashboard needs Node).

```bash
# Agent ingest backend
cd backend && go run ./cmd/server -config configs/server.yaml

# Management API
cd management/backend && go run ./cmd/server -config ../docker/server.yaml

# Dashboard with hot reload
cd management/frontend && npm install && npm run dev

# Agents (each builds only on its own OS because of build constraints)
cd agents/linux   && GOOS=linux   GOARCH=amd64 go build ./cmd/agent
cd agents/windows && GOOS=windows GOARCH=amd64 go build ./cmd/agent
cd agents/macos   && GOOS=darwin  GOARCH=arm64 go build ./cmd/agent   # or amd64

# Tests
cd management/backend && go test ./...
```

Development builds without an embedded config read `agent.yaml` from disk. Copy `agents/<os>/configs/agent.yaml`, set `backend_url`, `api_key` and `ca_file`, and run the binary directly.

**Contributing:** keep each platform's signatures limited to fields its collectors populate, add new signature sets to `sig_registry.go` so the sanity tests and ATT&CK coverage see them, and add a migration (never edit an applied one) for schema changes.

## License

Copyright © 2026 Blessing Honmane.

All Rights Reserved.

This project is proprietary software. Public access to this
repository does not grant permission to copy, modify, distribute,
or commercially use its source code.

See [LICENSE](./LICENSE) for details.
