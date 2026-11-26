# Endpoint deployment

This guide takes you from an empty server to enrolled Linux, Windows and macOS agents. It also covers upgrades, removal, revocation and the network probe.

Related documents:

- `configuration.md`: every agent and server setting.
- `capability.md`: what each collector captures and what the platform does with it.
- `identity.md` and `response-actions.md` (this folder): design notes for identity and response.

Agents authenticate with their own enrolled client certificate. There is no API key anywhere in the agent path.

---

## 1. Platform prerequisites

Implemented in: `docker-compose.yml`, `.env.example`, `cert-init/init.sh`, `backend/docker/server.yaml`, `backend/internal/api/server.go`.

### 1.1 Host and ports

One Linux host with Docker and Docker Compose.

| Port | Service | Who connects | Notes |
|---|---|---|---|
| 8443 | `backend` | Agents and network probes | Enrollment, event ingest, location, live-response tunnel, install-key calls. Agents need only this port. |
| 443, 80 | `mgmt-ui` | Analysts' browsers | 80 only redirects to HTTPS. |
| 8444 | `mgmt-api` | Browsers (API) | Mapped to container port 8443. Agents never call it directly. |

The database (`timescaledb`) has no published port.

Agents also make outbound calls that do not go to your server:

- Linux, macOS and Windows: `https://ipinfo.io/json` every 30 minutes for IP geolocation.
- Windows: `https://download.sysinternals.com/files/Sysmon.zip` when Sysmon is missing (unless the build embeds Sysmon).
- Linux: the distribution package mirror when `nft` and `iptables` are both missing (see 3.1).

### 1.2 `.env`

Copy `.env.example` to `.env` and fill it in.

| Variable | Required | Purpose |
|---|---|---|
| `DB_PASSWORD` | yes | Database password for backend and management. Compose refuses to start without it. Placeholders such as `changeme` are refused by the services. |
| `JWT_SECRET` | yes | Signs dashboard sessions (32 characters or more). |
| `OW_SECRET_KEY` | yes | Encrypts stored credentials. It also signs the agent identity that the backend passes to management for tunnel and install-key calls. Both services must have the same value. Without it live response, response actions and install-key checks do not work. Back it up separately. |
| `HOST_IP` | see note | Server IP placed in the self-signed certificate. |
| `BACKEND_DOMAIN` | no | Domain for the certificate. When set, `cert-init` requests a Let's Encrypt certificate (port 80 must be free and the name must resolve to this host). |
| `EXTRA_SAN_DNS` | no | Extra DNS names for the self-signed certificate. |
| `AGENT_API_KEY` | no | Not used to authenticate agents. It only seeds application user hashing. Leave it empty. |
| `OW_ALLOWED_ORIGINS` | no | Extra browser origins for WebSockets. |

Note on `HOST_IP`: `.env.example` does not list it and Compose does not enforce it. If it is empty, `cert-init` puts the container's default gateway address into the certificate, which agents cannot use. Set it.

### 1.3 Certificates (`cert-init`)

`cert-init` runs once at each `docker compose up` and exits.

- Self-signed mode (no `BACKEND_DOMAIN`): creates a 10-year RSA CA (`ca-private` volume, key mounted only into `cert-init`) and an 825-day server certificate with SANs `HOST_IP`, `127.0.0.1`, the detected public IP and `EXTRA_SAN_DNS`. It re-issues the server certificate when fewer than 30 days remain or when a new `EXTRA_SAN_DNS` name is missing.
- Let's Encrypt mode: uses `acme.sh` with the HTTP challenge on port 80.
- It writes `cert-meta.json`. On first start the management server reads it to pre-fill the Agent builder (backend URL `https://<domain or public IP or private IP>:8443`, management URL, CA).

This deployment CA protects the server's TLS. It is not the agent CA.

### 1.4 The agent CA (`agent-ca` volume)

The backend creates a separate ECDSA P-256 CA (10 years) on first start, in the `agent-ca` volume (`agent-ca/agent-ca.crt`, key `agent-ca/agent-ca.key`, mode 0600). It signs every agent certificate. Its public certificate is published to the `agent_ca` table for the management server.

Back up the `agent-ca` volume. If you lose it, every enrolled agent is refused and every host must be reinstalled with a new build.

### 1.5 Start

```bash
sudo docker compose up -d --build
sudo docker compose logs cert-init
sudo docker compose logs backend | grep -i "agent CA\|agent identity"
```

The backend logs `agent CA created - back up the key file` on the first start and `agent identity: certificates required` on every start. It logs a warning if `auth.api_keys` or `auth.mtls_enabled` are still present in `server.yaml`; both are ignored.

Check that `tunnel.management_url` in `backend/docker/server.yaml` points at the management API (default `https://mgmt-api:8443`). If it is empty, agents cannot open the live-response tunnel or register install keys.

---

## 2. Building agents (Agent builder)

Implemented in: `management/backend/internal/api/agent_builder.go`, `agent_cache_meta.go`, `agent_macos_profile.go`, `management/frontend/src/pages/AgentBuilder.jsx`.

Open **Agent builder** (admin only). The backend URL, management URL and CA are pre-filled from setup.

### 2.1 What a build does

1. Validates the backend URL (must be `https://`) and the management URL (if given, `https://`).
2. Mints a new enrollment token for this build. The token is stored only as a SHA-256 hash and is labelled `Agent builder: <platform> build by <user>, <time>`.
3. Generates the agent YAML (see `configuration.md`, section 3), with the token, URLs and CA inside.
4. Writes the YAML into the agent's `internal/config/embedded.go`, runs `go build` (CGO off, `-ldflags "-s -w"`, no network), then restores the empty stub. A file lock serialises builds of the same platform.
5. Packs a zip and stores it in the `agent-cache` volume with a sidecar `.meta` file (zip SHA-256, config hash, build time).

Each build compiles fresh because each build carries a new token (1 to 2 minutes). A cached zip is served by `GET /api/v1/agent-builder/download/{platform}` for up to 14 days, if its SHA-256 still matches. That zip still carries the token it was built with.

### 2.2 Builder fields

| Field | Default | Limits | Effect |
|---|---|---|---|
| Enrollment token valid for (days) | 30 | 1 to 90 days | Hosts must enroll before the token expires. Already enrolled hosts are not affected. |
| Maximum hosts for this build | 500 | 1 to 100,000 | Each enrollment uses one. |
| Enable live response | off | | Writes `live_response.enabled`. Also required for every response action and live hunt, because they share the tunnel. |
| Backend URL / Management URL / CA | from setup | `https` only | Embedded in the binary. |
| App-server profile options | off | | Adds an `app_monitoring` block (application monitoring area, not covered here). |

### 2.3 Platforms and zip contents

| Platform key | Binary in the zip | Target |
|---|---|---|
| `linux` | `obsidianwatch-linux-agent` | Linux x86-64 |
| `windows` | `obsidianwatch-win-agent.exe` | Windows x86-64 |
| `macos` | `obsidianwatch-macos-agent` | macOS Intel |
| `macos-arm64` | `obsidianwatch-macos-agent` | macOS Apple Silicon |
| `network` | `obsidianwatch-network-probe` | Linux x86-64 (does not build, see section 9) |

Each zip contains the binary, `SHA256SUMS`, `INSTALL.md`, and for macOS `ObsidianWatch-FullDiskAccess.mobileconfig`. Binaries are not code-signed or notarised.

Treat the zip as a secret until the token expires or is used up. Anyone holding it can enroll a host into your fleet.

### 2.4 Tokens created by hand

**Platform settings → Agent enrollment** lists every token (label, creator, expiry, uses) and every enrolled identity. You can create a token there (for the network probe or development builds) and revoke one. Revoking a token stops new enrollments with it; it does not affect hosts that already enrolled.

---

## 3. Install, upgrade and uninstall

Implemented in: `agents/linux/cmd/agent/main.go`, `agents/linux/cmd/agent/enroll.go`, `agents/linux/internal/service/service.go`; `agents/macos/cmd/agent/*`, `agents/macos/internal/service/service.go`; `agents/windows/cmd/agent/main.go`, `agents/windows/cmd/agent/enroll.go`.

### 3.1 Linux (systemd)

```bash
chmod +x obsidianwatch-linux-agent
sha256sum -c SHA256SUMS
sudo ./obsidianwatch-linux-agent install
systemctl status obsidianwatch-agent
sudo journalctl -u obsidianwatch-agent -f
```

`install` does the following, in order:

1. If `/usr/local/bin/obsidianwatch-agent` exists: removes the immutable flags, stops and disables the service (upgrade path).
2. Generates a random 32-hex-character install key.
3. Enrolls (up to 60 s) and registers the install key through the backend. If the server is unreachable, it prints a warning and the service does both when it starts.
4. Creates `/etc/obsidianwatch` and `/var/lib/obsidianwatch` (0700), copies the binary (0700), writes the key to `/etc/obsidianwatch/.install_key` (0600).
5. Writes `/etc/systemd/system/obsidianwatch-agent.service`.
6. Makes sure `nft` or `iptables` exists. If neither does, it installs `nftables` with the first package manager it finds (apt-get, dnf, yum, zypper, apk, pacman). This happens automatically.
7. `systemctl daemon-reload` and `systemctl enable --now`.
8. `chattr +i` on the binary, the unit file and the install-key file.

Unit settings: `User=root`, `Restart=always`, `NoNewPrivileges=true`, `ProtectSystem=strict`, `ReadWritePaths=/var/lib/obsidianwatch /etc/obsidianwatch`, `PrivateTmp=true`, `ProtectHome=read-only`, `MemoryMax=512M` with `GOMEMLIMIT=384MiB` (the Go runtime collects before the limit; 256M crash-looped a busy Docker host), `CPUQuota=25%`.

If a busy host needs more memory (`systemctl status obsidianwatch-agent` shows `oom-kill` and the restart counter climbs), raise the limit with a drop-in, which survives agent upgrades:

```bash
sudo mkdir -p /etc/systemd/system/obsidianwatch-agent.service.d
printf '[Service]\nMemoryMax=768M\nEnvironment=GOMEMLIMIT=600MiB\n' | sudo tee /etc/systemd/system/obsidianwatch-agent.service.d/memory.conf
sudo systemctl daemon-reload && sudo systemctl restart obsidianwatch-agent
```

Keep `GOMEMLIMIT` about 20% below `MemoryMax`.

Caution about the sandbox: `PrivateTmp=true` gives the service its own `/tmp` and `/var/tmp`, so the file monitor's `/tmp` and `/var/tmp` watches see the private directories, not the host's. `ProtectSystem=strict` and `ProtectHome=read-only` also make most of the file system read-only for the agent, which is expected to make quarantine and delete of files under `/home`, `/opt` or `/tmp`, and `disable_user` (which runs `usermod` on `/etc/shadow`), fail with a read-only error. Only the nftables installer works around the sandbox (it uses `systemd-run`). Test these actions on your own hosts before relying on them.

Requirements: root, systemd, `journalctl` for the journal collector, Docker socket for container events, `/var/log/dpkg.log` for software events.

### 3.2 macOS (launchd)

```bash
chmod +x obsidianwatch-macos-agent
shasum -a 256 -c SHA256SUMS
sudo ./obsidianwatch-macos-agent install
```

`install` enrolls, registers the install key, copies the binary to `/usr/local/bin/obsidianwatch-agent`, writes `/Library/LaunchDaemons/com.obsidianwatch.agent.plist` (`KeepAlive`), loads it with `launchctl load -w`, and sets `chflags uchg` on the binary, plist and install-key file.

Full Disk Access (FDA) is needed for the `eslogger` exec stream and the BSM audit-pipe file monitor. Without it, the agent falls back to process polling and kqueue file monitoring. Grant it in System Settings → Privacy & Security → Full Disk Access for `/usr/local/bin/obsidianwatch-agent`, or deploy the profile (section 3.4).

The macOS agent is a preview.

### 3.3 Windows (service)

Run in an elevated PowerShell:

```powershell
.\obsidianwatch-win-agent.exe install
Get-Service ObsidianWatchAgent
Get-Content C:\ProgramData\ObsidianWatch\agent.log -Tail 50
```

`install` does the following:

1. Restricts the downloaded binary's ACL to SYSTEM (read and execute) and Administrators (full).
2. Generates an install key, prints it, and stores it in `C:\ProgramData\ObsidianWatch\.install_key`.
3. Enrolls and registers the install key (the service retries if this fails).
4. Removes an existing `ObsidianWatchAgent` service, even one protected by the tamper DACL.
5. Copies the binary to `C:\Program Files\ObsidianWatch\Agent\agent.exe` and creates the service (automatic start).
6. Applies the tamper DACL: SYSTEM full control; Administrators can query and start but not stop or delete; Everyone is denied stop and delete.
7. Starts the service.

At service start the agent makes sure the `EventLog` and `WinRM` services run (it re-enables them if disabled), checks Sysmon and installs it if missing (download from Sysinternals with an Authenticode check, or the copy embedded with `-tags embed_sysmon`), and applies its own Sysmon configuration (version 2). It retries the Sysmon install every 30 minutes while Sysmon is not running.

Important: if Sysmon is already installed with another configuration, the agent replaces that configuration with its own (`sysmon -c`). Plan for this on hosts with a managed Sysmon configuration.

Audit policy: the agent turns on Event 4688 command-line logging and PowerShell script-block logging only when you run it interactively as an administrator. Under the service it does not. Set these by Group Policy for service-only deployments.

Requirements: Windows 10 / Server 2016 or later, administrator rights.

### 3.4 macOS MDM notes

The zip contains `ObsidianWatch-FullDiskAccess.mobileconfig`, a PPPC profile that grants `SystemPolicyAllFiles` to `/usr/local/bin/obsidianwatch-agent`. Because the binary is unsigned, the profile identifies it by path (`IdentifierType: path`). Payload identifier `io.obsidianwatch.agent.fda`; the payload UUIDs are fixed, so redeploying updates the profile instead of duplicating it.

Deploy it through Jamf, Kandji or Intune before or after installing the binary. The profile does not install the agent; run `install` through your MDM's script feature.

### 3.5 Install locations

| | Linux | macOS | Windows |
|---|---|---|---|
| Binary | `/usr/local/bin/obsidianwatch-agent` | `/usr/local/bin/obsidianwatch-agent` | `C:\Program Files\ObsidianWatch\Agent\agent.exe` |
| Service | `obsidianwatch-agent` (systemd) | `com.obsidianwatch.agent` (launchd) | `ObsidianWatchAgent` |
| Install key (local copy) | `/etc/obsidianwatch/.install_key` | `/etc/obsidianwatch/.install_key` | `C:\ProgramData\ObsidianWatch\.install_key` |
| Identity bundle | `/var/lib/obsidianwatch/identity/agent-identity.json` (0600, directory 0700) | same as Linux | `C:\ProgramData\ObsidianWatch\identity\agent-identity.dpapi` (machine DPAPI, SYSTEM and Administrators only) |
| Event queue | `/var/lib/obsidianwatch/queue/segments/` | same as Linux | `C:\ProgramData\ObsidianWatch\queue\segments\` |
| Response state and quarantine vault | `/var/lib/obsidianwatch/` (`response.json`, `quarantine/`) | same as Linux | `C:\ProgramData\ObsidianWatch\` |
| Log | journald (stdout) | `/var/log/obsidianwatch/` (launchd stdout) | `C:\ProgramData\ObsidianWatch\agent.log` |
| Agent id | `ag-` + 32 hex, assigned at enrollment | same | same |

The agent id is random and assigned by the server. It is not the machine id, the hardware UUID or the host name. The `agent.id` key in the configuration does not affect the enrolled id.

### 3.6 Upgrade

Build a new agent in the Agent builder and run `install` again on the host. The installer stops the old service, replaces the binary and starts it again. The identity bundle in `/var/lib/obsidianwatch` (or `C:\ProgramData\ObsidianWatch`) is kept, so the host keeps its agent id and certificate; the new build's token is not used.

Known issue: on an upgrade the installer generates a new install key, but the registration step is skipped because the host is already registered under the same agent id (`agents/*/cmd/agent/enroll.go`, `install-key-registered` marker). The server keeps the old key. Use **Regenerate** on the dashboard (section 6) to get a key that works.

### 3.7 Uninstall

Uninstall requires the install key.

```bash
sudo ./obsidianwatch-linux-agent uninstall      # or the macOS binary
```
```powershell
.\obsidianwatch-win-agent.exe uninstall          # elevated
```

1. The agent asks for the key.
2. It sends the key to the backend with its certificate. The backend passes the call to management, which checks the key against the stored hash for that agent only, and rotates it on success (each key works once).
3. If the server cannot be reached, or answers 401 (for example the identity was revoked), the agent compares the key with its local copy instead. A server rejection (403) is final.
4. On success:
   - Linux: removes the immutable flags, stops and disables the unit, removes the unit, binary, `/etc/obsidianwatch` and `/var/lib/obsidianwatch` (identity, queue and quarantine vault included).
   - macOS: removes flags, unloads the plist, removes the plist, binary and `/etc/obsidianwatch`. `/var/lib/obsidianwatch` (identity, queue, vault) and `/var/log/obsidianwatch` stay.
   - Windows: unlocks the service DACL, stops and deletes the service. The binary in `C:\Program Files\ObsidianWatch\Agent` and everything in `C:\ProgramData\ObsidianWatch` (identity, queue, key) stay. Delete them by hand if needed.

Uninstall does not release isolation or remove IP blocks. Release a host in **Response** before uninstalling it.

### 3.8 Reinstall on the same host

If you uninstall on Linux (identity removed) and install a new build, the host enrolls again and gets a new agent id. When a host enrolls, the backend marks older agent records with the same host name (case-insensitive) as replaced (`agents.superseded_by`, migration 043 in the backend and 072 in management). Replaced records are hidden from **Fleet**, the agent counts and the location map, and silent-agent alerts stop for them. A hidden record that sends events again becomes visible again, so a live agent cannot be hidden this way.

Events still in the queue from the old identity are sent under the new id: the agent stamps every queued event with its current id, and the backend attributes every event in a batch to the certificate's agent. Only the batch-level `agent_id` must match the certificate.

Revoke the old identity in **Platform settings → Agent enrollment** (section 7).

---

## 4. Enrollment and certificate renewal

Implemented in: `agents/*/internal/identity/identity.go` (identical in all four agents), `keystore_file.go`, `keystore_windows.go`; `backend/internal/api/enroll.go`, `agent_identity.go`, `backend/internal/enroll/ca.go`, `backend/pkg/agentid`.

### 4.1 Enrollment

1. At `install`, or at service start if not yet enrolled, the agent creates an ECDSA P-256 key and a CSR on the host. The key never leaves the host.
2. It calls `POST https://<backend>:8443/api/v1/enroll` with `token`, `csr`, `hostname`, `os`, `agent_version`. No client certificate is needed for this route.
3. The backend rate-limits enrollment to 20 calls per minute per source IP. It spends one use of the token. An invalid, expired, revoked or used-up token returns 401.
4. The agent CA issues a certificate for a new random id `ag-<32 hex>` with CN and URI SAN `urn:obsidianwatch:agent:<id>`, client-auth only, valid for `cert_ttl` (default 30 days), backdated 5 minutes for clock skew. Names in the CSR are ignored.
5. The backend records the identity (host name, OS, token, serial, expiry, source IP) and marks older records with the same host name as replaced.
6. The agent saves key, certificate and CA in one bundle (section 3.5).

Each enrollment creates a new id, so cloned images that enroll at first boot get one id per clone. Do not run the agent on a golden image before cloning it.

If enrollment fails with 401, the agent logs `identity: enrollment refused - the token is invalid, expired, revoked or used up` and retries every 10 minutes. Other failures retry with back-off from 5 s up to 5 minutes. The agent sends nothing until it has a certificate.

### 4.2 Renewal

- The agent renews at half the certificate's life plus up to one hour of random jitter (about day 15 with the default TTL), using `POST /api/v1/enroll/renew` with its current certificate and a new key. The id stays the same.
- If renewal fails, it retries every 30 minutes.
- If the certificate expired (for example the host was off), the agent enrolls again with the built-in token, if the token is still valid and has uses left. This creates a new id.
- If the server answers that the identity is revoked, the agent stops renewing and does not re-enroll. It keeps running and queueing events until it is reinstalled.

Every connection to the backend (events, location, tunnel, install-key calls) presents the current certificate, chosen per TLS handshake, so a renewal applies to new connections without a restart.

---

## 5. Verify a new host

1. Agent log: look for `identity: enrolled` (or `agent identity` with an id and `certificate_expires`), then `All collectors running` (Linux) or `all collectors launched` (Windows).
2. **Fleet**: the host appears within seconds of the first batch and shows online while it reported in the last 2 minutes. The health heartbeat every 60 s keeps it online.
3. **Platform settings → Agent enrollment → Enrolled agents**: the identity is listed with its token.
4. **Events**: filter on the host; expect `health` events every minute and process events.
5. If live response was enabled: **Response** shows the host as `Live` under Reachable. `No tunnel` means the agent is online but the tunnel is down or live response is off in that build.
6. Windows: the health event carries `sysmon_status`; the platform alerts when Sysmon is not running.
7. Linux: the log says `process: kernel sensor active (eBPF)` and health events carry `process_sensor: ebpf`. It needs root and kernel BTF (`/sys/kernel/btf/vmlinux`, standard on current distribution kernels). Otherwise the log gives the reason and the agent uses the proc connector and polling, which miss short-lived processes. `OW_DISABLE_EBPF=1` in the service environment forces the fallback.
8. Windows without Sysmon: the log says `preflight: audit subcategory enabled` for Process Creation and Termination. The agent changes the host's audit policy (`auditpol`, by subcategory GUID) and turns on command-line inclusion so Security 4688 carries command lines. Group Policy that sets audit policy can override this; check with `auditpol /get /subcategory:"Process Creation"`.

### 5.1 Troubleshooting

| Symptom | Check |
|---|---|
| Host never appears | From the host: `curl -k https://<server>:8443/health`. Read the agent log for lines starting with `identity:`. |
| `enrollment refused` | The build's token expired, was revoked or is used up. Build again. |
| `this agent was built with an API key` | An old build. Rebuild in the Agent builder and reinstall (section 9). |
| `client certificate required; enroll this agent` (401) | The agent has no certificate yet, or something between agent and backend terminates TLS. TLS must reach the backend directly. |
| `client certificate not accepted` (401) | The agent CA changed (volume lost). Reinstall with a new build. |
| `agent identity revoked` | Revoked in Agent enrollment. Reinstall with a new build. |
| `agent_id does not match the client certificate` (403) | A batch names a different agent than the certificate. Should not happen with current agents. |
| TLS verification errors | The deployment CA or server certificate changed (`HOST_IP`, domain). Rebuild agents: the CA is embedded at build time. |
| Host shows online but **Response** says `No tunnel` | Built without live response, `tunnel.management_url` empty, or `OW_SECRET_KEY` differs between backend and management. |
| Windows process events lack command lines | Sysmon is not running. See the Sysmon health alert. |
| macOS process events delayed or missing | No Full Disk Access, so `eslogger` is not used. |
| Host goes **offline** after a while, but live response still works | Live response uses its own tunnel; online status comes from event ingest. Before the current build, events queued under a previous agent id (left over from a reinstall) were refused with 403 and blocked the queue. The backend now re-attributes them to the certificate's agent and the agent restamps its queue. Install the current build; if it persists, read the agent log for `forward` errors. |
| Reinstall created a second record | The new agent supersedes the old record by hostname on enrollment and the old one is hidden. Older builds did not; remove the old record once it has been offline for 2 minutes (7.2). |
| Live shell or a response action reports `Read-only file system` (Linux) | Earlier builds ran under a systemd sandbox (`ProtectSystem=strict`). Install the current build, or run `systemctl daemon-reload` after upgrading so the new unit takes effect. |
| 429 from ingest | The backend allows 500 events/s per agent with a 20,000-event burst. The agent retries. |

---

## 6. Tamper protection and the install key

Implemented in: `agents/*/internal/service`, `agents/windows/cmd/agent/main.go`, `management/backend/internal/api/handlers_agent_keys.go`, `management/frontend/src/pages/agents/tamper.jsx`.

| OS | Applied at install |
|---|---|
| Linux | `chattr +i` on binary, unit, install-key file; systemd hardening (section 3.1). |
| macOS | `chflags uchg` on binary, plist, install-key file. |
| Windows | Service DACL denies stop and delete to everyone except SYSTEM; binary ACL limited to SYSTEM and Administrators; data directory limited to SYSTEM and Administrators. |

The server stores only a SHA-256 hash of the install key. The dashboard cannot show it. To uninstall a host, open **Fleet**, select the host, open the shield icon (Tamper Protection), click **Regenerate**, and copy the new key. It is shown once. The Windows installer also prints the key at install time, and the local copy on the host is readable by root or Administrators.

The Tamper Protection panel also shows an Enabled/Disabled lock state. The agents do not read this state; it does not change what the agent or the uninstaller does.

Limits. Tamper protection is cooperative. A local root or administrator can stop the agent: `chattr -i` and `systemctl stop` on Linux, `chflags nouchg` and `launchctl unload` on macOS, and on Windows the uninstaller itself shows how to reset the DACL through a temporary SYSTEM service. When the server is unreachable, the local copy of the key is enough to uninstall. Compensating controls:

- A stopping agent sends an `agent.tamper` event (severity 4), which raises rule `AGENT-TAMPER-001` (Medium).
- An agent silent for 10 minutes raises `Agent offline: <host>` (Medium, High after one hour), again every hour while it stays silent.

---

## 7. Revocation and decommissioning

Implemented in: `management/backend/internal/api/agent_tunnel_identity.go`, `response_actions.go` (`handleDeleteAgent`), `backend/pkg/agentid`.

### 7.1 Revoke an identity

**Platform settings → Agent enrollment → Enrolled agents → Revoke** (admin, reason required, audited).

- Any live-response tunnel of that agent closes at once.
- Backend and management reload the revoked set every 15 s, so ingest refuses the certificate within about 20 s.
- The agent does not re-enroll on its own. It keeps running and queueing locally.
- Also revoke the build's token if the zip may be reused. A host whose revoked certificate later expires could otherwise enroll again with a still-valid token.

### 7.2 Remove a record

**Fleet → host → Remove record** deletes the agent record. It is refused while the agent has a live tunnel, and while it reported in the last 2 minutes (the same rule the Fleet page uses for "online"). This does not revoke the identity and does not delete stored events. If the agent reports again, the record comes back with the next batch.

### 7.3 Decommission checklist

1. Release isolation and remove IP blocks in **Response**, if any.
2. Uninstall on the host with the install key (section 3.7).
3. Revoke the identity (7.1).
4. Remove the record (7.2) once the host has been offline for 2 minutes.

---

## 8. Network probe

Implemented in: `agents/network/cmd/probe/main.go`, `agents/network/internal/*`, `buildNetworkProbeYAML` in `agent_builder.go`.

Status: not supported. The probe was never wired end to end, and it cannot be built here: its SNMP (`github.com/gosnmp/gosnmp`) and SQLite (`modernc.org/sqlite`) dependencies are not vendored, and the module download for the probe is commented out in `management/docker/Dockerfile`. A **network** build in the Agent builder therefore fails. Only its identity and forwarder packages were built and tested.

If you build it elsewhere:

```bash
sudo ./obsidianwatch-network-probe install --subnet 192.168.1.0/24 --community public --site "HQ"
sudo ./obsidianwatch-network-probe discover --subnet 192.168.1.0/24
```

`install` writes `/etc/obsidianwatch-probe/probe.yaml` (when no config is embedded), copies the binary to `/usr/local/bin/obsidianwatch-network-probe` and creates `obsidianwatch-probe.service` (`Restart=always`). The probe enrolls like an agent: it needs `forwarder.enroll_token` (create one in **Platform settings → Agent enrollment**) and stores its identity under `/var/lib/obsidianwatch-probe`. It sends events with OS `network-probe` to `/api/v1/events`.

Listening ports by default: syslog UDP and TCP 514, NetFlow 2055, sFlow 6343. ARP monitoring uses `eth0` by default.

---

## 9. Rollout from API-key agents

Agents built before certificate enrollment authenticated with a shared `X-API-Key`. The servers no longer accept it on any route.

1. Update the servers: `git pull && sudo docker compose up -d --build`. `AGENT_API_KEY` is no longer required. Remove `auth.api_keys` from `backend/docker/server.yaml` (it is ignored and logged).
2. Back up the `agent-ca` volume after the first start.
3. Rebuild every platform in the Agent builder. Old binaries cannot be converted; a configuration with `api_key` and no `enroll_token` refuses to start with a message saying so.
4. Install the new build over the old one (`install` upgrades in place). Each host enrolls and gets a new `ag-` id.
5. Old records (named after machine id, hardware UUID or host name) are hidden when the host enrolls again under the same host name. Remove records of hosts that never come back.
6. Old agents that are not reinstalled are refused and show as offline. They raise silent-agent alerts every hour until their record is removed.
