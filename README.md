# ObsidianWatch

Self-hosted SIEM platform. One repository, one command to deploy.

Agents collect security telemetry from Linux, Windows, and macOS endpoints and forward it over TLS to a central backend. The management dashboard provides real-time visibility, alert rules, MITRE ATT&CK detection, AI-powered analysis, threat intelligence feeds, and a built-in Agent Builder that compiles and configures agents for download — no manual config files needed on endpoints.

---

## Repository Structure

```
obsidianwatch/
├── backend/              # Agent event ingest server — :8443 (TLS)
├── agents/
│   ├── linux/            # Linux agent — systemd service
│   ├── windows/          # Windows agent — Windows Service + tamper DACL
│   └── macos/            # macOS agent — launchd daemon
├── management/
│   ├── backend/          # Management API — alerts, detections, AI, Agent Builder
│   ├── frontend/         # React + Tailwind dashboard
│   └── docker/           # Management-only compose (development reference)
├── cert-init/            # Auto-generates TLS certificates on first run
├── docker-compose.yml    # Starts everything — one command
└── .env.example          # Environment variable reference
```

---

## Quick Start

### 1. Configure environment

```bash
cd ~/ObsidianWatch
cp .env.example .env
```

Edit `.env`:

```env
# Your server's LAN IP — used as SAN in the TLS certificate
HOST_IP=192.168.1.x

# Database password — must match in both server.yaml files
DB_PASSWORD=changeme
```

### 2. Configure the backend

```bash
cp backend/configs/server.yaml backend/docker/server.yaml
```

Edit `backend/docker/server.yaml` — set one value:

```yaml
database:
  password: "your-db-password"     # must match DB_PASSWORD in .env
```

The `auth.api_keys` value is set automatically when you complete the setup wizard — no need to edit it manually.

### 3. Configure the management platform

```bash
cp management/backend/configs/server.yaml management/docker/server.yaml
```

Edit `management/docker/server.yaml` — set two values:

```yaml
database:
  password: "your-db-password"     # same as above

auth:
  jwt_secret: "your-jwt-secret"    # generate: openssl rand -hex 32
```

The `server.agent_api_key` value is set automatically by the setup wizard.

### 4. Start everything

```bash
sudo docker compose up -d --build
```

Five things happen automatically:

1. **cert-init** runs once — detects your private IP (`HOST_IP`) and public IP, generates a CA and server TLS certificate with both IPs as Subject Alternative Names. Skipped on subsequent starts if certs already exist.
2. **TimescaleDB** starts
3. **Backend** starts on `:8443` — agent event ingest over TLS
4. **Management API** starts on `:8080`
5. **Dashboard** starts on `:80`

Check everything is healthy:

```bash
sudo docker compose ps
sudo docker compose logs cert-init
```

---

## First Login and Setup

Open `http://<your-server-ip>` in a browser.

On first visit you are redirected to the **setup wizard** before you can log in. The wizard asks for:

| Field | Required | Description |
|---|---|---|
| Agent API Key | Yes | Generate with `openssl rand -hex 32` — automatically written to backend and management configs |
| Backend Domain | No | Add a domain to the TLS cert SAN (e.g. `siem.company.com`). Clears agent cache. |
| Backend URL | Auto | Pre-filled from detected IPs. Override if needed. |
| Management URL | Auto | Pre-filled from server's private IP. |
| Groq API Key | No | AI alert analysis — free at console.groq.com |
| Anthropic API Key | No | Fallback AI engine — console.anthropic.com |
| ThreatFox API Key | No | IOC feed — free at threatfox.abuse.ch |
| OTX API Key | No | AlienVault threat feed — free at otx.alienvault.com |

After completing setup, log in with:

- **Username:** `admin`
- **Password:** `changeme`

You are prompted to change the password immediately.

To re-run the setup wizard at any time, go to **Agent Builder → Reconfigure setup**.

---

## Deploying Agents

### Build an agent

Go to **Agent Builder** in the dashboard. All fields are pre-populated from setup — just select a platform and click **Build**.

The server compiles the agent from source with your configuration baked into the binary. First compile takes 1–2 minutes. Subsequent downloads of the same platform are instant.

### Install

Download the zip for your platform. It contains a single self-contained binary — configuration, CA certificate, and backend URL are all embedded.

**Linux:**
```bash
chmod +x obsidianwatch-linux-agent
sudo ./obsidianwatch-linux-agent install
```

**macOS:**
```bash
chmod +x obsidianwatch-macos-agent
sudo ./obsidianwatch-macos-agent install
```

**Windows (run as Administrator):**
```powershell
.\obsidianwatch-win-agent.exe install
```

The agent generates a random install key, registers it on the dashboard, and starts collecting immediately. It appears under **Agents** within seconds.

### Uninstall

Uninstall requires the install key shown on the dashboard under **Agents → shield icon**. This prevents unauthorised removal.

**Linux / macOS:**
```bash
sudo ./obsidianwatch-*-agent uninstall
# Enter install key when prompted
```

**Windows (run as Administrator):**
```powershell
.\obsidianwatch-win-agent.exe uninstall
# Enter install key when prompted
```

---

## What Each Agent Collects

| Telemetry | Linux | Windows | macOS |
|---|:---:|:---:|:---:|
| Authentication / SSH / sudo | ✓ | ✓ | ✓ |
| Process create / terminate | ✓ | ✓ | ✓ |
| Network connections | ✓ | ✓ | ✓ |
| DNS queries | ✓ | ✓ | ✓ |
| File integrity monitoring | ✓ | ✓ | ✓ |
| Registry changes | — | ✓ | — |
| PowerShell / script execution | — | ✓ | — |
| Sysmon telemetry | — | ✓ | — |
| Config file monitoring | ✓ | — | ✓ |
| Agent health heartbeat | ✓ | ✓ | ✓ |
| Geolocation enrichment | ✓ | ✓ | ✓ |
| Live response (remote shell) | ✓ | ✓ | — |

---

## Platform Features

**Alert Engine** — evaluates user-defined alert rules every 30 seconds against incoming events.

**Detection Engine** — runs every 45 seconds, matching events against 100+ MITRE ATT&CK signatures and live IOC indicators from threat intel feeds.

**Threat Intelligence** — syncs ThreatFox and AlienVault OTX feeds on a schedule. IOC matches automatically generate detections.

**AI Analysis** — Groq (llama-3.3-70b) as the primary engine, Anthropic Claude as fallback, local rule-based engine if neither is configured. Available on-demand from any alert.

**Agent Builder** — compiles agents from source inside the management container. Supports Linux (amd64), Windows (amd64), and macOS (amd64). Config and CA cert are embedded at compile time — no files needed on endpoints.

**Live Response** — interactive shell sessions to Linux and Windows endpoints directly from the dashboard.

**Tamper Protection** — agents install with a locked DACL (Windows) or restricted permissions (Linux/macOS). The install key must be entered to uninstall. Key is visible on the dashboard under Agents.

---

## Updating

```bash
cd ~/ObsidianWatch
git pull
sudo docker compose up -d --build
```

Database migrations run automatically on startup. Agent binaries need to be rebuilt from Agent Builder after updates that change the agent code.

---

## Re-generating Certificates

If you change your server IP or add a domain, delete the certs volume and restart:

```bash
sudo docker compose down
sudo docker volume rm obsidianwatch_certs
HOST_IP=192.168.1.x sudo docker compose up -d
```

Or update `.env` with the new `HOST_IP` and run the same commands. After new certs are generated, rebuild all agents from Agent Builder — the new CA cert will be embedded automatically.

---

## Development

Each component is an independent Go module:

```bash
# Agent backend
cd backend && go run ./cmd/server -config configs/server.yaml

# Management API
cd management/backend && go run ./cmd/server -config ../docker/server.yaml

# Management UI (hot reload)
cd management/frontend && npm install && npm run dev

# Build agents locally
cd agents/linux   && go build ./cmd/agent          # Linux only (build constraint)
cd agents/windows && go build ./cmd/agent          # Windows only
cd agents/macos   && go build ./cmd/agent          # macOS only

# Cross-compile
cd agents/linux   && GOOS=linux   GOARCH=amd64 go build ./cmd/agent
cd agents/windows && GOOS=windows GOARCH=amd64 go build ./cmd/agent
cd agents/macos   && GOOS=darwin  GOARCH=amd64 go build ./cmd/agent
```

---

## License

MIT
