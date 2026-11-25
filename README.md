# ObsidianWatch

Self-hosted, full-stack SIEM. One repository, one command to deploy.

ObsidianWatch collects security telemetry from **endpoints**, **cloud accounts** and **Git platforms**, runs it through a single **detection engine** (400+ built-in signatures, Sigma, threat-intel IOCs, correlation), and gives analysts one dashboard for alerts, search, posture and response.

## Status

| Module | Status | Documentation |
|---|---|---|
| Endpoint monitoring | Supported | Linux, Windows and macOS agents: telemetry, detection, response actions, live response, threat hunting. [docs/endpoint](docs/endpoint/) |
| Cloud security | Supported | AWS, Azure (with Entra ID) and GCP: log ingestion, posture (CSPM), CIS, compliance, blast radius. [docs/cloud](docs/cloud/) |
| Codebase security | Supported | GitHub, GitLab and Azure DevOps: audit, commits, secrets, SAST, SCA, posture. [docs/codebase](docs/codebase/) |
| Application monitoring | Built; not yet run in production | OpenTelemetry from Java, .NET, Python, Node and other SDKs, received by the local agent: routes, traces, errors, queries, dependencies, application security rules. [docs/application](docs/application/) |
| Network monitoring | Not yet supported | The probe code exists (`agents/network`) but is not part of the supported feature set |

Every folder has `deployment.md`, configuration and capability pages. Start at [docs/README.md](docs/README.md). Known defects found while writing the docs are listed in [docs/known-issues.md](docs/known-issues.md).

---

## 1. Architecture

```
 Endpoints (Linux / Windows / macOS)            Cloud (AWS / Azure / GCP)     Git (GitHub / GitLab / ADO)
        │  TLS :8443  (agent certificate)               │  API polling every 5 min      │  polling + webhooks
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
| `backend` | Agent event ingest and enrollment (TLS, agent certificates); proxies the live-response tunnel to management | `8443` |
| `mgmt-api` | Management API, detection/alert/cloud/DevOps engines, Agent Builder | `8444` |
| `mgmt-ui` | Dashboard (`:80` only redirects to HTTPS) | `443`, `80` |

### Repository layout

```
obsidianwatch/
├── agents/
│   ├── linux/            Linux agent  - systemd service
│   ├── windows/          Windows agent - Windows Service + tamper DACL
│   ├── macos/            macOS agent  - launchd daemon
│   └── network/          Network probe (not yet a supported feature)
├── backend/              Agent ingest server
├── management/
│   ├── backend/          Management API (alerts, detections, cloud, DevOps, AI, Agent Builder)
│   ├── frontend/         React + Tailwind dashboard
│   └── docker/           Management image, server.yaml, Semgrep rules
├── cert-init/            Certificate generator
├── docs/cloud/gcp/  Terraform for a read-only GCP collector service account
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
| `AGENT_API_KEY` | – | No longer used: agents authenticate with their own certificates. Leave empty |
| `JWT_SECRET` | ✅ | `openssl rand -hex 32` (≥ 32 chars). Signs dashboard logins |
| `OW_SECRET_KEY` | ✅ | `openssl rand -base64 32`. Encrypts cloud/Git credentials, API keys and SMTP password at rest (AES-256-GCM), and signs the agent identity the backend passes to management (both services need the same value). **Back it up separately. Losing it makes stored credentials unrecoverable** |
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

Notification channels: **SMTP email** (Settings → Email Alerts), plus **syslog forwarding** and **webhooks** (configured through the API, see the endpoint configuration guide).

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
- The `agent-ca` volume (agent identity CA). Without it every agent must be rebuilt and reinstalled.

### Agent ingest API (for custom integrations)

All routes except `/health` and `POST /api/v1/enroll` require an agent client certificate from the agent CA ([docs/endpoint/identity.md](docs/endpoint/identity.md)). There is no API key.

| Route | Purpose |
|---|---|
| `GET /health` | Liveness |
| `POST /api/v1/enroll` | Enrollment: token + CSR → certificate (no client certificate needed) |
| `POST /api/v1/enroll/renew` | Certificate renewal |
| `POST /api/v1/events` | Batch event ingest (`agent_id` must match the certificate) |
| `POST /api/v1/agents/location` | Agent location report |

### Troubleshooting

| Symptom | Check |
|---|---|
| Compose refuses to start | A required `.env` value is missing or still a placeholder |
| Dashboard container exits | Certificates missing: `docker compose logs cert-init` |
| Agent not appearing | `curl -k https://<server>:8443/health` from the endpoint; check the agent log for "identity:" lines (an expired, revoked or used-up enrollment token is named there; rebuild in the Agent builder); check Platform settings → Agent enrollment  |
| Agent TLS errors | Certificates were regenerated: rebuild the agent |
| Windows process detection empty | Sysmon not running: check the Sysmon health alert |
| Agent shows offline but live response works | Its event queue is stuck: see docs/endpoint/deployment.md (troubleshooting) |
| macOS process events delayed | Full Disk Access not granted, so `eslogger` is unavailable and polling is used |
| Cloud connector test fails | Missing permission: the GCP test lists them; for AWS/Azure compare against docs/cloud/configuration-aws.md or configuration-azure.md |
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

Development builds without an embedded config read `agent.yaml` from disk. Copy `agents/<os>/configs/agent.yaml`, set `backend_url`, `enroll_token` (create one in Platform settings → Agent enrollment) and `ca_file`, and run the binary directly.

**Contributing:** keep each platform's signatures limited to fields its collectors populate, add new signature sets to `sig_registry.go` so the sanity tests and ATT&CK coverage see them, and add a migration (never edit an applied one) for schema changes.

## License

Copyright © 2026 Blessing Honmane.

All Rights Reserved.

This project is proprietary software. Public access to this
repository does not grant permission to copy, modify, distribute,
or commercially use its source code.

See [LICENSE](./LICENSE) for details.
