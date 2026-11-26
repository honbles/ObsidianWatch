# ObsidianWatch

Self-hosted security platform for endpoints, applications, source code and cloud accounts. One repository, one `docker compose` stack, one console.

ObsidianWatch collects telemetry from four places and correlates it in one detection engine:

| Area | What it covers | Documentation |
|---|---|---|
| **Endpoint** | Linux, Windows and macOS agents: process, file, network, DNS and logon telemetry; 400+ signatures, Sigma and threat-intel IOCs; response actions (isolate, kill, quarantine, block), live response, hunting, prevention from threat intelligence | [docs/endpoint](docs/endpoint/) |
| **Application (APM)** | OpenTelemetry from Java, .NET, Python, Node, Go and other SDKs, received by the local agent; host discovery of services with no instrumentation; routes, traces, errors, queries, jobs, dependencies, SLOs; application security rules and per-language security helpers | [docs/application](docs/application/) |
| **Codebase** | GitHub, GitLab and Azure DevOps: audit and commits, secrets, SAST (Semgrep/opengrep, CodeQL, built-in rules), dependencies (SCA) and SBOM, repository posture, pull-request checks, scans of the commit actually deployed | [docs/codebase](docs/codebase/) |
| **Cloud** | AWS, Azure (with Entra ID) and GCP: log ingestion, posture (CSPM), CIS benchmarks, compliance, blast radius | [docs/cloud](docs/cloud/) |

The areas are linked: a host shows its services, a service shows the code linked to it and the commit it runs, and host CVEs, open ports and vulnerable code that is actually loaded land in one risk list per host.

---

## 1. Architecture

```
 Endpoints and app servers                     Cloud (AWS / Azure / GCP)     Git (GitHub / GitLab / ADO)
 (Linux / Windows / macOS agents)                      │  API polling                   │  polling + webhooks
        │  TLS :8443, agent certificate                ▼                               ▼
        ▼                                ┌──────────────────────────────────────────────────────────┐
 ┌──────────────┐     TimescaleDB        │  Management API (:8444 HTTPS)                            │
 │   backend    │ ──────────────────────►│  detection and alert engines · APM · cloud · code (SAST) │
 │ event ingest │                        │  threat intel · AI · Agent builder                       │
 └──────────────┘                        └─────────────────────────────┬────────────────────────────┘
                                                                       ▼
                                                        Web console (HTTPS :443)
```

| Service | Role | Host port |
|---|---|---|
| `cert-init` | One-shot: creates the CA and the server certificate for the host IP and domain | – |
| `timescaledb` | Events and platform data (internal network only) | – |
| `backend` | Agent enrollment and event ingest (TLS with agent certificates); relays the live-response tunnel | `8443` |
| `mgmt-api` | Management API, all engines, Agent builder, code scanners | `8444` |
| `mgmt-ui` | Web console (`:80` redirects to HTTPS) | `443`, `80` |

Repository layout:

```
agents/{linux,windows,macos}   endpoint and application agents
agents/network                 network probe (not a supported feature yet)
backend/                       agent ingest server
management/backend/            management API and engines
management/frontend/           React console
management/docker/             management image, server.yaml, scanner install
cert-init/                     certificate generator
samples/app/                   instrumented sample apps (Node, Python, Java, .NET, Go) and verify.sh
tools/                         helper scripts (OpenTelemetry Go SDK refresh)
docs/                          documentation (start at docs/README.md)
```

---

## 2. Install

**Requirements:** a Linux server with Docker and Docker Compose; ports `443`, `80`, `8443` and `8444` reachable from users and endpoints; outbound internet for threat-intel feeds, OSV/NVD, scanner downloads at build time, and cloud and Git APIs.

### 2.1 Configure

```bash
cp .env.example .env
```

| Variable | Required | Purpose |
|---|:---:|---|
| `HOST_IP` | yes | Server IP; becomes a name in the TLS certificate |
| `DB_PASSWORD` | yes | `openssl rand -hex 16` |
| `JWT_SECRET` | yes | `openssl rand -hex 32` (at least 32 characters); signs console logins |
| `OW_SECRET_KEY` | yes | `openssl rand -base64 32`. Encrypts stored credentials and API keys, and signs the agent identity the backend passes to management. **Back it up separately: losing it makes stored credentials unrecoverable** |
| `BACKEND_DOMAIN` | – | Domain name agents use; added to the certificate |
| `EXTRA_SAN_DNS` | – | More DNS names for the certificate, comma-separated |
| `OW_ALLOWED_ORIGINS` | – | Extra browser origins allowed to open WebSockets |
| `AGENT_API_KEY` | – | Not used for authentication any more; leave empty |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | – | Self-monitoring of the management server through the host's agent, e.g. `unix:///run/ow-otlp/otlp.sock` ([application deployment, section 7a](docs/application/deployment.md)) |
| `OW_ENVIRONMENT` | – | Environment name for self-monitoring (default `prod`) |

Services refuse to start with a missing required value or a placeholder such as `changeme`.

**Local changes** (another port, an extra volume) go in `docker-compose.override.yml`, which Compose merges automatically and updates never overwrite. Example, publishing the backend on an extra port:

```yaml
services:
  backend:
    ports:
      - "8834:8443"
```

### 2.2 Start

```bash
sudo docker compose up -d --build
sudo docker compose ps
```

The first build compiles the management image and installs the code scanners; it takes several minutes.

### 2.3 First login

1. Open `https://<server>` (self-signed certificate unless you supplied your own domain and certificate).
2. The setup wizard opens before login: backend and management URLs (pre-filled), optional backend domain, optional AI keys (Groq, Anthropic) and threat-intel keys (ThreatFox, OTX). Run it again later from **Agent builder → Reconfigure setup**.
3. The first start creates `admin` with a one-time password:
   ```bash
   sudo docker compose logs mgmt-api | grep -A4 "First-run admin"
   ```
   Sign in and change it.

### 2.4 Roles

| Role | Access |
|---|---|
| `admin` | Everything: users, settings, Agent builder, connectors, live response, response actions |
| `analyst` | Triage alerts, search, investigate, hunt |
| `viewer` | Read-only (enforced on the server) |

### 2.5 Next steps

1. **Agents:** Agent builder → choose the OS and profile (endpoint, or app server for application monitoring) → install the zip on each host ([endpoint deployment](docs/endpoint/deployment.md)).
2. **Applications:** point each instrumented service at the local agent ([application deployment](docs/application/deployment.md) and the guide for its language).
3. **Code:** Code → Repositories → add a GitHub, GitLab or Azure DevOps connector ([codebase deployment](docs/codebase/deployment.md)). Every repository and branch is rescanned every 5 days by default.
4. **Cloud:** Cloud → add an AWS, Azure or GCP connector ([cloud deployment](docs/cloud/deployment.md)).
5. **Notifications:** Settings → Email alerts; syslog and webhooks through the API ([endpoint configuration](docs/endpoint/configuration.md)).

---

## 3. Documentation for administrators

Read in this order. Each area folder also has capability pages: the full reference of what the feature does, its rules and its limits.

**Platform and endpoints (everyone)**

1. This README: install, upgrade, backup.
2. [docs/endpoint/deployment.md](docs/endpoint/deployment.md): server prerequisites, certificates, building and installing agents, enrollment, tamper protection, revocation.
3. [docs/endpoint/identity.md](docs/endpoint/identity.md): agent certificates, enrollment tokens, renewal and the live-response tunnel.
4. [docs/endpoint/configuration.md](docs/endpoint/configuration.md): agent settings, detection rules, suppressions, notifications, platform settings.
5. [docs/endpoint/response-actions.md](docs/endpoint/response-actions.md): what each response action does and its safety rules.
6. [docs/endpoint/prevention.md](docs/endpoint/prevention.md): IP, hash and domain blocking from threat intelligence; audit and enforce.
7. [docs/known-issues.md](docs/known-issues.md): open defects and their workarounds.

**Application monitoring**

8. [docs/application/deployment.md](docs/application/deployment.md): the app-server agent, sockets for containers and Kubernetes, verification, self-monitoring of the management server.
9. [docs/application/configuration-platform.md](docs/application/configuration-platform.md): console settings per service (SLOs, criticality, payload review, API specs, rule tuning).
10. The guide for each language your teams use: [Java](docs/application/configuration-java.md), [.NET](docs/application/configuration-dotnet.md), [Python](docs/application/configuration-python.md), [Node](docs/application/configuration-node.md) (long walkthrough: [node-security-guide.md](docs/application/node-security-guide.md)), [Go](docs/application/configuration-go.md), [other SDKs](docs/application/configuration-other-sdks.md).

**Codebase security**

11. [docs/codebase/deployment.md](docs/codebase/deployment.md): connecting each Git platform, token rights, webhooks, scanners, automation and pull-request checks.
12. [docs/codebase/configuration.md](docs/codebase/configuration.md): scan policy, schedules, rules and settings.

**Cloud security**

13. [docs/cloud/deployment.md](docs/cloud/deployment.md): how connectors work, credential storage, outbound access.
14. The page for each provider you connect: [AWS](docs/cloud/configuration-aws.md), [Azure](docs/cloud/configuration-azure.md), [GCP](docs/cloud/configuration-gcp.md) (Terraform for GCP: [docs/cloud/gcp/main.tf](docs/cloud/gcp/main.tf)).

**Reference (as needed):** [endpoint](docs/endpoint/capability.md), [application](docs/application/capability.md), [codebase](docs/codebase/capability.md) and cloud ([shared](docs/cloud/capability.md), [AWS](docs/cloud/capability-aws.md), [Azure](docs/cloud/capability-azure.md), [GCP](docs/cloud/capability-gcp.md)) capability pages. The full index is [docs/README.md](docs/README.md).

---

## 4. Operations

### Upgrade

```bash
git pull
sudo docker compose up -d --build
```

Migrations run at start-up. After an upgrade that changes agent code, rebuild agents in the Agent builder and reinstall them; an install over an existing agent upgrades it in place.

### Certificates

After changing the server IP or domain:

```bash
sudo docker compose down
sudo docker volume rm obsidianwatch_certs
# update HOST_IP / BACKEND_DOMAIN in .env
sudo docker compose up -d
```

Then rebuild and reinstall all agents.

### Backup

- The `timescale_data` volume (events and platform data).
- `.env`, above all `OW_SECRET_KEY`, stored apart from database backups.
- The `ca-private` volume (server CA key) and the `agent-ca` volume (agent identity CA; without it every agent must be rebuilt and reinstalled).
- `docker-compose.override.yml`, if you have one.

### Troubleshooting

| Symptom | Check |
|---|---|
| Compose refuses to start | A required `.env` value is missing or still a placeholder |
| Console container exits | Certificates missing: `docker compose logs cert-init` |
| Agent does not appear | From the host: `curl -k https://<server>:8443/health`. In the agent log, `identity:` lines name an expired, revoked or used-up enrollment token |
| Agents stop sending after an upgrade | The backend port changed (for example a local port edit was overwritten): put it in `docker-compose.override.yml` |
| Agent restarts repeatedly | `systemctl status obsidianwatch-agent` shows `oom-kill`: raise `MemoryMax` with a systemd drop-in ([endpoint deployment](docs/endpoint/deployment.md)) |
| Windows process events empty | Sysmon not running: see the Sysmon health alert |
| Service missing in Applications | [application deployment, section 7](docs/application/deployment.md) |
| Cloud connector test fails | A missing permission: compare with the provider's configuration page |
| SAST shows built-in rules only | A scanner failed to install during the image build: check the build log |

### Agent ingest API

All routes except `/health` and `POST /api/v1/enroll` need an agent client certificate ([identity.md](docs/endpoint/identity.md)).

| Route | Purpose |
|---|---|
| `GET /health` | Liveness |
| `POST /api/v1/enroll` | Enrollment: token and CSR → certificate |
| `POST /api/v1/enroll/renew` | Certificate renewal |
| `POST /api/v1/events` | Event batches (`agent_id` must match the certificate) |
| `POST /api/v1/agents/location` | Agent location report |

---

## 5. Development

Each component is its own Go module (Go 1.25); the console needs Node.

```bash
cd backend && go run ./cmd/server -config configs/server.yaml                  # ingest backend
cd management/backend && go run ./cmd/server -config ../docker/server.yaml     # management API
cd management/frontend && npm install && npm run dev                           # console with hot reload
cd agents/linux   && GOOS=linux   go build ./cmd/agent
cd agents/windows && GOOS=windows go build ./cmd/agent
cd agents/macos   && GOOS=darwin  go build ./cmd/agent
cd management/backend && go test ./...
```

Development agents without an embedded config read `agent.yaml` from disk: copy `agents/<os>/configs/agent.yaml` and set `backend_url`, `enroll_token` (Platform settings → Agent enrollment) and `ca_file`.

Application monitoring samples and an end-to-end check against the real agent receiver: `samples/app` (`verify.sh`).

Contributing: keep each platform's signatures limited to fields its collectors fill, register new signature sets in `sig_registry.go`, and add a new migration for schema changes (never edit an applied one). UI conventions: [docs/development/design-language.md](docs/development/design-language.md).

## License

Copyright © 2026 Blessing Honmane. All rights reserved.

This project is proprietary software. Public access to this repository does not grant permission to copy, modify, distribute or commercially use its source code. See [LICENSE](./LICENSE).
