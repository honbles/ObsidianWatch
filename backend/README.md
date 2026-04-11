# OpenSIEM Backend

The ingest and storage backend for the OpenSIEM platform. Receives security event batches from Windows agents over HTTPS, stores them in TimescaleDB, and exposes a REST API for querying events and agent fleet status.

**Version: v0.2.0**

---

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Prerequisites](#prerequisites)
- [Quick Start](#quick-start)
- [Configuration](#configuration)
- [TLS & Authentication](#tls--authentication)
- [API Reference](#api-reference)
- [Database Schema](#database-schema)
- [Migrations](#migrations)
- [Production Deployment](#production-deployment)
- [Project Structure](#project-structure)
- [Contributing](#contributing)
- [License](#license)

---

## Overview

The OpenSIEM backend is a single Go binary fronted by Docker Compose. It:

- Accepts batched event POSTs from one or more OpenSIEM agents over HTTPS
- Validates, stores, and indexes events in a TimescaleDB hypertable partitioned by time
- Automatically upserts agent metadata (hostname, version, last-seen IP, event count) on every batch
- Runs all schema migrations automatically on startup — no manual SQL required
- Exposes a REST API for the management platform and for direct querying
- Supports mTLS (mutual TLS) or API key authentication — both enforced at the HTTP layer
- Retains 90 days of events by default with a configurable TimescaleDB retention policy

---

## Architecture

```
                          HTTPS :8443
  agent.exe (Windows) ─────────────────► opensiem-backend (Go)
                                                │
                                                │ SQL
                                                ▼
                                        TimescaleDB :5432
                                        (hypertable: events)
                                        (table:      agents)

  Management Platform ──────────────── GET /api/v1/events
                                        GET /api/v1/agents
```

Both services run as Docker containers on the same host via Docker Compose. TimescaleDB data is persisted in a named volume.

---

## Prerequisites

- Docker 24+ and Docker Compose v2
- A Linux server (Ubuntu 22.04+ recommended)
- Ports `8443` (HTTPS ingest/API) and optionally `5432` (DB, localhost only) available
- TLS certificate and key for the server (see [TLS & Authentication](#tls--authentication))

---

## Quick Start

```bash
# 1. Clone the repo
git clone https://github.com/honbles/opensiem-backend.git
cd opensiem-backend

# 2. Create your certs directory and generate a self-signed cert (dev only)
mkdir docker/certs
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout docker/certs/server.key \
  -out docker/certs/server.crt \
  -days 365 \
  -subj "/CN=opensiem-backend" \
  -addext "subjectAltName=IP:$(hostname -I | awk '{print $1}')"

# 3. Edit the runtime config
cp docker/server.yaml docker/server.yaml
# Set:
#   database.password  — must match POSTGRES_PASSWORD in docker-compose.yml
#   auth.api_keys      — generate with: openssl rand -hex 32

# 4. Start everything
cd docker
docker compose up -d --build

# 5. Verify
curl -k https://localhost:8443/health
```

Expected response:
```json
{"status":"ok","db":"ok","version":"0.2.0"}
```

---

## Configuration

The backend is configured by `docker/server.yaml`, which is mounted read-only into the container. Edit this file before or after starting — restart the container to apply changes.

### Full annotated server.yaml

```yaml
server:
  # Address and port to listen on inside the container.
  listen_addr: ":8443"

  # TLS certificate and key (PEM format).
  # Paths are relative to the working directory inside the container (/app/).
  tls_cert_file: "certs/server.crt"
  tls_key_file:  "certs/server.key"

  # CA certificate for mTLS client verification.
  # Only required when auth.mtls_enabled: true
  # tls_ca_file: "certs/ca.crt"

  read_timeout:  "30s"
  write_timeout: "30s"

  # Maximum number of events accepted in a single POST /api/v1/events request.
  max_batch_size: 1000

database:
  # Use the Docker Compose service name when running inside compose.
  # Use the actual IP/hostname when the management platform connects remotely.
  host:     "timescaledb"
  port:     5432
  name:     "opensiem"
  user:     "opensiem"
  password: "changeme"       # MUST match POSTGRES_PASSWORD in docker-compose.yml
  ssl_mode: "disable"

  # Connection pool
  max_open_conns:    25
  max_idle_conns:    10
  conn_max_lifetime: "5m"

auth:
  # List of accepted X-API-Key header values.
  # Generate a key: openssl rand -hex 32
  # Paste the same value into agent.yaml → forwarder.api_key
  api_keys:
    - "your-generated-key-here"

  # Set to true to require a valid mTLS client certificate instead of API keys.
  # Also set tls_ca_file above when enabling this.
  mtls_enabled: false

log:
  level:  "info"    # debug | info | warn | error
  format: "json"    # json  | text
```

### docker-compose.yml environment variables

| Variable | Default | Description |
|---|---|---|
| `POSTGRES_DB` | `opensiem` | Database name |
| `POSTGRES_USER` | `opensiem` | Database user |
| `POSTGRES_PASSWORD` | `changeme` | **Change this** — must match `database.password` in server.yaml |

---

## TLS & Authentication

The backend always requires HTTPS. Authentication is enforced on all `/api/` routes. The `/health` endpoint is public.

### Mode 1 — API Key (default)

Every request to `/api/` must include the header:

```
X-API-Key: your-api-key-here
```

Configure one or more keys in `server.yaml`:

```yaml
auth:
  api_keys:
    - "key-for-agent-1"
    - "key-for-agent-2"
  mtls_enabled: false
```

Generate a key:
```bash
openssl rand -hex 32
```

### Mode 2 — Mutual TLS (mTLS)

With mTLS enabled, the server requires every connecting client to present a certificate signed by your CA. API key headers are ignored.

```yaml
server:
  tls_cert_file: "certs/server.crt"
  tls_key_file:  "certs/server.key"
  tls_ca_file:   "certs/ca.crt"     # CA that signed agent certs

auth:
  mtls_enabled: true
```

**Creating a CA and issuing certificates:**

```bash
# CA (do this once)
openssl genrsa -out ca.key 4096
openssl req -new -x509 -days 3650 -key ca.key -out ca.crt \
  -subj "/C=US/O=OpenSIEM/CN=OpenSIEM-CA"

# Server certificate
openssl genrsa -out server.key 2048
openssl req -new -key server.key -out server.csr \
  -subj "/C=US/O=OpenSIEM/CN=your-server-hostname"

cat > server-ext.cnf << EOF
[req]
req_extensions = v3_req
[v3_req]
subjectAltName = @alt_names
[alt_names]
DNS.1 = your-server-hostname
IP.1  = 192.168.1.140
EOF

openssl x509 -req -days 825 -in server.csr -CA ca.crt -CAkey ca.key \
  -CAcreateserial -out server.crt -extfile server-ext.cnf -extensions v3_req

# Per-agent certificate (repeat for each agent)
HOSTNAME="workstation-01"
openssl genrsa -out ${HOSTNAME}.key 2048
openssl req -new -key ${HOSTNAME}.key -out ${HOSTNAME}.csr \
  -subj "/C=US/O=OpenSIEM/CN=${HOSTNAME}"
openssl x509 -req -days 825 -in ${HOSTNAME}.csr \
  -CA ca.crt -CAkey ca.key -CAcreateserial -out ${HOSTNAME}.crt
```

Copy `ca.crt`, `server.crt`, and `server.key` to `docker/certs/`.  
Distribute `ca.crt`, `HOSTNAME.crt`, and `HOSTNAME.key` to each agent host.

---

## API Reference

All `/api/` endpoints require authentication (see above). All responses are JSON.

---

### `GET /health`

Public. Returns server and database health.

**Response:**
```json
{
  "status": "ok",
  "db": "ok",
  "version": "0.2.0"
}
```

If the database is unreachable, `"db"` returns `"error"` and the HTTP status is `503`.

---

### `POST /api/v1/events`

Ingest a batch of events from an agent. Called by the agent forwarder — not typically called manually.

**Request body:**
```json
{
  "agent_id": "CORP-VAPT",
  "agent_version": "0.2.0",
  "sent_at": "2025-03-07T12:00:00Z",
  "events": [
    {
      "id": "abc123",
      "time": "2025-03-07T11:59:55Z",
      "agent_id": "CORP-VAPT",
      "host": "CORP-VAPT",
      "os": "windows",
      "event_type": "logon",
      "severity": 3,
      "source": "Security",
      "event_id": 4625,
      "user_name": "administrator",
      "domain": "CORP",
      "src_ip": "10.0.0.55",
      "raw": {}
    }
  ]
}
```

**Response:**
```json
{"accepted": 1}
```

**Errors:**

| Status | Meaning |
|---|---|
| `400` | Missing `agent_id`, invalid JSON, or empty batch |
| `413` | Batch exceeds `max_batch_size` |
| `401` | Missing or invalid API key / client certificate |
| `500` | Database write error |

---

### `GET /api/v1/events`

Query stored events with optional filters. Default window is the last 24 hours.

**Query parameters:**

| Parameter | Type | Description |
|---|---|---|
| `agent_id` | string | Filter by agent ID |
| `host` | string | Filter by hostname |
| `event_type` | string | `logon` `process` `network` `registry` `file` `dns` `fim` `applog` `health` `sysmon` `raw` |
| `severity` | int | Minimum severity (1–5) |
| `src_ip` | string | Filter by source IP |
| `dst_ip` | string | Filter by destination IP |
| `user_name` | string | Filter by username |
| `since` | RFC3339 | Start of time range |
| `until` | RFC3339 | End of time range |
| `limit` | int | Results per page (default 100, max 1000) |
| `offset` | int | Pagination offset (default 0) |

**Example:**
```bash
# Last 100 failed logons in the past hour
curl -k "https://localhost:8443/api/v1/events?event_type=logon&severity=3&since=2025-03-07T11:00:00Z" \
  -H "X-API-Key: your-key"

# All events from a specific host
curl -k "https://localhost:8443/api/v1/events?host=CORP-VAPT&limit=500" \
  -H "X-API-Key: your-key"
```

**Response:**
```json
{
  "events": [ { ...event objects... } ],
  "total": 1042,
  "limit": 100,
  "offset": 0
}
```

---

### `GET /api/v1/agents`

List all agents that have ever connected, with online/offline status.

An agent is considered **online** if its `last_seen` timestamp is within the last 2 minutes.

**Response:**
```json
{
  "agents": [
    {
      "id": "CORP-VAPT",
      "hostname": "CORP-VAPT",
      "os": "windows",
      "version": "0.2.0",
      "first_seen": "2025-03-05T10:00:00Z",
      "last_seen": "2025-03-07T12:00:01Z",
      "last_ip": "192.168.1.105",
      "event_count": 284921,
      "online": true
    }
  ]
}
```

---

### `GET /api/v1/agents/{id}`

Get a single agent by ID.

**Example:**
```bash
curl -k "https://localhost:8443/api/v1/agents/CORP-VAPT" \
  -H "X-API-Key: your-key"
```

Returns the same object as in the list, or `404` if not found.

---

## Database Schema

The backend uses two primary tables and a migration tracking table.

### `events` (TimescaleDB hypertable)

Partitioned by `time` in 1-day chunks. Retention policy: 90 days.

| Column | Type | Description |
|---|---|---|
| `id` | TEXT | Deterministic dedup ID (primary key with time) |
| `time` | TIMESTAMPTZ | Event timestamp — hypertable partition key |
| `agent_id` | TEXT | Agent identifier |
| `host` | TEXT | Hostname |
| `os` | TEXT | Operating system |
| `event_type` | TEXT | logon / process / network / registry / file / dns / health / applog / sysmon / raw |
| `severity` | SMALLINT | 1–5 |
| `source` | TEXT | Channel or provider name |
| `raw` | JSONB | Full original payload — GIN indexed |
| `pid` | INTEGER | Process ID |
| `ppid` | INTEGER | Parent process ID |
| `process_name` | TEXT | Process image name |
| `command_line` | TEXT | Full command line — trigram indexed |
| `image_path` | TEXT | Full path to process image |
| `user_name` | TEXT | Subject or target user |
| `domain` | TEXT | AD domain |
| `logon_id` | TEXT | Logon session ID |
| `src_ip` | INET | Source IP address |
| `src_port` | INTEGER | Source port |
| `dst_ip` | INET | Destination IP or queried DNS name |
| `dst_port` | INTEGER | Destination port |
| `proto` | TEXT | tcp / udp / icmp |
| `reg_key` | TEXT | Registry key path |
| `reg_value` | TEXT | Registry value name |
| `reg_data` | TEXT | New registry value data |
| `file_path` | TEXT | File or object path — trigram indexed |
| `file_hash` | TEXT | File hash |
| `event_id` | INTEGER | Windows Event ID |
| `channel` | TEXT | Windows Event Log channel |
| `record_id` | BIGINT | Event record ID |

### `agents`

| Column | Type | Description |
|---|---|---|
| `id` | TEXT | Agent ID (primary key) |
| `hostname` | TEXT | Machine hostname |
| `os` | TEXT | Operating system |
| `version` | TEXT | Agent version |
| `first_seen` | TIMESTAMPTZ | When the agent first connected |
| `last_seen` | TIMESTAMPTZ | When the agent last sent a batch |
| `last_ip` | TEXT | Last seen remote IP |
| `event_count` | BIGINT | Total events received from this agent |

---

## Migrations

Migrations run automatically every time the backend starts. Each `.sql` file in `internal/store/migrations/` is applied once and recorded in the `schema_migrations` table.

| File | Description |
|---|---|
| `001_events.sql` | Events hypertable, TimescaleDB setup, retention policy, base indexes |
| `002_agents.sql` | Agents table |
| `003_indexes.sql` | v0.2.0 query indexes — channel, event_id, file_path, command_line trigram, JSONB GIN, composite indexes for alert engine and dashboard stats |

**To add a migration:** create `NNN_description.sql` (next sequence number, zero-padded) with idempotent SQL. It will be picked up automatically on the next restart.

---

## Production Deployment

### Checklist before going live

```bash
# 1. Generate a strong database password
openssl rand -hex 32

# 2. Update docker-compose.yml
POSTGRES_PASSWORD: "your-strong-password"

# 3. Update server.yaml to match
database:
  password: "your-strong-password"

# 4. Generate API keys
openssl rand -hex 32

# 5. Update server.yaml
auth:
  api_keys:
    - "your-generated-api-key"

# 6. Use a real TLS certificate (Let's Encrypt, internal CA, or self-signed with CA)

# 7. Set log level to warn in production to reduce volume
log:
  level: "warn"
```

### Start / stop / update

```bash
cd docker

# Start all services
docker compose up -d --build

# View logs
docker compose logs -f backend
docker compose logs -f timescaledb

# Restart backend only (e.g. after editing server.yaml)
docker compose restart backend

# Stop everything
docker compose down

# Stop and wipe all data (DESTRUCTIVE)
docker compose down -v
```

### Verify events are arriving

```bash
# Count events in the last 5 minutes
curl -k -s "https://localhost:8443/api/v1/events?since=$(date -u -d '5 minutes ago' +%Y-%m-%dT%H:%M:%SZ)&limit=1" \
  -H "X-API-Key: your-key" | python3 -m json.tool

# Check agent fleet
curl -k -s "https://localhost:8443/api/v1/agents" \
  -H "X-API-Key: your-key" | python3 -m json.tool
```

### Direct database access

```bash
# Connect to TimescaleDB directly
docker exec -it opensiem-db psql -U opensiem -d opensiem

# Useful queries
SELECT event_type, count(*) FROM events
  WHERE time > NOW() - INTERVAL '1 hour'
  GROUP BY event_type ORDER BY count DESC;

SELECT host, max(last_seen) as last_seen, sum(event_count) as total
  FROM agents GROUP BY host;

-- Check hypertable chunk status
SELECT * FROM timescaledb_information.chunks
  WHERE hypertable_name = 'events' ORDER BY range_end DESC LIMIT 10;
```

### Firewall rules

| Direction | Port | Protocol | Purpose |
|---|---|---|---|
| Inbound | 8443 | TCP | Agent ingest + management platform API |
| Inbound | 5432 | TCP | DB access (localhost only — do not expose) |
| Outbound | — | — | None required |

---

## Project Structure

```
backend/
├── cmd/
│   └── server/
│       └── main.go                  # Entry point — config, DB, migrations, HTTP server
├── internal/
│   ├── api/
│   │   ├── server.go                # HTTP server, route registration, TLS, middleware
│   │   ├── ingest.go                # POST /api/v1/events — batch validation and insert
│   │   ├── query.go                 # GET  /api/v1/events — filter and paginate
│   │   ├── agents.go                # GET  /api/v1/agents and /api/v1/agents/{id}
│   │   └── health.go                # GET  /health — server and DB liveness
│   ├── auth/
│   │   ├── apikey.go                # X-API-Key middleware
│   │   └── mtls.go                  # mTLS client certificate middleware and TLS config helpers
│   ├── store/
│   │   ├── db.go                    # PostgreSQL connection pool
│   │   ├── events.go                # InsertEvents, QueryEvents, CountEvents
│   │   ├── agents.go                # UpsertAgent, ListAgents, GetAgent
│   │   └── migrations/
│   │       ├── migrate.go           # Embedded SQL migration runner
│   │       ├── 001_events.sql       # Events hypertable
│   │       ├── 002_agents.sql       # Agents table
│   │       └── 003_indexes.sql      # v0.2.0 performance indexes
│   └── config/
│       └── config.go                # YAML config loader, defaults, validation
├── pkg/
│   └── schema/
│       └── event.go                 # Shared Event and Batch types (mirrors agent schema)
├── docker/
│   ├── Dockerfile                   # Multi-stage Go build
│   ├── docker-compose.yml           # TimescaleDB + backend services
│   ├── server.yaml                  # Runtime config (mounted into container)
│   └── certs/                       # TLS certificate directory (gitignored)
├── configs/
│   └── server.yaml                  # Build-time config template
└── go.mod
```

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

---

## License

MIT — see [LICENSE](LICENSE) for details.
