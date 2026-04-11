# Contributing to OpenSIEM Backend

Thank you for your interest in contributing. This document covers development setup, conventions, and how to submit changes.

---

## Development Setup

**Prerequisites:**
- Go 1.22+
- Docker and Docker Compose
- Git

```bash
git clone https://github.com/honbles/opensiem-backend.git
cd opensiem-backend

# Start a local TimescaleDB for development
docker compose -f docker/docker-compose.yml up timescaledb -d

# Copy the example config and edit it
cp docker/server.yaml server.yaml
# Set database.password and auth.api_keys

# Build and run the backend
go mod tidy
go run ./cmd/server -config server.yaml

# Run tests
go test ./...

# Build binary
go build -o opensiem-backend ./cmd/server
```

The server auto-runs all pending migrations on startup, so you never need to apply SQL files manually.

---

## Project Layout

```
backend/
├── cmd/server/main.go               # Entry point, startup wiring
├── internal/
│   ├── api/
│   │   ├── server.go                # HTTP server, routes, TLS, middleware
│   │   ├── ingest.go                # POST /api/v1/events
│   │   ├── query.go                 # GET  /api/v1/events
│   │   ├── agents.go                # GET  /api/v1/agents, GET /api/v1/agents/{id}
│   │   └── health.go                # GET  /health
│   ├── auth/
│   │   ├── apikey.go                # X-API-Key middleware
│   │   └── mtls.go                  # mTLS client certificate middleware
│   ├── store/
│   │   ├── db.go                    # Connection pool
│   │   ├── events.go                # InsertEvents, QueryEvents, CountEvents
│   │   ├── agents.go                # UpsertAgent, ListAgents, GetAgent
│   │   └── migrations/
│   │       ├── migrate.go           # Auto-migration runner
│   │       ├── 001_events.sql       # Events hypertable + indexes
│   │       ├── 002_agents.sql       # Agents table
│   │       └── 003_indexes.sql      # v0.2.0 query indexes
│   └── config/config.go             # YAML config loader
├── pkg/schema/event.go              # Shared Event and Batch types
├── docker/
│   ├── Dockerfile
│   ├── docker-compose.yml
│   └── server.yaml                  # Runtime config (mounted into container)
└── go.mod
```

---

## Adding a New API Endpoint

1. Create a handler function in the appropriate file under `internal/api/` (or a new file if the domain is new).
2. Register the route in `internal/api/server.go` — place it under `protected` if it requires auth, or `mux` directly if it is public.
3. Add any required store methods in `internal/store/`.
4. Write a test for the handler.

Handler signature convention:
```go
func handleYourThing(db yourStoreInterface) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        // ...
        writeJSON(w, http.StatusOK, result)
    }
}
```

Use the `writeJSON` helper (defined in `server.go`) for all JSON responses — it sets the correct `Content-Type` header and handles encoding errors.

---

## Adding a Database Migration

1. Create `internal/store/migrations/NNN_description.sql` where `NNN` is the next sequence number (zero-padded to three digits).
2. Write idempotent SQL — use `CREATE TABLE IF NOT EXISTS`, `CREATE INDEX IF NOT EXISTS`, `ADD COLUMN IF NOT EXISTS`, etc.
3. The migration runner applies files in lexicographic order and records each file in `schema_migrations` so it is never applied twice.
4. Never modify an already-applied migration file — always add a new one.

---

## Code Style

- Format with `gofmt -w .` before committing.
- All exported types and functions must have a doc comment.
- Use `slog` for all logging: `Debug` for per-request detail, `Info` for lifecycle events, `Warn` for recoverable errors, `Error` for fatal startup failures.
- Store methods accept a `context.Context` as the first parameter.
- Handler functions return `http.HandlerFunc` — they do not implement `http.Handler` directly.
- Do not log request bodies — they may contain sensitive event data.

---

## Pull Request Process

1. Open an issue first for significant changes.
2. Fork and create a feature branch: `git checkout -b feat/your-feature`.
3. Run `go build ./...` and `go test ./...` before pushing.
4. Update `docker/server.yaml` and `README.md` if you add or change any configuration.
5. Open the pull request against `main` with a clear description.

---

## Good First Issues

- Add `GET /api/v1/stats` — return event counts grouped by severity and event_type for a time range
- Add `event_id` and `channel` as query filter parameters on `GET /api/v1/events`
- Write integration tests using `testcontainers-go` to spin up a real TimescaleDB
- Add structured request logging (method, path, status, duration) to `loggingMiddleware`
- Support environment variable overrides for all config fields (e.g. `OPENSIEM_DB_PASSWORD`)
- Add `GET /api/v1/events/{id}` to retrieve a single event by ID

---

## Reporting Bugs

Open a GitHub issue with:

- OS and Docker version
- Go version (`go version`)
- The relevant section of `server.yaml` (redact passwords and API keys)
- Container logs (`docker compose logs backend`)
- Steps to reproduce

---

## License

By contributing you agree that your contributions will be licensed under the [MIT License](LICENSE).
