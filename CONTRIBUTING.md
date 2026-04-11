# Contributing to ObsidianWatch Management Platform

Thank you for your interest in contributing. This document covers development setup, conventions, and how to submit changes.

---

## Development Setup

### Backend (Go)

**Prerequisites:** Go 1.22+, Docker (for a local TimescaleDB)

```bash
git clone https://github.com/honbles/obsidianwatch-management.git
cd obsidianwatch-management/backend

# Copy and configure
cp docker/server.yaml server.yaml
# Set database.password and auth.jwt_secret

# Run
go mod tidy
go run ./cmd/server -config server.yaml
```

### Frontend (React)

**Prerequisites:** Node.js 20+

```bash
cd frontend
npm install
npm run dev    # http://localhost:5173
```

The Vite dev server proxies `/api/`, `/auth/`, and `/ws/` to `localhost:8080` — make sure the Go API is running first.

The backend runs all schema migrations automatically on startup — no manual SQL needed.

---

## Project Layout

```
backend/
├── cmd/server/main.go               # Entry point, startup, graceful shutdown
├── internal/
│   ├── api/
│   │   ├── server.go                # HTTP server, route registration, middleware
│   │   ├── handlers.go              # All REST handler functions
│   │   ├── ws.go                    # WebSocket hub and broadcaster
│   │   └── alerts_engine.go         # Background alert auto-creation (every 30s)
│   ├── auth/
│   │   ├── jwt.go                   # JWT signing and validation
│   │   └── middleware.go            # HTTP auth middleware
│   ├── store/
│   │   ├── events.go                # Event queries (read-only)
│   │   ├── agents.go                # Agent queries (read-only)
│   │   ├── alerts.go                # Alert CRUD
│   │   ├── stats.go                 # Dashboard stats + threat intel aggregations
│   │   ├── users.go                 # User auth queries
│   │   └── migrations/              # Auto-applied SQL files
│   └── config/config.go             # YAML config loader, defaults, validation
frontend/
├── src/
│   ├── pages/                       # One file per page
│   ├── components/                  # Shared UI: Navbar, SeverityBadge
│   └── api/
│       ├── client.js                # Axios instance with JWT interceptor
│       └── useLiveFeed.js           # WebSocket hook with auto-reconnect
└── nginx.conf                       # SPA routing + reverse proxy to mgmt-api
```

---

## Adding a New API Endpoint

1. Write a handler function in `internal/api/handlers.go` (or a new file for a new domain).
2. Register it in `internal/api/server.go` — under `protected` for JWT-required routes, directly on `mux` for public routes.
3. Add any required store methods in `internal/store/`.
4. Update the frontend to consume the new endpoint.

Handler signature convention:

```go
func handleYourThing(db *store.DB) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        // ...
        writeJSON(w, http.StatusOK, result)
    }
}
```

Use `writeJSON(w, status, payload)` for all JSON responses — it sets the correct `Content-Type` header.

---

## Adding a New Frontend Page

1. Create `frontend/src/pages/YourPage.jsx`.
2. Add the route in `frontend/src/App.jsx`.
3. Add a nav link in `frontend/src/components/Navbar.jsx`.

Use the shared API client and live feed hook:

```js
import api from '../api/client'
const { data } = await api.get('/api/v1/your-endpoint')

import { useLiveFeed } from '../api/useLiveFeed'
const { events, connected } = useLiveFeed(200)
```

Style with Tailwind using the custom `siem-*` color palette defined in `tailwind.config.js`.

---

## Adding a Database Migration

1. Create `internal/store/migrations/NNN_description.sql` where `NNN` is the next sequence number, zero-padded to three digits.
2. Write idempotent SQL — `CREATE TABLE IF NOT EXISTS`, `CREATE INDEX IF NOT EXISTS`, `ADD COLUMN IF NOT EXISTS`.
3. The runner applies files in lexicographic order and records each in `schema_migrations` — it never re-runs the same file.
4. Never modify an already-applied migration — always add a new file.

The management platform has its own `schema_migrations` table, separate from the agent backend's.

---

## Code Style

### Go

- Format with `gofmt -w .` before committing
- All exported types and functions must have a doc comment
- Use `slog` for all logging: `Debug` for per-request noise, `Info` for lifecycle events, `Warn` for recoverable errors, `Error` for startup failures
- Store methods always accept `context.Context` as the first argument
- Handlers return `http.HandlerFunc` — they don't implement `http.Handler` directly

### React

- Functional components with hooks only
- Style with Tailwind `siem-*` utility classes
- API calls belong in `useEffect`, not inline in render
- Use the shared `SeverityBadge` component for severity display
- Loading states: simple "Loading..." text in table cells, not full-page spinners

---

## Pull Request Process

1. Open an issue first for significant changes.
2. Fork and create a feature branch: `git checkout -b feat/your-feature`.
3. Run `go build ./...` and `go test ./...` before pushing.
4. Update `docker/server.yaml` and `README.md` if you add or change configuration.
5. Open the PR against `main` with a clear description of the change and why.

---

## Good First Issues

- Add `PATCH /api/v1/auth/password` — change-password endpoint for the logged-in user
- Add `GET /api/v1/events/{id}` — single event by ID with full raw JSON
- Add `event_id` and `channel` as query filter parameters on `GET /api/v1/events`
- Add a Settings page (change password, show current API token, theme toggle)
- Write integration tests using `testcontainers-go` against a real TimescaleDB
- Support environment variable overrides for all config fields (e.g. `OBSIDIANWATCH_JWT_SECRET`)
- Add role-based access control — restrict `analyst` role from closing others' alerts
- Add a per-agent detail page showing that agent's recent events and stats

---

## Reporting Bugs

Open a GitHub issue with:

- OS and Docker version
- Go version (`go version`) or Node version (`node --version`)
- Relevant section of `server.yaml` (redact passwords and JWT secret)
- Container logs: `sudo docker logs obsidianwatch-mgmt-api` and `sudo docker logs obsidianwatch-mgmt-ui`
- Steps to reproduce

---

## License

By contributing you agree that your contributions will be licensed under the [MIT License](LICENSE).
