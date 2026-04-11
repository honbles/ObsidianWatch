package api

// devops_engine.go — DevOps connector polling engine + HTTP handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"obsidianwatch/management/internal/store"
)

// ── DevOps Engine ─────────────────────────────────────────────────────────────

type DevOpsEngine struct {
	db      *store.DB
	eventDB *store.DB
	logger  *slog.Logger
}

func NewDevOpsEngine(db *store.DB, eventDB *store.DB, logger *slog.Logger) *DevOpsEngine {
	return &DevOpsEngine{db: db, eventDB: eventDB, logger: logger}
}

func (e *DevOpsEngine) Run(ctx context.Context) {
	e.logger.Info("devops engine started")
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	// Run immediately on startup
	e.syncAll(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			e.syncAll(ctx)
		}
	}
}

func (e *DevOpsEngine) syncAll(ctx context.Context) {
	connectors, err := e.db.ListDevOpsConnectorsRaw(ctx)
	if err != nil {
		e.logger.Warn("devops: list connectors failed", "err", err)
		return
	}
	for _, conn := range connectors {
		c := conn
		go e.syncOne(ctx, &c)
	}
}

func (e *DevOpsEngine) SyncOne(ctx context.Context, id int64) error {
	conn, err := e.db.GetDevOpsConnectorRaw(ctx, id)
	if err != nil {
		return err
	}
	return e.syncOne(ctx, conn)
}

func (e *DevOpsEngine) syncOne(ctx context.Context, conn *store.DevOpsConnector) error {
	syncCtx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()

	ingested, cursor, err := e.doSync(syncCtx, conn)
	if err != nil {
		e.logger.Warn("devops sync failed", "provider", conn.Provider, "org", conn.Org, "err", err)
		e.db.UpdateDevOpsConnectorStatus(ctx, conn.ID, "error", err.Error(), 0, conn.SyncCursor)
		return err
	}
	e.db.UpdateDevOpsConnectorStatus(ctx, conn.ID, "connected", "", int64(ingested), cursor)
	if ingested > 0 {
		e.logger.Info("devops sync complete", "provider", conn.Provider, "org", conn.Org, "ingested", ingested)
	}
	return nil
}

func (e *DevOpsEngine) doSync(ctx context.Context, conn *store.DevOpsConnector) (int, string, error) {
	switch conn.Provider {
	case "github":
		return syncGitHub(ctx, conn, e.db, e.eventDB)
	case "gitlab":
		return syncGitLab(ctx, conn, e.db, e.eventDB)
	case "azuredevops":
		return syncAzureDevOps(ctx, conn, e.db, e.eventDB)
	default:
		return 0, "", fmt.Errorf("unknown provider: %s", conn.Provider)
	}
}

// ── HTTP Handlers ─────────────────────────────────────────────────────────────

func handleListDevOpsConnectors(db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		connectors, err := db.ListDevOpsConnectors(r.Context())
		if err != nil {
			http.Error(w, `{"error":"db error"}`, 500)
			return
		}
		if connectors == nil {
			connectors = []store.DevOpsConnector{}
		}
		writeJSON(w, 200, map[string]interface{}{"connectors": connectors})
	}
}

func handleSaveDevOpsConnector(db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Provider string            `json:"provider"`
			Org      string            `json:"org"`
			Label    string            `json:"label"`
			Credentials map[string]string `json:"credentials"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, 400, map[string]string{"error": "invalid body"})
			return
		}
		if req.Provider == "" || req.Org == "" {
			writeJSON(w, 400, map[string]string{"error": "provider and org required"})
			return
		}
		// Generate webhook secret
		webhookSecret := generateToken(16)
		id, err := db.UpsertDevOpsConnector(r.Context(),
			req.Provider, req.Org, req.Label, req.Credentials, webhookSecret)
		if err != nil {
			writeJSON(w, 500, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, 200, map[string]interface{}{
			"id":             id,
			"webhook_secret": webhookSecret,
			"status":         "pending",
		})
	}
}

func handleTestDevOpsConnector(db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Provider    string            `json:"provider"`
			Org         string            `json:"org"`
			Credentials map[string]string `json:"credentials"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, 400, map[string]string{"error": "invalid body"})
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
		defer cancel()

		var label string
		var err error
		switch req.Provider {
		case "github":
			label, err = testGitHubConnection(ctx, req.Credentials["token"], req.Org)
		case "gitlab":
			label, err = testGitLabConnection(ctx,
				req.Credentials["token"], req.Credentials["base_url"], req.Org)
		case "azuredevops":
			label, err = testAzureDevOpsConnection(ctx,
				req.Credentials["token"], req.Org, req.Credentials["base_url"])
		default:
			err = fmt.Errorf("unknown provider: %s", req.Provider)
		}
		if err != nil {
			writeJSON(w, 400, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, 200, map[string]string{"status": "ok", "label": label})
	}
}

func handleSyncDevOpsConnector(db *store.DB, engine *DevOpsEngine) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		idStr := r.PathValue("id")
		id, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			writeJSON(w, 400, map[string]string{"error": "invalid id"})
			return
		}
		go engine.SyncOne(context.Background(), id)
		writeJSON(w, 200, map[string]string{"status": "sync started"})
	}
}

func handleDeleteDevOpsConnector(db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		idStr := r.PathValue("id")
		id, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			writeJSON(w, 400, map[string]string{"error": "invalid id"})
			return
		}
		if err := db.DeleteDevOpsConnector(r.Context(), id); err != nil {
			writeJSON(w, 500, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, 200, map[string]string{"status": "deleted"})
	}
}

func handleListDevOpsCommits(db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		idStr := r.PathValue("id")
		id, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			writeJSON(w, 400, map[string]string{"error": "invalid id"})
			return
		}
		repo := r.URL.Query().Get("repo")
		limit := 100
		if l := r.URL.Query().Get("limit"); l != "" {
			if n, err := strconv.Atoi(l); err == nil && n > 0 {
				limit = n
			}
		}
		commits, err := db.ListDevOpsCommits(r.Context(), id, repo, limit)
		if err != nil {
			writeJSON(w, 500, map[string]string{"error": err.Error()})
			return
		}
		if commits == nil {
			commits = []store.DevOpsCommit{}
		}
		writeJSON(w, 200, commits)
	}
}

func handleGetDevOpsCommit(db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("sha")
		commit, err := db.GetDevOpsCommit(r.Context(), id)
		if err != nil {
			writeJSON(w, 404, map[string]string{"error": "not found"})
			return
		}
		writeJSON(w, 200, commit)
	}
}

// generateToken generates a hex random token
func generateToken(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(time.Now().UnixNano()>>uint(i%8) ^ int64(i*17))
	}
	return fmt.Sprintf("%x", b)
}

// isDevOpsEvent returns true if the event came from a DevOps provider
func isDevOpsEvent(ev store.Event) bool {
	return strings.HasPrefix(string(ev.EventType), "devops.")
}
