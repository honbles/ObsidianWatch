package api

// devops_engine.go — DevOps connector polling engine + HTTP handlers

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	neturl "net/url"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
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
	// DO-12: skip if a sync for this connector is already running.
	guardKey := fmt.Sprintf("devops:%d", conn.ID)
	if !tryAcquireSync(guardKey) {
		e.logger.Info("devops sync skipped: previous sync still running", "provider", conn.Provider, "org", conn.Org)
		return nil
	}
	defer releaseSync(guardKey)
	syncCtx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()

	ingested, cursor, err := e.doSync(syncCtx, conn)
	if err != nil {
		e.logger.Warn("devops sync failed", "provider", conn.Provider, "org", conn.Org, "err", err)
		e.db.UpdateDevOpsConnectorStatus(ctx, conn.ID, "error", err.Error(), 0, conn.SyncCursor)
		return err
	}
	e.db.UpdateDevOpsConnectorStatus(ctx, conn.ID, "connected", "", int64(ingested), cursor)
	// DO-05: surface reduced coverage instead of silently looking healthy.
	if note := takeCoverageNote(conn.ID); note != "" {
		e.db.SetDevOpsConnectorNote(ctx, conn.ID, note)
	}
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
		if bu, err := validateDevOpsBaseURL(req.Credentials["base_url"]); err != nil {
			writeJSON(w, 400, map[string]string{"error": err.Error()})
			return
		} else if bu != "" {
			req.Credentials["base_url"] = bu
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
		if bu, err := validateDevOpsBaseURL(req.Credentials["base_url"]); err != nil {
			writeJSON(w, 400, map[string]string{"error": err.Error()})
			return
		} else if bu != "" {
			req.Credentials["base_url"] = bu
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
	// DO-02: webhook secrets must be unpredictable — crypto/rand, not clock bits.
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand unavailable: " + err.Error())
	}
	return hex.EncodeToString(b)
}

// isDevOpsEvent returns true if the event came from a DevOps provider
func isDevOpsEvent(ev store.Event) bool {
	return strings.HasPrefix(string(ev.EventType), "devops.")
}

// validateDevOpsBaseURL checks a user-supplied provider base_url before the
// connector token is ever sent to it (DO-10: it used to be taken from the
// request unvalidated, so the token could be exfiltrated to any host or the
// server pointed at internal services). Rules: https only, no userinfo, a
// real hostname, and never loopback / link-local (cloud metadata) / unspecified
// addresses. Private RFC1918 ranges are permitted only when the operator sets
// OW_ALLOW_PRIVATE_DEVOPS=true, since self-hosted GitLab often lives there.
// Returns the normalised URL (scheme://host[:port][/path], no trailing slash).
func validateDevOpsBaseURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", nil
	}
	u, err := neturl.Parse(raw)
	if err != nil || u.Host == "" {
		return "", fmt.Errorf("base_url is not a valid URL")
	}
	if u.Scheme != "https" {
		return "", fmt.Errorf("base_url must use https")
	}
	if u.User != nil {
		return "", fmt.Errorf("base_url must not contain credentials")
	}
	host := strings.ToLower(u.Hostname())
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return "", fmt.Errorf("base_url host is not allowed")
	}
	if a, err := netip.ParseAddr(host); err == nil {
		a = a.Unmap()
		if a.IsLoopback() || a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast() || a.IsUnspecified() || a.IsMulticast() {
			return "", fmt.Errorf("base_url host is not allowed")
		}
		if a.IsPrivate() && os.Getenv("OW_ALLOW_PRIVATE_DEVOPS") != "true" {
			return "", fmt.Errorf("base_url points at a private address (set OW_ALLOW_PRIVATE_DEVOPS=true to allow self-hosted)")
		}
	}
	return strings.TrimRight(u.Scheme+"://"+u.Host+u.EscapedPath(), "/"), nil
}

// ── Coverage notes (DO-05) ────────────────────────────────────────────────────

var (
	coverageMu    sync.Mutex
	coverageNotes = map[int64]string{}
)

func setCoverageNote(id int64, note string) {
	coverageMu.Lock()
	coverageNotes[id] = note
	coverageMu.Unlock()
}

func takeCoverageNote(id int64) string {
	coverageMu.Lock()
	defer coverageMu.Unlock()
	n := coverageNotes[id]
	delete(coverageNotes, id)
	return n
}

// commitEventTime returns the time to stamp on a commit-derived event
// (DS-01/DO-08). Events now carry the real commit time — the detection
// engine pages by ingest time (D-01), so old timestamps are still evaluated —
// which also makes the (id, time) primary key stable, so a commit fetched
// twice (overlap window, manual sync, retry) is deduplicated instead of
// being inserted again. Zero or future-dated values (attacker- or
// clock-controlled) fall back to the receive time.
func commitEventTime(t time.Time) time.Time {
	now := time.Now().UTC()
	if t.IsZero() || t.After(now.Add(5*time.Minute)) {
		return now
	}
	return t.UTC()
}
