package api

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"obsidianwatch/backend/pkg/schema"
	"obsidianwatch/backend/internal/store"
)

type ingestStore interface {
	InsertEvents(ctx context.Context, events []schema.Event) error
	UpsertAgent(ctx context.Context, id, hostname, os, version, remoteIP, installKey string, eventCount int) error
}

func handleIngest(db ingestStore, maxBatch int, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
			return
		}

		// Decode batch
		var batch schema.Batch
		if err := json.NewDecoder(r.Body).Decode(&batch); err != nil {
			http.Error(w, `{"error":"invalid JSON"}`, http.StatusBadRequest)
			return
		}

		// Basic validation
		if batch.AgentID == "" {
			http.Error(w, `{"error":"missing agent_id"}`, http.StatusBadRequest)
			return
		}
		if len(batch.Events) == 0 {
			writeJSON(w, http.StatusOK, map[string]any{"accepted": 0})
			return
		}
		if len(batch.Events) > maxBatch {
			http.Error(w, `{"error":"batch too large"}`, http.StatusRequestEntityTooLarge)
			return
		}

		// Prefer the explicit hostname field; fall back to scanning events.
		hostname := batch.Hostname
		for i := range batch.Events {
			if batch.Events[i].AgentID == "" {
				batch.Events[i].AgentID = batch.AgentID
			}
			if batch.Events[i].Time.IsZero() {
				batch.Events[i].Time = time.Now().UTC()
			}
			if hostname == "" && batch.Events[i].Host != "" {
				hostname = batch.Events[i].Host
			}
		}
		if hostname == "" {
			hostname = batch.AgentID
		}

		// Write events
		if err := db.InsertEvents(r.Context(), batch.Events); err != nil {
			logger.Error("ingest: insert failed", "agent", batch.AgentID, "err", err)
			http.Error(w, `{"error":"internal server error"}`, http.StatusInternalServerError)
			return
		}

		// Update agent registry
		remoteIP := remoteAddr(r)
		os := "unknown"
		if len(batch.Events) > 0 && batch.Events[0].OS != "" {
			os = batch.Events[0].OS
		}
		if err := db.UpsertAgent(r.Context(),
			batch.AgentID, hostname, os, batch.AgentVer, remoteIP, batch.InstallKey, len(batch.Events),
		); err != nil {
			// Non-fatal — log and continue
			logger.Warn("ingest: upsert agent failed", "agent", batch.AgentID, "err", err)
		}

		logger.Info("ingest: batch accepted",
			"agent", batch.AgentID,
			"host", hostname,
			"count", len(batch.Events),
			"remote_ip", remoteIP,
		)

		writeJSON(w, http.StatusOK, map[string]any{
			"accepted": len(batch.Events),
			"agent_id": batch.AgentID,
		})
	}
}

// remoteAddr extracts a clean IP from the request, honouring X-Forwarded-For
// when the backend is behind a reverse proxy.
func remoteAddr(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// Take the first (leftmost) IP — the original client.
		if parts := strings.Split(xff, ","); len(parts) > 0 {
			return strings.TrimSpace(parts[0])
		}
	}
	// Strip port from RemoteAddr.
	addr := r.RemoteAddr
	if idx := strings.LastIndex(addr, ":"); idx != -1 {
		return addr[:idx]
	}
	return addr
}

// Ensure ingestStore is satisfied by *store.DB at compile time.
var _ ingestStore = (*store.DB)(nil)
