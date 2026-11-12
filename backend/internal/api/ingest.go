package api

import (
	"context"
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"obsidianwatch/backend/internal/store"
	"obsidianwatch/backend/pkg/schema"
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

		r.Body = http.MaxBytesReader(w, r.Body, maxIngestBodyBytes)
		// Decode batch
		var batch schema.Batch
		if err := json.NewDecoder(r.Body).Decode(&batch); err != nil {
			metrics.invalid.Add(1)
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

		if len(batch.AgentID) > 128 {
			http.Error(w, `{"error":"agent_id too long"}`, http.StatusBadRequest)
			return
		}
		if !ingestThrottle.allow(batch.AgentID, len(batch.Events)) {
			logger.Warn("ingest: per-agent rate limit exceeded", "agent", batch.AgentID, "count", len(batch.Events))
			metrics.throttled.Add(1)
			w.Header().Set("Retry-After", "30")
			http.Error(w, `{"error":"rate limit exceeded"}`, http.StatusTooManyRequests)
			return
		}
		truncated := 0
		for i := range batch.Events {
			if sanitizeEvent(&batch.Events[i]) {
				truncated++
			}
			liftProcessIdentity(&batch.Events[i])
		}
		metrics.truncated.Add(int64(truncated))
		if truncated > 0 {
			logger.Warn("ingest: oversized fields truncated", "agent", batch.AgentID, "events", truncated)
		}

		// Prefer the explicit hostname field; fall back to scanning events.
		hostname := batch.Hostname
		// X-02: events carry agent-supplied timestamps. The server-side
		// receive time is stored separately (events.ingested_at, migration
		// 007); here we detect clock skew and stop future-dated events from
		// poisoning time-window queries (they would sit at the top of every
		// "latest" view and evade lookback windows).
		recvNow := time.Now().UTC()
		var maxFuture time.Duration
		clamped := 0
		for i := range batch.Events {
			if t := batch.Events[i].Time; !t.IsZero() && t.After(recvNow.Add(10*time.Minute)) {
				if d := t.Sub(recvNow); d > maxFuture {
					maxFuture = d
				}
				batch.Events[i].Time = recvNow
				clamped++
			}
		}
		metrics.clamped.Add(int64(clamped))
		if clamped > 0 {
			logger.Warn("ingest: agent clock skew — future-dated events clamped to receive time",
				"agent", batch.AgentID, "clamped", clamped, "max_skew", maxFuture.Round(time.Second).String())
		}
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
		insStart := time.Now()
		if err := db.InsertEvents(r.Context(), batch.Events); err != nil {
			metrics.insertErrors.Add(1)
			logger.Error("ingest: insert failed", "agent", batch.AgentID, "err", err)
			http.Error(w, `{"error":"internal server error"}`, http.StatusInternalServerError)
			return
		}

		metrics.insertNanos.Add(int64(time.Since(insStart)))
		metrics.batches.Add(1)
		metrics.eventsAccepted.Add(int64(len(batch.Events)))
		metrics.lastIngestUnix.Store(time.Now().Unix())

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

var trustedProxies []netip.Prefix

// SetTrustedProxies (M-13) configures which peers may supply X-Forwarded-For.
func SetTrustedProxies(entries []string) {
	var out []netip.Prefix
	for _, e := range entries {
		e = strings.TrimSpace(e)
		if p, err := netip.ParsePrefix(e); err == nil {
			out = append(out, p)
		} else if a, err := netip.ParseAddr(e); err == nil {
			out = append(out, netip.PrefixFrom(a, a.BitLen()))
		}
	}
	trustedProxies = out
}

func peerAddr(r *http.Request) string {
	if h, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return h
	}
	return r.RemoteAddr
}

// remoteAddr returns the client IP. X-Forwarded-For is honoured only when the
// direct peer is a configured trusted proxy — otherwise any client could set
// the header and spoof last_ip (M-13). When trusted, the rightmost entry not
// itself a trusted proxy is used (the leftmost is client-controlled).
func remoteAddr(r *http.Request) string {
	peer := peerAddr(r)
	pa, err := netip.ParseAddr(peer)
	if err != nil || len(trustedProxies) == 0 || !inTrusted(pa) {
		return peer
	}
	xff := r.Header.Get("X-Forwarded-For")
	if xff == "" {
		return peer
	}
	parts := strings.Split(xff, ",")
	for i := len(parts) - 1; i >= 0; i-- {
		a, err := netip.ParseAddr(strings.TrimSpace(parts[i]))
		if err != nil {
			return peer
		}
		if !inTrusted(a) {
			return a.String()
		}
	}
	return peer
}

func inTrusted(a netip.Addr) bool {
	for _, p := range trustedProxies {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// Ensure ingestStore is satisfied by *store.DB at compile time.
var _ ingestStore = (*store.DB)(nil)
