package api

import (
	"context"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"obsidianwatch/management/internal/store"
)

// P-02: fleet prevalence. Every evaluated process/file event records
// (hash | image path | process name) x host so analysts can see how many hosts
// have run a binary and when it was first seen fleet-wide. No ML, just counts.

const prevalenceMaxPerBatch = 5000

func prevalenceKeys(ev store.Event) []string {
	var keys []string
	if ev.FileHash != nil {
		h := strings.ToLower(strings.TrimSpace(*ev.FileHash))
		if i := strings.Index(h, "="); i >= 0 {
			h = h[i+1:]
		}
		if len(h) >= 32 && len(h) <= 128 {
			keys = append(keys, "hash:"+h)
		}
	}
	if ev.EventType == "process" {
		if ev.ImagePath != nil && *ev.ImagePath != "" && len(*ev.ImagePath) < 400 {
			keys = append(keys, "image:"+strings.ToLower(*ev.ImagePath))
		}
		if ev.ProcessName != nil && *ev.ProcessName != "" && len(*ev.ProcessName) < 200 {
			keys = append(keys, "proc:"+strings.ToLower(filepath.Base(*ev.ProcessName)))
		}
	}
	return keys
}

func (e *DetectionEngine) recordPrevalence(events []store.Event) {
	if len(events) == 0 {
		return
	}
	type k struct{ key, host string }
	agg := map[k]*store.PrevalenceObs{}
	for _, ev := range events {
		if ev.Host == "" {
			continue
		}
		for _, key := range prevalenceKeys(ev) {
			kk := k{key, ev.Host}
			if o, ok := agg[kk]; ok {
				o.Count++
				if ev.Time.Before(o.At) {
					o.At = ev.Time
				}
			} else if len(agg) < prevalenceMaxPerBatch {
				agg[kk] = &store.PrevalenceObs{Key: key, Host: ev.Host, Count: 1, At: ev.Time}
			}
		}
	}
	if len(agg) == 0 {
		return
	}
	obs := make([]store.PrevalenceObs, 0, len(agg))
	for _, o := range agg {
		obs = append(obs, *o)
	}
	// Detached context so a cancelled cycle does not lose the batch, bounded.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := e.db.RecordPrevalence(ctx, obs); err != nil {
		e.logger.Warn("prevalence: record failed", "err", err)
	}
}

// handlePrevalence: GET /api/v1/prevalence?hash=..|image=..|process=..
func handlePrevalence(db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		var key string
		switch {
		case q.Get("hash") != "":
			key = "hash:" + strings.ToLower(strings.TrimSpace(q.Get("hash")))
		case q.Get("image") != "":
			key = "image:" + strings.ToLower(q.Get("image"))
		case q.Get("process") != "":
			key = "proc:" + strings.ToLower(filepath.Base(q.Get("process")))
		default:
			writeJSONError(w, http.StatusBadRequest, "provide hash, image or process")
			return
		}
		info, err := db.GetPrevalence(r.Context(), key)
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, "lookup failed")
			return
		}
		writeJSON(w, 200, info)
	}
}
