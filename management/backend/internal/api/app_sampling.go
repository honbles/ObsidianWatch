package api

// app_sampling.go - "kept / seen" per keep reason for a service (APM spec item 13.3), so loss from sampling is visible.

import (
	"net/http"
	"strconv"

	"obsidianwatch/management/internal/store"
)

type appSamplingRow struct {
	Reason string `json:"reason"`
	Seen   int64  `json:"seen"`
	Kept   int64  `json:"kept"`
}

func appHandleSampling(db, backendDB *store.DB) http.HandlerFunc {
	idb := appIngestDB(db, backendDB)
	return func(w http.ResponseWriter, r *http.Request) {
		id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid id"})
			return
		}
		from, to, msg := appParseRange(r)
		if msg != "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": msg})
			return
		}
		rows, err := idb.QueryContext(r.Context(), `
			SELECT reason, SUM(seen), SUM(kept) FROM app_sampling_stats
			WHERE service_id = $1 AND hour >= date_trunc('hour', $2::timestamptz) AND hour < $3 GROUP BY reason`, id, from, to)
		out := []appSamplingRow{}
		if err == nil { // a missing table means no counters yet
			for rows.Next() {
				var x appSamplingRow
				if rows.Scan(&x.Reason, &x.Seen, &x.Kept) == nil {
					out = append(out, x)
				}
			}
			rows.Close()
		}
		order := map[string]int{"security": 0, "error": 1, "slow": 2, "baseline": 3}
		for i := range out {
			for j := i + 1; j < len(out); j++ {
				if order[out[j].Reason] < order[out[i].Reason] {
					out[i], out[j] = out[j], out[i]
				}
			}
		}
		writeJSON(w, http.StatusOK, map[string]any{"sampling": out})
	}
}
