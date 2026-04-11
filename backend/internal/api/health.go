package api

import (
	"context"
	"encoding/json"
	"net/http"
	"time"
)

type healthStore interface {
	HealthCheck(ctx context.Context) error
}

type healthResponse struct {
	Status    string    `json:"status"`
	Time      time.Time `json:"time"`
	Database  string    `json:"database"`
}

func handleHealth(db healthStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
		defer cancel()

		dbStatus := "ok"
		if err := db.HealthCheck(ctx); err != nil {
			dbStatus = "error: " + err.Error()
		}

		status := "ok"
		code := http.StatusOK
		if dbStatus != "ok" {
			status = "degraded"
			code = http.StatusServiceUnavailable
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		json.NewEncoder(w).Encode(healthResponse{
			Status:   status,
			Time:     time.Now().UTC(),
			Database: dbStatus,
		})
	}
}
