package api

import (
	"fmt"
	"net/http"
	"sync/atomic"
	"time"
)

// H-06: lightweight ingest metrics in Prometheus text format. Exposed at
// GET /api/v1/metrics behind the same auth as the ingest API.

type ingestMetrics struct {
	batches        atomic.Int64
	eventsAccepted atomic.Int64
	throttled      atomic.Int64
	insertErrors   atomic.Int64
	truncated      atomic.Int64
	clamped        atomic.Int64
	invalid        atomic.Int64
	lastIngestUnix atomic.Int64
	insertNanos    atomic.Int64 // cumulative insert time
}

var metrics = &ingestMetrics{}

func handleMetrics() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		last := metrics.lastIngestUnix.Load()
		age := float64(-1)
		if last > 0 {
			age = float64(time.Now().Unix() - last)
		}
		ingestThrottle.mu.Lock()
		agents := len(ingestThrottle.m)
		ingestThrottle.mu.Unlock()
		fmt.Fprintf(w, "# TYPE ow_ingest_batches_total counter\now_ingest_batches_total %d\n", metrics.batches.Load())
		fmt.Fprintf(w, "# TYPE ow_ingest_events_total counter\now_ingest_events_total %d\n", metrics.eventsAccepted.Load())
		fmt.Fprintf(w, "# TYPE ow_ingest_throttled_batches_total counter\now_ingest_throttled_batches_total %d\n", metrics.throttled.Load())
		fmt.Fprintf(w, "# TYPE ow_ingest_insert_errors_total counter\now_ingest_insert_errors_total %d\n", metrics.insertErrors.Load())
		fmt.Fprintf(w, "# TYPE ow_ingest_truncated_events_total counter\now_ingest_truncated_events_total %d\n", metrics.truncated.Load())
		fmt.Fprintf(w, "# TYPE ow_ingest_clock_skew_clamped_total counter\now_ingest_clock_skew_clamped_total %d\n", metrics.clamped.Load())
		fmt.Fprintf(w, "# TYPE ow_ingest_invalid_requests_total counter\now_ingest_invalid_requests_total %d\n", metrics.invalid.Load())
		fmt.Fprintf(w, "# TYPE ow_ingest_insert_seconds_total counter\now_ingest_insert_seconds_total %.3f\n", float64(metrics.insertNanos.Load())/1e9)
		fmt.Fprintf(w, "# TYPE ow_ingest_last_batch_age_seconds gauge\now_ingest_last_batch_age_seconds %.0f\n", age)
		fmt.Fprintf(w, "# TYPE ow_ingest_tracked_agents gauge\now_ingest_tracked_agents %d\n", agents)
	}
}
