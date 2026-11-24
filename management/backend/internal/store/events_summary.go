package store

import (
	"context"
	"fmt"
	"time"
)

// EventBucket is the number of events in one time bucket, split by severity (1..5).
type EventBucket struct {
	T     time.Time `json:"t"`
	N     int64     `json:"n"`
	BySev [6]int64  `json:"by_sev"`
}

// FacetValue is one value of a field and how many matching events carry it.
type FacetValue struct {
	V string `json:"v"`
	N int64  `json:"n"`
}

// EventSummary is the explorer header for a query: counts over time and the most common
// values of a few fields, both over every matching event rather than one page of them.
type EventSummary struct {
	Step    string                  `json:"step"`
	Buckets []EventBucket           `json:"buckets"`
	Facets  map[string][]FacetValue `json:"facets"`
}

// summaryFacetColumns are the fields counted for the facet panel. Fixed list: column names
// are interpolated into SQL, so they must never come from the request.
var summaryFacetColumns = []string{"host", "event_type", "source", "user_name", "process_name"}

// summaryStep picks a bucket width giving roughly 40-120 bars for the range.
func summaryStep(span time.Duration) (string, time.Duration) {
	steps := []struct {
		s string
		d time.Duration
	}{
		{"1 minute", time.Minute}, {"5 minutes", 5 * time.Minute}, {"15 minutes", 15 * time.Minute},
		{"30 minutes", 30 * time.Minute}, {"1 hour", time.Hour}, {"3 hours", 3 * time.Hour},
		{"6 hours", 6 * time.Hour}, {"12 hours", 12 * time.Hour}, {"1 day", 24 * time.Hour},
	}
	for _, s := range steps {
		if span/s.d <= 120 {
			return s.s, s.d
		}
	}
	return "1 day", 24 * time.Hour
}

// SummarizeEvents counts matching events per time bucket and severity, and the top values
// of each summary facet. f.Since must be set by the caller (it bounds the scan).
func (db *DB) SummarizeEvents(ctx context.Context, f EventFilter, facetLimit int) (*EventSummary, error) {
	whereStr, args, err := buildEventWhere(f)
	if err != nil {
		return nil, err
	}
	until := f.Until
	if until.IsZero() {
		until = time.Now()
	}
	step, _ := summaryStep(until.Sub(f.Since))
	out := &EventSummary{Step: step, Buckets: []EventBucket{}, Facets: map[string][]FacetValue{}}

	rows, err := db.QueryContext(ctx, fmt.Sprintf(`
		SELECT time_bucket('%s', time) AS b, LEAST(GREATEST(COALESCE(severity, 1), 1), 5) AS s, COUNT(*)
		FROM events WHERE %s
		GROUP BY 1, 2 ORDER BY 1`, step, whereStr), args...)
	if err != nil {
		return nil, fmt.Errorf("store: summarize events: %w", err)
	}
	idx := map[int64]int{}
	for rows.Next() {
		var b time.Time
		var s int
		var n int64
		if err := rows.Scan(&b, &s, &n); err != nil {
			rows.Close()
			return nil, fmt.Errorf("store: summarize events: %w", err)
		}
		i, ok := idx[b.Unix()]
		if !ok {
			out.Buckets = append(out.Buckets, EventBucket{T: b})
			i = len(out.Buckets) - 1
			idx[b.Unix()] = i
		}
		out.Buckets[i].N += n
		out.Buckets[i].BySev[s] += n
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: summarize events: %w", err)
	}

	if facetLimit <= 0 || facetLimit > 25 {
		facetLimit = 10
	}
	for _, col := range summaryFacetColumns {
		frows, err := db.QueryContext(ctx, fmt.Sprintf(`
			SELECT %s, COUNT(*) FROM events
			WHERE %s AND %s IS NOT NULL AND %s <> ''
			GROUP BY 1 ORDER BY 2 DESC LIMIT %d`, col, whereStr, col, col, facetLimit), args...)
		if err != nil {
			// A facet that fails (timeout on a huge range) must not hide the timeline.
			continue
		}
		vals := []FacetValue{}
		for frows.Next() {
			var v FacetValue
			if frows.Scan(&v.V, &v.N) == nil {
				vals = append(vals, v)
			}
		}
		frows.Close()
		out.Facets[col] = vals
	}
	return out, nil
}
