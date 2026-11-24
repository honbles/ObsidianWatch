package api

// app_sketch.go - the mergeable quantile sketch (DDSketch, 1 % relative accuracy), the same code as the agent's otel.Sketch.
// recorded in ms. Unlike the 12-bucket histogram it has no ceiling, so a 60 s request is reported as roughly 60 s,
// and two sketches (two instances, two minutes) merge exactly. The same code is kept in the ingest backend and in
// the management backend (store.appSketch and api.appSketch): keep the three in step. Wire form: appSketchWire.

import (
	"context"
	"encoding/json"
	"math"
	"sort"
	"time"

	"obsidianwatch/management/internal/store"
)

const (
	appSketchAlpha    = 0.01
	appSketchMaxBins  = 2048
	appSketchMinValue = 0.001 // ms; anything at or below goes to the zero bucket
)

var appSketchGamma = (1 + appSketchAlpha) / (1 - appSketchAlpha)
var appSketchLnGamma = math.Log(appSketchGamma)

// appSketchWire is the serialised sketch: B is a flat list of (bin index, count) pairs in ascending index order.
type appSketchWire struct {
	Z   int64   `json:"z,omitempty"` // observations at or below appSketchMinValue
	Max float64 `json:"max"`         // largest value seen, exact
	B   []int64 `json:"b"`
}

// appSketch is the in-memory form.
type appSketch struct {
	bins  map[int64]int64
	zero  int64
	count int64
	max   float64
}

func newAppSketch() *appSketch { return &appSketch{bins: map[int64]int64{}} }

func (s *appSketch) Count() int64 { return s.count }
func (s *appSketch) Max() float64 { return s.max }

func appSketchIndex(v float64) int64 { return int64(math.Ceil(math.Log(v) / appSketchLnGamma)) }

// Add records one observation in ms. NaN, infinite and negative values are ignored.
func (s *appSketch) Add(v float64) {
	if math.IsNaN(v) || math.IsInf(v, 0) || v < 0 {
		return
	}
	s.count++
	if v > s.max {
		s.max = v
	}
	if v <= appSketchMinValue {
		s.zero++
		return
	}
	s.bins[appSketchIndex(v)]++
	if len(s.bins) > appSketchMaxBins {
		s.collapse()
	}
}

// collapse merges the lowest bins until the bin limit holds; the error then only affects the very lowest quantiles.
func (s *appSketch) collapse() {
	idx := s.sorted()
	for len(idx) > appSketchMaxBins {
		s.bins[idx[1]] += s.bins[idx[0]]
		delete(s.bins, idx[0])
		idx = idx[1:]
	}
}

func (s *appSketch) sorted() []int64 {
	idx := make([]int64, 0, len(s.bins))
	for i := range s.bins {
		idx = append(idx, i)
	}
	sort.Slice(idx, func(a, b int) bool { return idx[a] < idx[b] })
	return idx
}

// Merge adds another sketch's observations into this one.
func (s *appSketch) Merge(o *appSketch) {
	if o == nil {
		return
	}
	s.count += o.count
	s.zero += o.zero
	if o.max > s.max {
		s.max = o.max
	}
	for i, c := range o.bins {
		s.bins[i] += c
	}
	if len(s.bins) > appSketchMaxBins {
		s.collapse()
	}
}

// Quantile returns the q-quantile (0..1) in ms, or 0 for an empty sketch.
func (s *appSketch) Quantile(q float64) float64 {
	if s.count == 0 {
		return 0
	}
	if q <= 0 {
		q = 0
	}
	if q >= 1 {
		return s.max
	}
	rank := q * float64(s.count-1)
	seen := float64(s.zero)
	if rank < seen {
		return 0
	}
	for _, i := range s.sorted() {
		seen += float64(s.bins[i])
		if rank < seen {
			v := 2 * math.Pow(appSketchGamma, float64(i)) / (appSketchGamma + 1)
			if v > s.max {
				v = s.max
			}
			return v
		}
	}
	return s.max
}

// CountAtOrBelow returns how many observations are at or below v ms, to the sketch's accuracy.
func (s *appSketch) CountAtOrBelow(v float64) int64 {
	if v < 0 {
		return 0
	}
	n := s.zero
	if v <= appSketchMinValue {
		return n
	}
	limit := appSketchIndex(v)
	for i, c := range s.bins {
		if i <= limit {
			n += c
		}
	}
	return n
}

func (s *appSketch) Wire() *appSketchWire {
	w := &appSketchWire{Z: s.zero, Max: s.max, B: make([]int64, 0, len(s.bins)*2)}
	for _, i := range s.sorted() {
		w.B = append(w.B, i, s.bins[i])
	}
	return w
}

// appSketchFromWire rebuilds a sketch. It returns nil for a malformed or oversized wire form.
func appSketchFromWire(w *appSketchWire) *appSketch {
	if w == nil || len(w.B)%2 != 0 || len(w.B) > appSketchMaxBins*2+2 || w.Z < 0 || math.IsNaN(w.Max) || math.IsInf(w.Max, 0) || w.Max < 0 {
		return nil
	}
	s := newAppSketch()
	s.zero, s.max, s.count = w.Z, w.Max, w.Z
	for k := 0; k < len(w.B); k += 2 {
		if w.B[k+1] < 0 || w.B[k+1] > 1<<40 {
			return nil
		}
		s.bins[w.B[k]] += w.B[k+1]
		s.count += w.B[k+1]
	}
	return s
}

// appSketchMaxRange is the longest range read from sketches. A sketch is stored per route per minute, so longer
// ranges would read too many rows; they use the histogram and say so.
const appSketchMaxRange = 7 * 24 * time.Hour

// appLoadSketches merges the per-minute sketches of a service for a range, grouped by keyFn. method is
// "sketch" when every row in the range carries a complete sketch (the result is then usable), "histogram" when
// no row does (agents older than this feature, or a range that is too long), and "mixed" when only some do; in
// both of the latter cases the map is nil and callers use the histogram.
func appLoadSketches(ctx context.Context, idb *store.DB, id int64, from, to time.Time, route, method string,
	keyFn func(minute time.Time, route, method string) string) (map[string]*appSketch, string) {
	if to.Sub(from) > appSketchMaxRange {
		return nil, "histogram"
	}
	rows, err := idb.QueryContext(ctx, `
		SELECT minute, route, method, calls, sketch_calls, sketch
		FROM app_route_stats
		WHERE service_id = $1 AND minute >= $2 AND minute < $3 AND ($4 = '' OR route = $4) AND ($5 = '' OR method = $5)`,
		id, from, to, route, method)
	if err != nil {
		return nil, "histogram" // the column appears with the ingest migration
	}
	defer rows.Close()
	out := map[string]*appSketch{}
	complete, any, total := 0, 0, 0
	for rows.Next() {
		var minute time.Time
		var rt, mt string
		var calls, skCalls int64
		var raw []byte
		if rows.Scan(&minute, &rt, &mt, &calls, &skCalls, &raw) != nil {
			continue
		}
		total++
		if len(raw) == 0 || skCalls != calls {
			if len(raw) > 0 {
				any++
			}
			continue
		}
		var w appSketchWire
		sk := (*appSketch)(nil)
		if json.Unmarshal(raw, &w) == nil {
			sk = appSketchFromWire(&w)
		}
		if sk == nil {
			continue
		}
		any++
		complete++
		for _, k := range []string{keyFn(minute, rt, mt), "all"} {
			if out[k] == nil {
				out[k] = newAppSketch()
			}
			out[k].Merge(sk)
		}
	}
	switch {
	case total == 0 || any == 0:
		return nil, "histogram"
	case complete == total:
		return out, "sketch"
	}
	return nil, "mixed"
}

// appApdex is (satisfied + tolerating / 2) / total with T the latency target: satisfied up to T, tolerating up to 4T.
func appApdex(s *appSketch, targetMs int) *float64 {
	if s == nil || s.Count() == 0 || targetMs <= 0 {
		return nil
	}
	t := float64(targetMs)
	sat, tol := s.CountAtOrBelow(t), s.CountAtOrBelow(4*t)-s.CountAtOrBelow(t)
	v := (float64(sat) + float64(tol)/2) / float64(s.Count())
	v = float64(int64(v*1000+0.5)) / 1000
	return &v
}
