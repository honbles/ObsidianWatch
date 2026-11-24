package otel

// sketch.go - a mergeable quantile sketch (DDSketch, 1 % relative accuracy, at most 2048 bins). Latencies are
// recorded in ms. Unlike the 12-bucket histogram it has no ceiling, so a 60 s request is reported as roughly 60 s,
// and two sketches (two instances, two minutes) merge exactly. The same code is kept in the ingest backend and in
// the management backend (store.Sketch and api.appSketch): keep the three in step. Wire form: SketchWire.

import (
	"math"
	"sort"
)

const (
	sketchAlpha    = 0.01
	sketchMaxBins  = 2048
	sketchMinValue = 0.001 // ms; anything at or below goes to the zero bucket
)

var sketchGamma = (1 + sketchAlpha) / (1 - sketchAlpha)
var sketchLnGamma = math.Log(sketchGamma)

// SketchWire is the serialised sketch: B is a flat list of (bin index, count) pairs in ascending index order.
type SketchWire struct {
	Z   int64   `json:"z,omitempty"` // observations at or below sketchMinValue
	Max float64 `json:"max"`         // largest value seen, exact
	B   []int64 `json:"b"`
}

// Sketch is the in-memory form.
type Sketch struct {
	bins  map[int64]int64
	zero  int64
	count int64
	max   float64
}

func NewSketch() *Sketch { return &Sketch{bins: map[int64]int64{}} }

func (s *Sketch) Count() int64 { return s.count }
func (s *Sketch) Max() float64 { return s.max }

func sketchIndex(v float64) int64 { return int64(math.Ceil(math.Log(v) / sketchLnGamma)) }

// Add records one observation in ms. NaN, infinite and negative values are ignored.
func (s *Sketch) Add(v float64) {
	if math.IsNaN(v) || math.IsInf(v, 0) || v < 0 {
		return
	}
	s.count++
	if v > s.max {
		s.max = v
	}
	if v <= sketchMinValue {
		s.zero++
		return
	}
	s.bins[sketchIndex(v)]++
	if len(s.bins) > sketchMaxBins {
		s.collapse()
	}
}

// collapse merges the lowest bins until the bin limit holds; the error then only affects the very lowest quantiles.
func (s *Sketch) collapse() {
	idx := s.sorted()
	for len(idx) > sketchMaxBins {
		s.bins[idx[1]] += s.bins[idx[0]]
		delete(s.bins, idx[0])
		idx = idx[1:]
	}
}

func (s *Sketch) sorted() []int64 {
	idx := make([]int64, 0, len(s.bins))
	for i := range s.bins {
		idx = append(idx, i)
	}
	sort.Slice(idx, func(a, b int) bool { return idx[a] < idx[b] })
	return idx
}

// Merge adds another sketch's observations into this one.
func (s *Sketch) Merge(o *Sketch) {
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
	if len(s.bins) > sketchMaxBins {
		s.collapse()
	}
}

// Quantile returns the q-quantile (0..1) in ms, or 0 for an empty sketch.
func (s *Sketch) Quantile(q float64) float64 {
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
			v := 2 * math.Pow(sketchGamma, float64(i)) / (sketchGamma + 1)
			if v > s.max {
				v = s.max
			}
			return v
		}
	}
	return s.max
}

// CountAtOrBelow returns how many observations are at or below v ms, to the sketch's accuracy.
func (s *Sketch) CountAtOrBelow(v float64) int64 {
	if v < 0 {
		return 0
	}
	n := s.zero
	if v <= sketchMinValue {
		return n
	}
	limit := sketchIndex(v)
	for i, c := range s.bins {
		if i <= limit {
			n += c
		}
	}
	return n
}

func (s *Sketch) Wire() *SketchWire {
	w := &SketchWire{Z: s.zero, Max: s.max, B: make([]int64, 0, len(s.bins)*2)}
	for _, i := range s.sorted() {
		w.B = append(w.B, i, s.bins[i])
	}
	return w
}

// SketchFromWire rebuilds a sketch. It returns nil for a malformed or oversized wire form.
func SketchFromWire(w *SketchWire) *Sketch {
	if w == nil || len(w.B)%2 != 0 || len(w.B) > sketchMaxBins*2+2 || w.Z < 0 || math.IsNaN(w.Max) || math.IsInf(w.Max, 0) || w.Max < 0 {
		return nil
	}
	s := NewSketch()
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
