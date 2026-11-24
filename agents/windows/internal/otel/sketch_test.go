package otel

import (
	"math"
	"math/rand"
	"sort"
	"testing"
	"time"
)

func TestSketchAccuracyBeyondHistogramCeiling(t *testing.T) {
	r := rand.New(rand.NewSource(1))
	s := NewSketch()
	var all []float64
	for i := 0; i < 20000; i++ {
		v := math.Exp(r.Float64()*math.Log(60000)) + 0.5 // 0.5 ms to 60 s, log-uniform
		all = append(all, v)
		s.Add(v)
	}
	sort.Float64s(all)
	for _, q := range []float64{0.5, 0.95, 0.99} {
		want := all[int(q*float64(len(all)-1))]
		got := s.Quantile(q)
		if math.Abs(got-want)/want > 0.011 {
			t.Fatalf("p%.0f: got %.2f want %.2f", q*100, got, want)
		}
	}
	if s.Max() < 59000 {
		t.Fatalf("max %v", s.Max())
	}
}

func TestSketchMergeEqualsWhole(t *testing.T) {
	r := rand.New(rand.NewSource(2))
	a, b, whole := NewSketch(), NewSketch(), NewSketch()
	for i := 0; i < 5000; i++ {
		v := r.Float64() * 3000
		whole.Add(v)
		if i%2 == 0 {
			a.Add(v)
		} else {
			b.Add(v)
		}
	}
	m := SketchFromWire(a.Wire())
	m.Merge(SketchFromWire(b.Wire()))
	if m.Count() != whole.Count() || m.Quantile(0.99) != whole.Quantile(0.99) {
		t.Fatalf("merge: %d %v vs %d %v", m.Count(), m.Quantile(0.99), whole.Count(), whole.Quantile(0.99))
	}
}

func TestSketchBinLimitAndBadWire(t *testing.T) {
	s := NewSketch()
	for i := 0; i < 100000; i++ {
		s.Add(math.Pow(1.03, float64(i%1500)) * 0.01)
	}
	if len(s.bins) > sketchMaxBins {
		t.Fatalf("bins: %d", len(s.bins))
	}
	for _, w := range []*SketchWire{{B: []int64{1}}, {B: []int64{1, -5}}, {Z: -1}, {Max: math.NaN()}} {
		if SketchFromWire(w) != nil {
			t.Fatalf("accepted %+v", w)
		}
	}
	e := NewSketch()
	if e.Quantile(0.5) != 0 {
		t.Fatal("empty sketch")
	}
	e.Add(math.NaN())
	e.Add(-1)
	if e.Count() != 0 {
		t.Fatal("bad values counted")
	}
}

func TestAggregatorSendsSketch(t *testing.T) {
	a, _ := newTestAgg(AggOptions{})
	end := testNow.Add(-time.Minute)
	a.Ingest(srvSpan("/x", 200, 90000, end), verifiedPeer, IdentityVerified) // 90 s: past the histogram ceiling
	a.Ingest(srvSpan("/x", 200, 40, end), verifiedPeer, IdentityVerified)
	b := a.Flush("ag", false)
	if b == nil || len(b.Routes) != 1 || b.Routes[0].Sketch == nil {
		t.Fatalf("no sketch in batch: %+v", b)
	}
	sk := SketchFromWire(b.Routes[0].Sketch)
	if sk.Count() != 2 || sk.Max() < 89000 {
		t.Fatalf("sketch: %d %v", sk.Count(), sk.Max())
	}
}
