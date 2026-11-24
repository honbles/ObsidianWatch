package otel

import (
	"fmt"
	"testing"
	"time"
)

func sampCount(b *Batch, reason string) (seen, kept int64) {
	for _, s := range b.Sampling {
		if s.Reason == reason {
			seen += s.Seen
			kept += s.Kept
		}
	}
	return
}

func TestSamplingBaselineZeroStopsBaselineAndCounts(t *testing.T) {
	zero := 0.0
	a, now := newTestAgg(AggOptions{BaselinePct: 100, SamplingFn: func(string, string) SamplePolicy { return SamplePolicy{BaselinePct: &zero} }})
	for i := 0; i < 20; i++ {
		mkTrace(a, fmt.Sprintf("ok%d", i), 5, 200, true)
	}
	mkTrace(a, "err", 5, 500, true)
	*now = now.Add(3 * time.Second)
	b := a.Flush("x", false)
	if len(b.Traces) != 1 || b.Traces[0].KeepReason != "error" {
		t.Fatalf("only the error is kept: %+v", b.Traces)
	}
	if s, k := sampCount(b, "baseline"); s != 20 || k != 0 {
		t.Fatalf("baseline seen/kept: %d/%d", s, k)
	}
	if s, k := sampCount(b, "error"); s != 1 || k != 1 {
		t.Fatalf("error seen/kept: %d/%d", s, k)
	}
}

func TestSamplingDefaultUnchanged(t *testing.T) {
	a, now := newTestAgg(AggOptions{BaselinePct: 100})
	mkTrace(a, "any", 5, 200, true)
	*now = now.Add(3 * time.Second)
	b := a.Flush("x", false)
	if len(b.Traces) != 1 {
		t.Fatal("default policy keeps baseline as before")
	}
	if s, k := sampCount(b, "baseline"); s != 1 || k != 1 {
		t.Fatalf("%d/%d", s, k)
	}
}

func TestSamplingErrorCapPerMinute(t *testing.T) {
	a, now := newTestAgg(AggOptions{BaselinePct: -1, SamplingFn: func(string, string) SamplePolicy { return SamplePolicy{ErrorMaxPerMin: 3} }})
	for i := 0; i < 10; i++ {
		mkTrace(a, fmt.Sprintf("e%d", i), 5, 500, true)
	}
	*now = now.Add(3 * time.Second)
	b := a.Flush("x", false)
	if s, k := sampCount(b, "error"); s != 10 || k != 3 || len(b.Traces) != 3 {
		t.Fatalf("seen %d kept %d traces %d", s, k, len(b.Traces))
	}
}

func TestSamplingFlushBudgetOrder(t *testing.T) {
	a, now := newTestAgg(AggOptions{BaselinePct: 100, SlowMs: 1000, SamplingFn: func(string, string) SamplePolicy { return SamplePolicy{MaxPerFlush: 3} }})
	mkTrace(a, "b1", 5, 200, true)
	mkTrace(a, "b2", 5, 200, true)
	mkTrace(a, "s1", 2000, 200, true)
	mkTrace(a, "e1", 5, 500, true) // evicts a baseline trace
	mkTrace(a, "sec", 5, 200, true)
	a.MarkSecurity("sec") // never dropped, even over the budget
	mkTrace(a, "b3", 5, 200, true)
	*now = now.Add(3 * time.Second)
	b := a.Flush("x", false)
	have := map[string]bool{}
	for _, tr := range b.Traces {
		have[tr.TraceID] = true
	}
	if !have["s1"] || !have["e1"] || !have["sec"] || have["b3"] {
		t.Fatalf("kept: %v", have)
	}
	if _, k := sampCount(b, "baseline"); int(k) > 1 {
		t.Fatalf("baseline kept %d", k)
	}
	total := int64(0)
	for _, s := range b.Sampling {
		total += s.Kept
	}
	if int(total) != len(b.Traces) {
		t.Fatalf("counters %d disagree with %d traces", total, len(b.Traces))
	}
}

func TestCleanSamplePolicy(t *testing.T) {
	hi, lo := 250.0, -5.0
	c := cleanSamplePolicy(&SamplePolicy{BaselinePct: &hi, ErrorMaxPerMin: -1, MaxPerFlush: 99999})
	if *c.BaselinePct != 100 || c.ErrorMaxPerMin != 0 || c.MaxPerFlush != 5000 {
		t.Fatalf("%+v", c)
	}
	if c := cleanSamplePolicy(&SamplePolicy{BaselinePct: &lo}); *c.BaselinePct != 0 {
		t.Fatal("negative becomes zero")
	}
}
