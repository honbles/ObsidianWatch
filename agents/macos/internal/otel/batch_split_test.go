package otel

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestSplitCarriesEverySection(t *testing.T) {
	b := &Batch{AgentID: "a", SchemaVersion: 2,
		Routes: []BatchRoute{{}}, Children: []BatchChild{{}}, Queries: []BatchQuery{{}}, NPlusOne: []BatchNPlusOne{{}},
		Errors: []BatchError{{}}, Metrics: []BatchMetric{{}}, Sampling: []BatchSampling{{}}, Operations: []BatchOperation{{}},
		Notes: []BatchNote{{}}}
	parts := b.Split()
	if len(parts) != 1 {
		t.Fatalf("pieces = %d", len(parts))
	}
	p := parts[0]
	if p.items() != b.items() || len(p.Notes) != 1 || p.SchemaVersion != 2 {
		t.Fatalf("lost sections: %+v", p)
	}
}

func TestSplitRespectsCountAndBytes(t *testing.T) {
	b := &Batch{AgentID: "a", Errors: make([]BatchError, BatchMaxErrors+1)}
	if parts := b.Split(); len(parts) != 2 || len(parts[0].Errors) != BatchMaxErrors {
		t.Fatalf("count split wrong: %d", len(parts))
	}
	// 100 traces of 64 KiB each is 6.4 MiB: under the count cap of 50 per
	// piece twice, but still over the byte cap, so pieces must be halved.
	big := strings.Repeat("x", 64<<10)
	b = &Batch{AgentID: "a", Notes: []BatchNote{{}}}
	for i := 0; i < 100; i++ {
		b.Traces = append(b.Traces, BatchTrace{TraceID: big})
	}
	total := 0
	for _, p := range b.Split() {
		raw, _ := json.Marshal(p)
		if len(raw) > BatchMaxBytes {
			t.Fatalf("piece is %d bytes", len(raw))
		}
		total += p.items()
	}
	if total != 100 {
		t.Fatalf("items = %d", total)
	}
}
