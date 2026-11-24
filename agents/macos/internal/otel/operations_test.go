package otel

import (
	"fmt"
	"testing"
	"time"
)

func opSpan(kind int, parent, job, sys, dest string, errored bool, durMs float64) Span {
	end := uint64(testNow.Add(-time.Minute).UnixNano())
	s := Span{Res: Resource{Service: "worker", Environment: "prod"}, Kind: kind, TraceID: "t", SpanID: "s", ParentID: parent, Name: "process " + dest,
		StartNano: end - uint64(durMs*1e6), EndNano: end, JobName: job, Messaging: sys, MessagingDest: dest, MessagingOp: "process"}
	if errored {
		s.StatusCode = statusError
	}
	return s
}

func TestOperationsJobsAndConsumers(t *testing.T) {
	a, now := newTestAgg(AggOptions{BaselinePct: -1})
	a.Ingest(opSpan(kindInternal, "", "nightly-report", "", "", false, 200), verifiedPeer, IdentityVerified)
	a.Ingest(opSpan(kindInternal, "", "nightly-report", "", "", true, 300), verifiedPeer, IdentityVerified)
	a.Ingest(opSpan(kindConsumer, "p", "", "kafka", "orders-8842", false, 50), verifiedPeer, IdentityVerified)
	a.Ingest(opSpan(kindInternal, "p", "", "", "", false, 5), verifiedPeer, IdentityVerified) // an ordinary child span: not an operation
	a.Ingest(opSpan(kindServer, "", "", "", "", false, 5), verifiedPeer, IdentityVerified)    // an HTTP-ish server span: not an operation
	*now = now.Add(2 * time.Minute)
	b := a.Flush("x", false)
	got := map[string]BatchOperation{}
	for _, o := range b.Operations {
		got[o.Kind+"|"+o.Name] = o
	}
	j := got["job|nightly-report"]
	if len(b.Operations) != 2 || j.Runs != 2 || j.Failures != 1 || j.Sketch == nil || j.LastRun.IsZero() {
		t.Fatalf("%+v", b.Operations)
	}
	if c := got["consumer|kafka orders-? process"]; c.Runs != 1 {
		t.Fatalf("destination ids are templated: %+v", b.Operations)
	}
}

func TestOperationsCardinalityCap(t *testing.T) {
	a, now := newTestAgg(AggOptions{BaselinePct: -1})
	for i := 0; i < maxOpsPerService+30; i++ {
		a.Ingest(opSpan(kindInternal, "", fmt.Sprintf("job-%c%c", 'a'+i/26, 'a'+i%26), "", "", false, 1), verifiedPeer, IdentityVerified)
	}
	*now = now.Add(2 * time.Minute)
	b := a.Flush("x", false)
	other := int64(0)
	for _, o := range b.Operations {
		if o.Name == otherOp {
			other += o.Runs
		}
	}
	if len(b.Operations) != maxOpsPerService+1 || other != 30 {
		t.Fatalf("%d operations, %d in other", len(b.Operations), other)
	}
}
