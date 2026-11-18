package otel

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
)

var testNow = time.Date(2026, 11, 10, 12, 30, 20, 0, time.UTC)

func newTestAgg(opt AggOptions) (*Aggregator, *time.Time) {
	now := testNow
	return NewAggregator(opt, func() time.Time { return now }), &now
}

func srvSpan(route string, status int, durMs float64, end time.Time) Span {
	e := uint64(end.UnixNano())
	return Span{Res: Resource{Service: "api", Environment: "prod", Version: "1"}, Kind: kindServer, Method: "GET", Route: route,
		HTTPStatus: status, StartNano: e - uint64(durMs*1e6), EndNano: e, TraceID: "", SpanID: "s"}
}

var verifiedPeer = Peer{Resolved: true, PID: 100, PPID: 1, ProcStart: testNow.Add(-time.Hour), Exe: "/usr/bin/java"}

func TestAggREDStatusClassesAndHistogram(t *testing.T) {
	a, _ := newTestAgg(AggOptions{})
	end := testNow.Add(-time.Minute) // a closed minute
	for _, c := range []struct {
		code int
		ms   float64
	}{{200, 3}, {200, 40}, {401, 8}, {403, 8}, {429, 1}, {500, 700}, {404, 20}, {200, 20000}} {
		a.Ingest(srvSpan("/orders/{id}", c.code, c.ms, end), verifiedPeer, IdentityVerified)
	}
	b := a.Flush("agent-1", false)
	if b == nil || len(b.Routes) != 1 {
		t.Fatalf("batch: %+v", b)
	}
	r := b.Routes[0]
	if r.Calls != 8 || r.Status2xx != 3 || r.Status40103 != 2 || r.Status429 != 1 || r.Status5xx != 1 || r.Errors != 1 {
		t.Fatalf("counts: %+v", r)
	}
	if r.Route != "/orders/{id}" || r.Method != "GET" || !r.Minute.Equal(end.Truncate(time.Minute)) {
		t.Fatalf("keys: %+v", r)
	}
	if len(r.DurBuckets) != 12 || r.DurBuckets[0] != 2 || r.DurBuckets[11] != 1 { // 3ms,1ms ≤5 ; 20000ms is +Inf
		t.Fatalf("histogram: %v", r.DurBuckets)
	}
}

func TestAggHoldsOpenMinuteUntilFinal(t *testing.T) {
	a, _ := newTestAgg(AggOptions{})
	a.Ingest(srvSpan("/a", 200, 5, testNow), verifiedPeer, IdentityVerified) // current minute
	if b := a.Flush("x", false); b == nil || len(b.Routes) != 0 {
		t.Fatalf("open minute must be held back: %+v", b)
	}
	if b := a.Flush("x", true); b == nil || len(b.Routes) != 1 {
		t.Fatalf("final flush must release it: %+v", b)
	}
}

func TestAggUnmatchedRouteAndCardinalityCap(t *testing.T) {
	a, _ := newTestAgg(AggOptions{MaxRoutes: 3})
	end := testNow.Add(-time.Minute)
	a.Ingest(srvSpan("", 200, 1, end), verifiedPeer, IdentityVerified) // no http.route → never the raw path
	for i := 0; i < 10; i++ {
		a.Ingest(srvSpan(fmt.Sprintf("/r%d", i), 200, 1, end), verifiedPeer, IdentityVerified)
	}
	b := a.Flush("x", false)
	routes := map[string]int64{}
	for _, r := range b.Routes {
		routes[r.Route] += r.Calls
	}
	if routes["(unmatched)"] != 1 || routes["other"] == 0 || len(routes) > 4 {
		t.Fatalf("routes: %v", routes)
	}
	var overflow int64
	for _, n := range b.Notes {
		overflow += n.RouteOverflow
	}
	if overflow == 0 {
		t.Fatalf("overflow must be reported: %+v", b.Notes)
	}
}

func TestAggClockSkewUsesReceiveTime(t *testing.T) {
	a, _ := newTestAgg(AggOptions{})
	a.Ingest(srvSpan("/x", 200, 1, testNow.Add(-6*time.Hour)), verifiedPeer, IdentityVerified)
	if a.Stats.ClockSkew != 1 {
		t.Fatal("skew not counted")
	}
	b := a.Flush("x", true)
	if !b.Routes[0].Minute.Equal(testNow.Truncate(time.Minute)) {
		t.Fatalf("skewed span must be bucketed at receive time: %v", b.Routes[0].Minute)
	}
}

func TestAggEdges(t *testing.T) {
	a, _ := newTestAgg(AggOptions{})
	cl := func(mut func(*Span)) {
		s := Span{Res: Resource{Service: "api", Environment: "prod"}, Kind: kindClient, StartNano: 1, EndNano: 2}
		mut(&s)
		a.Ingest(s, verifiedPeer, IdentityVerified)
	}
	cl(func(s *Span) { s.DBSystem, s.ServerAddr, s.ServerPort = "postgresql", "DB1.internal", 5432 })
	cl(func(s *Span) {
		s.DBSystem, s.ServerAddr, s.ServerPort = "postgresql", "db1.internal", 5432
		s.StatusCode = statusError
	})
	cl(func(s *Span) { s.Messaging = "kafka" })
	cl(func(s *Span) { s.PeerService = "payments" })
	cl(func(s *Span) { s.ServerAddr = "api.stripe.com" })
	cl(func(s *Span) {}) // nothing to name: ignored
	b := a.Flush("x", false)
	got := map[string][2]int64{}
	for _, e := range b.Edges {
		got[e.DstKind+"/"+e.DstName] = [2]int64{e.Calls, e.Errors}
		if e.Source != "otel" {
			t.Fatalf("source: %+v", e)
		}
	}
	want := map[string][2]int64{"database/postgresql@db1.internal:5432": {2, 1}, "queue/kafka": {1, 0}, "service/payments": {1, 0}, "external/api.stripe.com": {1, 0}}
	if len(got) != len(want) {
		t.Fatalf("edges: %v", got)
	}
	for k, v := range want {
		if got[k] != v {
			t.Fatalf("edge %s: %v want %v (all: %v)", k, got[k], v, got)
		}
	}
	if b2 := a.Flush("x", false); b2 != nil && len(b2.Edges) != 0 {
		t.Fatal("edge deltas must be sent once")
	}
}

func TestAggInstancesIdentityAndHeartbeat(t *testing.T) {
	a, now := newTestAgg(AggOptions{})
	s := srvSpan("/x", 200, 1, testNow)
	a.Ingest(s, verifiedPeer, IdentityVerified)
	b := a.Flush("x", false)
	if b == nil || len(b.Instances) != 1 {
		t.Fatalf("%+v", b)
	}
	in := b.Instances[0]
	if in.PID != 100 || in.Identity != "verified" || !in.Instrumented || in.Source != "otel" || in.Version != "1" || in.Exe != "/usr/bin/java" {
		t.Fatalf("%+v", in)
	}
	// An asserted claim from the same process must not downgrade it.
	a.Ingest(s, verifiedPeer, IdentityAsserted)
	*now = now.Add(2 * time.Second)
	if b := a.Flush("x", false); b != nil && len(b.Instances) != 0 && b.Instances[0].Identity != "verified" {
		t.Fatalf("downgraded: %+v", b.Instances)
	}
	*now = now.Add(61 * time.Second) // heartbeat
	a.Ingest(s, verifiedPeer, IdentityVerified)
	if b := a.Flush("x", false); b == nil || len(b.Instances) != 1 {
		t.Fatalf("heartbeat missing: %+v", b)
	}
}

func mkTrace(a *Aggregator, id string, durMs float64, errCode int, withRoot bool) {
	start := uint64(testNow.UnixNano())
	parent := "p"
	if withRoot {
		parent = ""
	}
	a.Ingest(Span{Res: Resource{Service: "api", Environment: "prod"}, TraceID: id, SpanID: "a" + id, ParentID: parent, Kind: kindServer,
		Method: "GET", Route: "/t", HTTPStatus: errCode, StartNano: start, EndNano: start + uint64(durMs*1e6)}, verifiedPeer, IdentityVerified)
}

func TestTraceSamplingDecisions(t *testing.T) {
	a, now := newTestAgg(AggOptions{SlowMs: 1000, BaselinePct: -1}) // -1 → baseline sampling off
	mkTrace(a, "err", 10, 500, true)
	mkTrace(a, "slow", 1500, 200, true)
	mkTrace(a, "sec", 10, 200, true)
	mkTrace(a, "boring", 10, 200, true)
	a.MarkSecurity("sec")
	*now = now.Add(3 * time.Second)
	b := a.Flush("x", false)
	got := map[string]string{}
	for _, tr := range b.Traces {
		got[tr.TraceID] = tr.KeepReason
	}
	if got["err"] != "error" || got["slow"] != "slow" || got["sec"] != "security" || len(got) != 3 {
		t.Fatalf("kept: %v", got)
	}
	for _, tr := range b.Traces {
		if tr.TraceID == "err" && (tr.Status != "error" || tr.RootRoute != "GET /t" || tr.SpanCount != 1) {
			t.Fatalf("%+v", tr)
		}
	}
}

func TestTraceBaselineSampling(t *testing.T) {
	a, now := newTestAgg(AggOptions{BaselinePct: 100})
	mkTrace(a, "any", 5, 200, true)
	*now = now.Add(3 * time.Second)
	if b := a.Flush("x", false); b == nil || len(b.Traces) != 1 || b.Traces[0].KeepReason != "baseline" {
		t.Fatalf("%+v", b)
	}
}

func TestTraceIncompleteWaitsForIdle(t *testing.T) {
	a, now := newTestAgg(AggOptions{BaselinePct: 100, TraceIdle: 10 * time.Second})
	mkTrace(a, "noroot", 5, 200, false) // a child span only
	*now = now.Add(5 * time.Second)
	if b := a.Flush("x", false); b != nil && len(b.Traces) != 0 {
		t.Fatal("must wait until idle")
	}
	*now = now.Add(6 * time.Second)
	if b := a.Flush("x", false); b == nil || len(b.Traces) != 1 {
		t.Fatalf("idle trace should complete: %+v", b)
	}
}

func TestTraceSpansCappedAt64KB(t *testing.T) {
	a, now := newTestAgg(AggOptions{BaselinePct: 100, MaxSpans: 5000})
	start := uint64(testNow.UnixNano())
	for i := 0; i < 3000; i++ {
		a.Ingest(Span{Res: Resource{Service: "api"}, TraceID: "big", SpanID: fmt.Sprintf("%016d", i), ParentID: "p",
			Name: strings.Repeat("n", 200), Kind: kindInternal, StartNano: start + uint64(i), EndNano: start + uint64(i) + 5}, verifiedPeer, IdentityVerified)
	}
	*now = now.Add(11 * time.Second)
	b := a.Flush("x", false)
	if b == nil || len(b.Traces) != 1 || len(b.Traces[0].Spans) > maxTraceJSON || !json.Valid(b.Traces[0].Spans) {
		t.Fatalf("trace not capped: %v", b)
	}
}

func TestTraceBufferBoundedDropsOldestAndCounts(t *testing.T) {
	a, now := newTestAgg(AggOptions{MaxOpenTraces: 3, BaselinePct: 100})
	for i := 0; i < 6; i++ {
		mkTrace(a, fmt.Sprintf("t%d", i), 5, 200, false)
	}
	if len(a.traces) != 3 || a.Stats.TracesDropped != 3 {
		t.Fatalf("open=%d dropped=%d", len(a.traces), a.Stats.TracesDropped)
	}
	*now = now.Add(11 * time.Second)
	b := a.Flush("x", false)
	var drops int64
	for _, n := range b.Notes {
		drops += n.TraceDrops
	}
	if drops != 3 {
		t.Fatalf("drop note: %+v", b.Notes)
	}
}

func TestRequeueMergesExactly(t *testing.T) {
	a, _ := newTestAgg(AggOptions{})
	end := testNow.Add(-time.Minute)
	a.Ingest(srvSpan("/x", 500, 7, end), verifiedPeer, IdentityVerified)
	b := a.Flush("x", false)
	a.Ingest(srvSpan("/x", 200, 7, end), verifiedPeer, IdentityVerified) // new data for the same minute
	a.Requeue(b)
	b2 := a.Flush("x", false)
	if len(b2.Routes) != 1 || b2.Routes[0].Calls != 2 || b2.Routes[0].Status5xx != 1 || b2.Routes[0].Status2xx != 1 || b2.Routes[0].DurBuckets[1] != 2 {
		t.Fatalf("%+v", b2.Routes)
	}
}

func TestBatchSplitRespectsBackendCaps(t *testing.T) {
	b := &Batch{AgentID: "a", Notes: []BatchNote{{Service: "s"}}}
	for i := 0; i < BatchMaxRoutes*2+5; i++ {
		b.Routes = append(b.Routes, BatchRoute{Service: "s"})
	}
	for i := 0; i < BatchMaxTraces+1; i++ {
		b.Traces = append(b.Traces, BatchTrace{TraceID: fmt.Sprint(i)})
	}
	parts := b.Split()
	rt, tr, nt := 0, 0, 0
	for _, p := range parts {
		if len(p.Routes) > BatchMaxRoutes || len(p.Traces) > BatchMaxTraces {
			t.Fatalf("part over cap: %d %d", len(p.Routes), len(p.Traces))
		}
		rt, tr, nt = rt+len(p.Routes), tr+len(p.Traces), nt+len(p.Notes)
	}
	if rt != len(b.Routes) || tr != len(b.Traces) || nt != 1 {
		t.Fatalf("lost items: %d %d %d", rt, tr, nt)
	}
}

func TestDiscoveredInstancesAndMerge(t *testing.T) {
	a, now := newTestAgg(AggOptions{})
	disc := BatchInstance{Service: "checkout", Environment: "prod", Source: "discovered", PID: 100, ProcStart: testNow.Add(-time.Hour),
		Identity: IdentityVerified, Listen: []byte(`[8080]`), Exe: "/usr/bin/java", Sensor: "procevent"}
	a.AddDiscovered([]BatchInstance{disc, {Service: ""}})
	b := a.Flush("x", false)
	if b == nil || len(b.Instances) != 1 {
		t.Fatalf("%+v", b)
	}
	in := b.Instances[0]
	if in.Source != "discovered" || in.Instrumented || in.Sensor != "procevent" || string(in.Listen) != "[8080]" || in.PID != 100 || in.Identity != "verified" {
		t.Fatalf("%+v", in)
	}
	if len(a.PIDs()) != 0 {
		t.Fatal("a discovered instance is not an instrumented pid")
	}
	// the same process then sends OpenTelemetry under ITS OWN service name ("api" != "checkout"): the merge keys on the process
	*now = now.Add(2 * time.Second)
	peer := Peer{Resolved: true, PID: 100, ProcStart: disc.ProcStart, Exe: "/usr/bin/java"}
	a.Ingest(srvSpan("/x", 200, 5, testNow.Add(-time.Minute)), peer, IdentityVerified)
	a.AddDiscovered([]BatchInstance{disc}) // the sensor keeps reporting it
	*now = now.Add(2 * time.Second)
	b = a.Flush("x", true)
	if len(b.Instances) != 1 || b.Instances[0].Source != "otel" || !b.Instances[0].Instrumented || b.Instances[0].Service != "api" {
		t.Fatalf("one instance, reported as instrumented: %+v", b.Instances)
	}
	if got := a.PIDs(); len(got) != 1 || got[0] != 100 {
		t.Fatalf("instrumented pids feed the sensor's watch set: %v", got)
	}
}
