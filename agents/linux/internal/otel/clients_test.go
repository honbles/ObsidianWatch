package otel

import (
	"fmt"
	"testing"
	"time"
)

func failSpan(route string, status int, client, peer, exc string, end time.Time) Span {
	s := srvSpan(route, status, 5, end)
	s.ClientAddr, s.PeerAddr, s.ExcType = client, peer, exc
	return s
}

func TestClientFailureCounters(t *testing.T) {
	a, _ := newTestAgg(AggOptions{})
	end := testNow.Add(-time.Minute)
	for _, c := range []struct {
		code int
		exc  string
	}{{401, ""}, {403, ""}, {429, ""}, {404, ""}, {500, ""}, {200, ""}, {200, "java.sql.SQLSyntaxErrorException"}} {
		a.Ingest(failSpan("/login", c.code, "203.0.113.9", "10.0.0.2", c.exc, end), verifiedPeer, IdentityVerified)
	}
	b := a.Flush("x", false)
	got := map[string]BatchClient{}
	for _, c := range b.Clients {
		got[c.ExcType] = c
	}
	plain, exc := got[""], got["java.sql.SQLSyntaxErrorException"]
	if plain.Failures != 5 || plain.Status40103 != 2 || plain.Status429 != 1 || plain.Status4xxOther != 1 || plain.Status5xx != 1 {
		t.Fatalf("plain: %+v", plain) // the 200 without an exception is NOT a failure
	}
	if exc.Failures != 1 || exc.Status40103+exc.Status429+exc.Status4xxOther+exc.Status5xx != 0 {
		t.Fatalf("exception-only failure: %+v", exc)
	}
	if plain.ClientIP != "203.0.113.9" || plain.PeerIP != "10.0.0.2" || plain.Route != "/login" || plain.Method != "GET" || !plain.Minute.Equal(end.Truncate(time.Minute)) {
		t.Fatalf("keys: %+v", plain)
	}
}

func TestClientFailuresNeedAnAddress(t *testing.T) {
	a, _ := newTestAgg(AggOptions{})
	a.Ingest(failSpan("/x", 500, "", "", "", testNow.Add(-time.Minute)), verifiedPeer, IdentityVerified)
	if b := a.Flush("x", false); b == nil || len(b.Clients) != 0 {
		t.Fatalf("no address, no client row: %+v", b)
	}
}

func TestClientAddressPrivacyModes(t *testing.T) {
	for mode, want := range map[string][2]string{
		ClientIPFull: {"203.0.113.9", "10.0.0.2"}, ClientIPTruncated: {"203.0.113.0/24", "10.0.0.0/24"}, ClientIPOff: {"", ""},
	} {
		a, _ := newTestAgg(AggOptions{IPMode: func(string, string) string { return mode }})
		a.Ingest(failSpan("/x", 401, "203.0.113.9", "10.0.0.2", "", testNow.Add(-time.Minute)), verifiedPeer, IdentityVerified)
		b := a.Flush("x", false)
		if mode == ClientIPOff {
			if b != nil && len(b.Clients) != 0 {
				t.Fatalf("off: nothing may be stored: %+v", b.Clients)
			}
			continue
		}
		if len(b.Clients) != 1 || b.Clients[0].ClientIP != want[0] || b.Clients[0].PeerIP != want[1] {
			t.Fatalf("%s: %+v", mode, b.Clients)
		}
	}
}

func TestClientKeyCapCountsOverflow(t *testing.T) {
	a, _ := newTestAgg(AggOptions{MaxClientKeys: 5})
	end := testNow.Add(-time.Minute)
	for i := 0; i < 20; i++ {
		a.Ingest(failSpan("/login", 401, fmt.Sprintf("203.0.113.%d", i), "", "", end), verifiedPeer, IdentityVerified)
	}
	b := a.Flush("x", false)
	var overflow int64
	for _, n := range b.Notes {
		overflow += n.ClientOverflow
	}
	if len(b.Clients) != 5 || overflow != 15 {
		t.Fatalf("clients=%d overflow=%d", len(b.Clients), overflow)
	}
	// After a flush the cap frees up again for the next minute.
	a.Ingest(failSpan("/login", 401, "198.51.100.1", "", "", end), verifiedPeer, IdentityVerified)
	if b := a.Flush("x", false); len(b.Clients) != 1 {
		t.Fatalf("cap must reset after flush: %+v", b)
	}
}

func TestClientStatsHeldUntilMinuteCloses(t *testing.T) {
	a, _ := newTestAgg(AggOptions{})
	a.Ingest(failSpan("/x", 401, "203.0.113.9", "", "", testNow), verifiedPeer, IdentityVerified) // current minute
	if b := a.Flush("x", false); b != nil && len(b.Clients) != 0 {
		t.Fatal("open minute must wait")
	}
	if b := a.Flush("x", true); b == nil || len(b.Clients) != 1 {
		t.Fatalf("final flush releases it: %+v", b)
	}
}

func TestClientStatsRequeueMerges(t *testing.T) {
	a, _ := newTestAgg(AggOptions{})
	end := testNow.Add(-time.Minute)
	a.Ingest(failSpan("/login", 401, "203.0.113.9", "", "", end), verifiedPeer, IdentityVerified)
	b := a.Flush("x", false)
	a.Ingest(failSpan("/login", 429, "203.0.113.9", "", "", end), verifiedPeer, IdentityVerified)
	a.Requeue(b)
	b2 := a.Flush("x", false)
	if len(b2.Clients) != 1 || b2.Clients[0].Failures != 2 || b2.Clients[0].Status40103 != 1 || b2.Clients[0].Status429 != 1 {
		t.Fatalf("%+v", b2.Clients)
	}
}

func TestBatchSplitCapsClients(t *testing.T) {
	b := &Batch{AgentID: "a"}
	for i := 0; i < BatchMaxClients*2+1; i++ {
		b.Clients = append(b.Clients, BatchClient{Service: "s"})
	}
	total := 0
	for _, p := range b.Split() {
		if len(p.Clients) > BatchMaxClients {
			t.Fatalf("part over cap: %d", len(p.Clients))
		}
		total += len(p.Clients)
	}
	if total != len(b.Clients) {
		t.Fatalf("lost rows: %d", total)
	}
}

func TestSlowFnOverridesThreshold(t *testing.T) {
	a, now := newTestAgg(AggOptions{SlowMs: 5000, BaselinePct: -1, SlowFn: func(s, e string) int {
		if s == "api" {
			return 100
		}
		return 0
	}})
	mkTrace(a, "t1", 150, 200, true) // 150 ms: slow only because the per-service target is 100 ms
	*now = now.Add(3 * time.Second)
	if b := a.Flush("x", false); b == nil || len(b.Traces) != 1 || b.Traces[0].KeepReason != "slow" {
		t.Fatalf("%+v", b)
	}
}
