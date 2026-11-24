package otel

import (
	"strings"
	"testing"
	"time"
)

func TestFingerprintSQL(t *testing.T) {
	a, ta := fingerprintSQL("SELECT * FROM users WHERE id = 5 AND name = 'bob''s' /* c */")
	b, tb := fingerprintSQL("select  *  from users where id = 9 and name = 'alice'")
	if a != b || ta != tb {
		t.Fatalf("not the same query: %q vs %q", ta, tb)
	}
	if strings.ContainsAny(ta, "59") || strings.Contains(ta, "bob") {
		t.Fatalf("literal kept: %s", ta)
	}
	_, in1 := fingerprintSQL("SELECT a FROM t WHERE id IN (1,2,3)")
	_, in2 := fingerprintSQL("SELECT a FROM t WHERE id IN (7,8)")
	if in1 != in2 || !strings.Contains(in1, "in (?)") {
		t.Fatalf("in list: %q %q", in1, in2)
	}
	_, ph := fingerprintSQL("SELECT a FROM t2 WHERE id = $1")
	if !strings.Contains(ph, "t2") || !strings.Contains(ph, "= ?") {
		t.Fatalf("placeholder/identifier: %q", ph)
	}
	if len(func() string { _, x := fingerprintSQL(strings.Repeat("a ", 1000)); return x }()) > 512 {
		t.Fatal("text not capped")
	}
}

func TestDiagnoseTrace(t *testing.T) {
	now := time.Date(2026, 1, 1, 12, 0, 30, 0, time.UTC)
	a := NewAggregator(AggOptions{DBStmtFn: func(string, string) string { return "fingerprint" }}, func() time.Time { return now })
	res := Resource{Service: "orders", Environment: "prod"}
	ms := uint64(1e6)
	base := uint64(now.UnixNano())
	sp := func(id, parent string, kind int, start, dur uint64, f func(*Span)) Span {
		s := Span{Res: res, TraceID: "t1", SpanID: id, ParentID: parent, Name: "n" + id, Kind: kind, StartNano: base + start*ms, EndNano: base + (start+dur)*ms}
		if f != nil {
			f(&s)
		}
		return s
	}
	tr := &openTrace{id: "t1"}
	tr.spans = append(tr.spans,
		sp("r", "", kindServer, 0, 100, func(s *Span) { s.Route, s.Method = "/orders/:id", "GET" }),
		sp("h", "r", kindInternal, 1, 90, nil),
		sp("p", "h", kindClient, 2, 30, func(s *Span) {
			s.DBSystem, s.Name = "postgresql", "SELECT orders"
			s.DBOp, s.DBTable = "SELECT", "orders"
		}),
		sp("x", "h", kindClient, 40, 40, func(s *Span) { s.PeerService, s.Name = "payments", "POST /charge/123456" }),
	)
	for i := 0; i < 12; i++ { // an N+1: the same statement under one parent
		id := string(rune('a'+i)) + "q"
		tr.spans = append(tr.spans, sp(id, "h", kindClient, uint64(80+i), 1, func(s *Span) {
			s.DBSystem, s.DBOp, s.DBTable, s.DBStmt = "postgresql", "SELECT", "items", "SELECT * FROM items WHERE order_id = "+string(rune('1'+i%9))
		}))
	}
	self, n1 := a.diagnoseTrace(tr, now)
	if self["r"] != 10 { // 100 minus its one child h (90)
		t.Fatalf("root self: %v", self["r"])
	}
	if self["h"] < 0 || self["h"] > 90 {
		t.Fatalf("h self: %v", self["h"])
	}
	if len(n1) != 12 {
		t.Fatalf("n+1 spans: %d", len(n1))
	}
	b := &Batch{}
	a.drainDiag(b)
	if len(b.NPlusOne) != 1 || b.NPlusOne[0].Route != "/orders/:id" {
		t.Fatalf("n+1 counter: %+v", b.NPlusOne)
	}
	kinds := map[string]bool{}
	for _, c := range b.Children {
		kinds[c.Kind+"|"+c.Target+"|"+c.Name] = true
		if strings.Contains(c.Name, "123456") {
			t.Fatalf("id kept in name: %s", c.Name)
		}
	}
	if !kinds["http|payments|POST /charge/?"] || !kinds["db|postgresql|SELECT orders"] {
		t.Fatalf("children: %v", kinds)
	}
	var items, pg *BatchQuery
	for i := range b.Queries {
		q := &b.Queries[i]
		if q.Table == "items" {
			items = q
		}
		if q.Table == "orders" {
			pg = q
		}
	}
	if items == nil || items.Calls != 12 || items.Fingerprint == "" || strings.ContainsAny(items.Text, "123456789") {
		t.Fatalf("items query: %+v", items)
	}
	if pg == nil || pg.Fingerprint != "" || pg.Text != "" {
		t.Fatalf("a call without a statement has no fingerprint: %+v", pg)
	}
	// Mode off: no fingerprint at all.
	a2 := NewAggregator(AggOptions{}, func() time.Time { return now })
	a2.diagnoseTrace(tr, now)
	b2 := &Batch{}
	a2.drainDiag(b2)
	for _, q := range b2.Queries {
		if q.Fingerprint != "" || q.Text != "" {
			t.Fatalf("mode off leaked a fingerprint: %+v", q)
		}
	}
}

func TestDiagnoseCaps(t *testing.T) {
	now := time.Now()
	a := NewAggregator(AggOptions{}, func() time.Time { return now })
	tr := &openTrace{id: "t"}
	res := Resource{Service: "s", Environment: "e"}
	tr.spans = append(tr.spans, Span{Res: res, TraceID: "t", SpanID: "r", Kind: kindServer, Route: "/x", Method: "GET", StartNano: 1, EndNano: 2e9})
	for i := 0; i < 60; i++ {
		tr.spans = append(tr.spans, Span{Res: res, TraceID: "t", SpanID: "c" + itoa(i), ParentID: "r", Kind: kindClient, PeerService: "p" + itoa(i), Name: "call", StartNano: 1, EndNano: 1e6})
	}
	a.diagnoseTrace(tr, now)
	b := &Batch{}
	a.drainDiag(b)
	if len(b.Children) > maxChildrenPerRoute+1 {
		t.Fatalf("children not capped: %d", len(b.Children))
	}
}
