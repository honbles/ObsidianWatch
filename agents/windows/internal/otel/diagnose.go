package otel

// diagnose.go - what a closed trace tells us beyond its own record (APM spec items 1 and 2).
//
//   - self time per span (duration minus the time of its children, never below zero),
//   - the slowest downstream calls per route (top_children),
//   - database calls by operation, table and, when the service allows it, a literal-free statement fingerprint,
//   - N+1 detection: the same statement run many times under one parent span.
//
// Privacy: a statement is read only to build the fingerprint. The raw statement is never stored, forwarded or logged.
// Without db_statement_mode "fingerprint" for the service, no statement text is forwarded at all. Only operation and
// table NAMES are forwarded otherwise. Every stream has an explicit cap.

import (
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"strings"
	"time"
)

const (
	maxChildrenPerRoute = 20   // distinct (kind, target, name) per route per flush; the rest collapse into "(other)"
	maxChildKeys        = 5000 // all routes, per flush
	maxQueryKeys        = 200  // distinct query keys per service per flush; the rest collapse into "(other)"
	maxFingerprintText  = 512  // bytes of normalised statement forwarded
	nPlusOneThreshold   = 10   // same statement under one parent this many times is an N+1
	maxAncestorDepth    = 64
	otherName           = "(other)"
)

type childKey struct {
	rt     routeKey
	minute time.Time
	kind   string
	target string
	name   string
}

type childVal struct {
	calls   int64
	totalMs float64
}

type queryKey struct {
	svc    svcKey
	minute time.Time
	system string
	op     string
	table  string
	fp     string
}

type queryVal struct {
	text   string
	calls  int64
	errors int64
	totMs  float64
	hist   [histLen]int64
}

type diagState struct {
	ch  map[childKey]*childVal
	chN map[routeKey]int
	q   map[queryKey]*queryVal
	qN  map[svcKey]int
	n1  map[routeKey]int64
	er  map[errKey]*errVal
	erN map[svcKey]int
}

// BatchChild is one slow-downstream aggregate: calls made from a route to one kind of target in a minute.
type BatchChild struct {
	Service     string    `json:"service"`
	Environment string    `json:"environment"`
	Route       string    `json:"route"`
	Method      string    `json:"method"`
	Minute      time.Time `json:"minute"`
	Kind        string    `json:"kind"` // db | http | queue | client
	Target      string    `json:"target"`
	Name        string    `json:"name"`
	Calls       int64     `json:"calls"`
	TotalMs     float64   `json:"total_ms"`
}

// BatchQuery is database calls grouped by (system, operation, table, fingerprint) in a minute.
type BatchQuery struct {
	Service     string    `json:"service"`
	Environment string    `json:"environment"`
	Minute      time.Time `json:"minute"`
	System      string    `json:"system"`
	Operation   string    `json:"operation"`
	Table       string    `json:"table"`
	Fingerprint string    `json:"fingerprint,omitempty"`
	Text        string    `json:"text,omitempty"` // normalised, literal-free; only in fingerprint mode
	Calls       int64     `json:"calls"`
	Errors      int64     `json:"errors"`
	TotalMs     float64   `json:"total_ms"`
	DurBuckets  []int64   `json:"duration_buckets"`
}

// BatchNPlusOne counts the N+1 patterns found under a route since the last flush.
type BatchNPlusOne struct {
	Service     string `json:"service"`
	Environment string `json:"environment"`
	Route       string `json:"route"`
	Method      string `json:"method"`
	Count       int64  `json:"count"`
}

var (
	reUUID    = regexp.MustCompile(`(?i)[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`)
	reHexLong = regexp.MustCompile(`(?i)\b[0-9a-f]{12,}\b`)
	reDigits  = regexp.MustCompile(`\d+`)
	reSQLCmt  = regexp.MustCompile(`(?s)/\*.*?\*/|--[^\n]*`)
	reSQLStr  = regexp.MustCompile(`'(?:[^']|'')*'`)
	reSQLHex  = regexp.MustCompile(`(?i)\b0x[0-9a-f]+\b`)
	reSQLNum  = regexp.MustCompile(`\b\d+(?:\.\d+)?(?:e[+-]?\d+)?\b`)
	reSQLPh   = regexp.MustCompile(`\$\d+|@\w+`)
	reSQLIn   = regexp.MustCompile(`(?i)\b(in|values)\s*\(\s*\?(?:\s*,\s*\?)*\s*\)`)
	reSpace   = regexp.MustCompile(`\s+`)
)

// templateName makes a span name safe as a grouping key: ids, hashes and numbers become "?".
func templateName(n string) string {
	n = reUUID.ReplaceAllString(n, "?")
	n = reHexLong.ReplaceAllString(n, "?")
	n = reDigits.ReplaceAllString(n, "?")
	n = reSpace.ReplaceAllString(strings.TrimSpace(n), " ")
	if len(n) > 80 {
		n = n[:80]
	}
	return n
}

// fingerprintSQL returns a literal-free form of a statement and a short stable id for it.
func fingerprintSQL(stmt string) (id, text string) {
	s := reSQLCmt.ReplaceAllString(stmt, " ")
	s = reSQLStr.ReplaceAllString(s, "?")
	s = reSQLHex.ReplaceAllString(s, "?")
	s = reSQLPh.ReplaceAllString(s, "?")
	s = reSQLNum.ReplaceAllString(s, "?")
	s = reSQLIn.ReplaceAllString(s, "$1 (?)")
	s = strings.ToLower(reSpace.ReplaceAllString(strings.TrimSpace(s), " "))
	s = strings.TrimRight(s, "; ")
	sum := sha256.Sum256([]byte(s))
	id = hex.EncodeToString(sum[:8])
	if len(s) > maxFingerprintText {
		s = s[:maxFingerprintText]
	}
	return id, s
}

func (a *Aggregator) diag() *diagState {
	if a.dg == nil {
		a.dg = &diagState{ch: map[childKey]*childVal{}, chN: map[routeKey]int{}, q: map[queryKey]*queryVal{},
			qN: map[svcKey]int{}, n1: map[routeKey]int64{}, er: map[errKey]*errVal{}, erN: map[svcKey]int{}}
	}
	return a.dg
}

func childKind(s *Span) string {
	switch {
	case s.DBSystem != "":
		return "db"
	case s.Kind == kindProducer:
		return "queue"
	case s.PeerService != "" || s.ServerAddr != "":
		return "http"
	}
	return "client"
}

// diagnoseTrace walks a closed trace. It returns self time per span id and the span ids that are part of an N+1.
func (a *Aggregator) diagnoseTrace(t *openTrace, now time.Time) (self map[string]float64, n1 map[string]bool) {
	d := a.diag()
	minute := now.UTC().Truncate(time.Minute)
	byID := make(map[string]*Span, len(t.spans))
	childSum := map[string]float64{}
	for i := range t.spans {
		byID[t.spans[i].SpanID] = &t.spans[i]
	}
	for i := range t.spans {
		s := &t.spans[i]
		if s.ParentID != "" {
			if _, ok := byID[s.ParentID]; ok {
				childSum[s.ParentID] += s.DurationMs()
			}
		}
	}
	self = make(map[string]float64, len(t.spans))
	for i := range t.spans {
		s := &t.spans[i]
		v := s.DurationMs() - childSum[s.SpanID]
		if v < 0 {
			v = 0
		}
		self[s.SpanID] = v
	}

	routeOf := func(s *Span) *Span { // nearest ancestor that is an HTTP server span with a route
		cur := s
		for i := 0; i < maxAncestorDepth && cur != nil; i++ {
			if cur.Kind == kindServer && cur.Route != "" {
				return cur
			}
			cur = byID[cur.ParentID]
		}
		return nil
	}

	type repKey struct{ parent, fp string }
	reps := map[repKey][]*Span{}
	for i := range t.spans {
		s := &t.spans[i]
		if s.ExcType != "" {
			er, em := "", ""
			if rs := routeOf(s); rs != nil {
				er, em = rs.Route, rs.Method
			}
			a.noteError(s, er, em, now)
		}
		if s.Kind != kindClient && s.Kind != kindProducer {
			continue
		}
		rs := routeOf(s)
		var rk routeKey
		if rs != nil {
			rk = routeKey{svcKey{rs.Res.Service, envOf(rs.Res.Environment)}, rs.Route, rs.Method}
			ck := childKey{rk, minute, childKind(s), "", templateName(s.Name)}
			switch {
			case s.DBSystem != "":
				ck.target = s.DBSystem
			case s.PeerService != "":
				ck.target = s.PeerService
			default:
				ck.target = s.ServerAddr
			}
			if _, ok := d.ch[ck]; !ok {
				if d.chN[rk] >= maxChildrenPerRoute || len(d.ch) >= maxChildKeys {
					ck.name, ck.target = otherName, ""
				} else {
					d.chN[rk]++
				}
			}
			v := d.ch[ck]
			if v == nil {
				v = &childVal{}
				d.ch[ck] = v
			}
			v.calls++
			v.totalMs += s.DurationMs()
		}
		if s.DBSystem == "" {
			continue
		}
		sv := svcKey{s.Res.Service, envOf(s.Res.Environment)}
		op := strings.ToUpper(s.DBOp)
		if op == "" {
			op = strings.ToUpper(firstWord(s.Name))
		}
		fp, text := "", ""
		if s.DBStmt != "" && a.opt.DBStmtFn != nil && a.opt.DBStmtFn(sv.name, sv.env) == "fingerprint" {
			fp, text = fingerprintSQL(s.DBStmt)
		}
		qk := queryKey{sv, minute, s.DBSystem, clipN(op, 32), clipN(s.DBTable, 64), fp}
		if _, ok := d.q[qk]; !ok && d.qN[sv] >= maxQueryKeys {
			qk = queryKey{sv, minute, s.DBSystem, otherName, "", ""}
			text = ""
		} else if !ok {
			d.qN[sv]++
		}
		qv := d.q[qk]
		if qv == nil {
			qv = &queryVal{text: text}
			d.q[qk] = qv
		}
		qv.calls++
		if s.IsError() {
			qv.errors++
		}
		qv.totMs += s.DurationMs()
		qv.hist[durBucket(s.DurationMs())]++

		group := fp
		if group == "" {
			group = qk.op + "|" + qk.table
		}
		if rs != nil && s.ParentID != "" {
			rkey := repKey{s.ParentID, group}
			reps[rkey] = append(reps[rkey], s)
		}
	}
	for _, list := range reps {
		if len(list) < nPlusOneThreshold {
			continue
		}
		if n1 == nil {
			n1 = map[string]bool{}
		}
		for _, s := range list {
			n1[s.SpanID] = true
		}
		if rs := routeOf(list[0]); rs != nil {
			d.n1[routeKey{svcKey{rs.Res.Service, envOf(rs.Res.Environment)}, rs.Route, rs.Method}]++
		}
	}
	return self, n1
}

func firstWord(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexAny(s, " \t\n."); i > 0 {
		return s[:i]
	}
	return s
}

func clipN(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// drainDiag moves the diagnostic aggregates into a batch.
func (a *Aggregator) drainDiag(b *Batch) {
	d := a.dg
	if d == nil {
		return
	}
	for k, v := range d.ch {
		b.Children = append(b.Children, BatchChild{Service: k.rt.svc.name, Environment: k.rt.svc.env, Route: k.rt.route, Method: k.rt.method,
			Minute: k.minute, Kind: k.kind, Target: k.target, Name: k.name, Calls: v.calls, TotalMs: v.totalMs})
	}
	for k, v := range d.q {
		h := make([]int64, histLen)
		copy(h, v.hist[:])
		b.Queries = append(b.Queries, BatchQuery{Service: k.svc.name, Environment: k.svc.env, Minute: k.minute, System: k.system,
			Operation: k.op, Table: k.table, Fingerprint: k.fp, Text: v.text, Calls: v.calls, Errors: v.errors, TotalMs: v.totMs, DurBuckets: h})
	}
	for k, n := range d.n1 {
		b.NPlusOne = append(b.NPlusOne, BatchNPlusOne{Service: k.svc.name, Environment: k.svc.env, Route: k.route, Method: k.method, Count: n})
	}
	for k, v := range d.er {
		b.Errors = append(b.Errors, BatchError{Service: k.svc.name, Environment: k.svc.env, Route: v.route, Method: v.method,
			Fingerprint: k.fp, Type: v.typ, Frame: v.frame, Frames: v.frames, Message: v.msg, Version: v.version, TraceID: v.trace,
			Count: v.count, Time: v.at.UTC()})
	}
	a.dg = nil
}
