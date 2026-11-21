package otel

import (
	"encoding/json"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestInjectionClass(t *testing.T) {
	hit := map[string]string{
		"1' OR '1'='1":                        "sql-injection",
		"1 UNION SELECT user,pass FROM users": "sql-injection",
		"x'; DROP TABLE users":                "sql-injection",
		"<script>alert(1)</script>":           "script-injection",
		"\"><img src=x onerror=alert(1)>":     "script-injection",
		"a; cat /etc/passwd":                  "command-injection",
		"$(whoami)":                           "command-injection",
		"../../../../etc/passwd":              "path-traversal",
		"${jndi:ldap://x/a}":                  "jndi-injection",
		url.QueryEscape("1' or 1=1 --"):       "sql-injection", // double-encoded after the receiver's decode
	}
	for v, want := range hit {
		if got := InjectionClass(v); got != want {
			t.Errorf("%q: got %q want %q", v, got, want)
		}
	}
	for _, v := range []string{"", "alice", "select a shirt", "O'Brien", "page=2", "union station", "5 and 6", "a-b--c",
		"https://example.com/a/b", "2026-11-21", "R&D", "it's 1=1 true", "drop it", "../readme"} {
		if got := InjectionClass(v); got != "" {
			t.Errorf("false positive %q: %q", v, got)
		}
	}
}

func TestInjectionFeedsClientRecordWithoutValue(t *testing.T) {
	a := NewAggregator(AggOptions{MaxClientKeys: 100}, time.Now)
	names, vals := queryParams("q=1%27%20OR%20%271%27%3D%271&page=2")
	s := Span{Kind: kindServer, HTTPStatus: 200, Route: "/search", Method: "GET", ClientAddr: "203.0.113.9",
		Res: Resource{Service: "shop"}, ParamNames: names, ParamValues: vals, TraceID: "t1"}
	a.Ingest(s, Peer{}, "")
	b := a.Flush("ag", true)
	if len(b.Clients) != 1 || b.Clients[0].ExcType != "param.sql-injection" || b.Clients[0].Failures != 1 {
		t.Fatalf("clients: %+v", b.Clients)
	}
	raw, _ := json.Marshal(b)
	if strings.Contains(string(raw), "OR '1'") || strings.Contains(string(raw), "1%27") {
		t.Fatalf("value leaked into the batch: %s", raw)
	}
}
