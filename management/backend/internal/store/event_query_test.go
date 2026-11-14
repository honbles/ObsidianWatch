package store

import (
	"strings"
	"testing"
)

func compileQ(t *testing.T, q string) (string, []interface{}) {
	t.Helper()
	e, err := ParseEventQuery(q)
	if err != nil {
		t.Fatalf("parse %q: %v", q, err)
	}
	s, a, err := e.SQL(1)
	if err != nil {
		t.Fatalf("sql %q: %v", q, err)
	}
	return s, a
}

func TestQueryPrecedenceAndGrouping(t *testing.T) {
	s, a := compileQ(t, `severity>=high and (host:web* or host:db*) and not user:SYSTEM`)
	if !strings.HasPrefix(s, "(severity >= $1 AND (") || !strings.Contains(s, "NOT (") {
		t.Fatalf("shape: %s", s)
	}
	if len(a) != 4 || a[0] != 4 || a[1] != "web%" || a[2] != "db%" {
		t.Fatalf("args: %#v", a)
	}
	// and binds tighter than or
	s, _ = compileQ(t, `host:a or host:b host:c`)
	if !strings.HasPrefix(s, "(") || strings.Count(s, " OR ") != 1 || !strings.Contains(s, " AND ") {
		t.Fatalf("or/and: %s", s)
	}
}

func TestQueryBackwardCompat(t *testing.T) {
	// the old search syntax still parses: terms, phrases, -exclusion, field:value, sev:4
	for _, q := range []string{`powershell "encoded command" -chrome host:web1 sev:4`, `10.0.0.1:443`, `C:\Windows\System32\cmd.exe`, `foo:bar`} {
		if _, a := compileQ(t, q); len(a) == 0 {
			t.Errorf("%q compiled without args", q)
		}
	}
	_, a := compileQ(t, `sev:4`)
	if a[0] != 4 {
		t.Errorf("sev:4 -> %v", a)
	}
	// an unknown prefix is a plain term over many columns, not an error
	s, _ := compileQ(t, `foo:bar`)
	if !strings.Contains(s, "raw::text ILIKE") {
		t.Errorf("unknown prefix should be a term: %s", s)
	}
}

func TestQueryFieldsAndOperators(t *testing.T) {
	s, a := compileQ(t, `port!=443`)
	if !strings.HasPrefix(s, "NOT ") || a[0] != int64(443) {
		t.Errorf("port!=: %s %v", s, a)
	}
	s, _ = compileQ(t, `dst:203.0.113.7`)
	if !strings.Contains(s, "dst_ip::text,'') = $1") {
		t.Errorf("exact ip: %s", s)
	}
	s, _ = compileQ(t, `ip:10.0.`)
	if !strings.Contains(s, "ILIKE") {
		t.Errorf("partial ip: %s", s)
	}
	s, a = compileQ(t, `type:(process or network) severity=critical`)
	if len(a) != 3 || a[2] != 5 {
		t.Errorf("type group: %s %v", s, a)
	}
	if _, a = compileQ(t, `type:cloud`); a[0] != "cloud.%" {
		t.Errorf("type:cloud -> %v", a)
	}
	s, a = compileQ(t, `time>=2026-11-14T10:30`)
	if !strings.HasPrefix(s, "time >= $1") || len(a) != 1 {
		t.Errorf("time: %s", s)
	}
	_, a = compileQ(t, `cmd:"-enc ZQBj"`)
	if a[0] != "%-enc ZQBj%" {
		t.Errorf("quoted value: %v", a)
	}
}

func TestQueryEscapesLikeAndNeverInlines(t *testing.T) {
	s, a := compileQ(t, `cmd:100%_x'; DROP TABLE events;--`)
	if strings.Contains(s, "DROP") || strings.Contains(s, "100%") {
		t.Fatalf("user text leaked into SQL: %s", s)
	}
	if a[0] != `%100\%\_x';%` { // later words are separate terms, all parameterised
		t.Errorf("not escaped: %v", a)
	}
}

func TestQueryErrors(t *testing.T) {
	bad := []string{`(host:a`, `host:a)`, `host:a or`, `not`, `()`, `severity:bogus`, `pid:abc`, `time>=yesterday`, `host>5`, `cmd:"unterminated`, `host:(`}
	for _, q := range bad {
		e, err := ParseEventQuery(q)
		if err == nil {
			_, _, err = e.SQL(1)
		}
		if err == nil {
			t.Errorf("%q should fail", q)
			continue
		}
		if _, ok := err.(*QueryError); !ok {
			t.Errorf("%q: not a QueryError: %T", q, err)
		}
	}
	long := strings.Repeat("a ", 2000)
	if _, err := ParseEventQuery(long); err == nil {
		t.Errorf("too long query accepted")
	}
	deep := strings.Repeat("(", 40) + "a" + strings.Repeat(")", 40)
	if _, err := ParseEventQuery(deep); err == nil {
		t.Errorf("deep nesting accepted")
	}
	if e, err := ParseEventQuery("   "); e != nil || err != nil {
		t.Errorf("empty query should be nil,nil")
	}
}

func TestLooksLikeQuery(t *testing.T) {
	yes := []string{`severity>=high`, `a or b`, `(a b)`, `host:web1`, `not x`, `proc:cmd.exe`}
	no := []string{`blessing`, `10.0.0.1:443`, `chrome.exe`, `C:\Users\x`, `foo:bar`}
	for _, q := range yes {
		if !LooksLikeQuery(q) {
			t.Errorf("%q should look like a query", q)
		}
	}
	for _, q := range no {
		if LooksLikeQuery(q) {
			t.Errorf("%q should not", q)
		}
	}
}
