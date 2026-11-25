package otel

import (
	"strings"
	"testing"
	"time"
)

const nodeStack = `Error: order 123 not found for bob@example.com
    at getOrder (/app/src/orders.js:42:15)
    at Layer.handle [as handle_request] (/app/node_modules/express/lib/router/layer.js:95:5)
    at /app/src/routes.js:10:5
    at node:internal/process/task_queues:95:5`

func TestParseStackAllLanguages(t *testing.T) {
	n := parseStack(nodeStack)
	if len(n) != 4 || n[0].fn != "getOrder" || n[0].line != 42 || n[0].lib || !n[1].lib || n[2].fn != "" || n[2].lib || !n[3].lib {
		t.Fatalf("node: %+v", n)
	}
	py := parseStack("Traceback (most recent call last):\n  File \"/srv/app/views.py\", line 7, in get_order\n    x()\n  File \"/usr/lib/python3/site-packages/flask/app.py\", line 9, in dispatch")
	if len(py) != 2 || py[0].fn != "get_order" || py[0].file != "srv/app/views.py" || py[0].lib || !py[1].lib {
		t.Fatalf("python: %+v", py)
	}
	jv := parseStack("java.lang.IllegalStateException: x\n\tat com.acme.OrderService.find(OrderService.java:42)\n\tat java.base/java.util.ArrayList.get(ArrayList.java:427)")
	if len(jv) != 2 || jv[0].fn != "com.acme.OrderService.find" || jv[0].line != 42 || jv[0].lib || !jv[1].lib {
		t.Fatalf("java: %+v", jv)
	}
	nt := parseStack("   at Acme.Orders.Get(Int32 id) in /src/Orders.cs:line 42\n   at System.Threading.Tasks.Task.Run() in /x/Task.cs:line 9")
	if len(nt) != 2 || nt[0].fn != "Acme.Orders.Get" || nt[0].line != 42 || nt[0].lib || !nt[1].lib {
		t.Fatalf(".net: %+v", nt)
	}
}

func TestErrorFingerprintStable(t *testing.T) {
	a := parseStack("    at getOrder (/app/src/orders.js:42:15)\n    at Layer.handle (/app/node_modules/express/layer.js:1:1)")
	b := parseStack("    at getOrder (/other/place/app/src/orders.js:57:9)\n    at Layer.handle (/x/node_modules/express/layer.js:2:2)")
	if errorFingerprint("Error", a, "/orders/:id") != errorFingerprint("Error", b, "/orders/:id") {
		t.Fatal("the same failure after a deploy (line moved, other path prefix) must keep its group")
	}
	c := parseStack("    at otherFn (/app/src/orders.js:42:15)")
	if errorFingerprint("Error", a, "/orders/:id") == errorFingerprint("Error", c, "/orders/:id") {
		t.Fatal("a different function is a different group")
	}
	if errorFingerprint("Error", a, "/orders/:id") == errorFingerprint("Error", a, "/other") {
		t.Fatal("route is part of the group")
	}
}

func TestScrubMessage(t *testing.T) {
	m := scrubMessage(`order 123 not found for bob@example.com "secret" id 3f2b8c1e-aaaa-bbbb-cccc-0123456789ab token eyJhbGciOiJIUzI1NiJ9abcdef`)
	for _, bad := range []string{"123", "bob", "secret", "3f2b", "eyJ"} {
		if strings.Contains(m, bad) {
			t.Fatalf("%q kept in %q", bad, m)
		}
	}
	if !strings.Contains(m, "not found") {
		t.Fatalf("words must stay: %q", m)
	}
}

func TestNoteErrorGroupsAndModes(t *testing.T) {
	now := time.Now()
	run := func(mode string) *Batch {
		a := NewAggregator(AggOptions{ErrMsgFn: func(string, string) string { return mode }}, func() time.Time { return now })
		res := Resource{Service: "api", Environment: "prod", Version: "1.2.0"}
		for i, id := range []string{"123", "456"} { // same failure, different ids in the message
			s := Span{Res: res, TraceID: "t" + id, ExcType: "Error", ExcMsg: "order " + id + " not found", ExcStack: nodeStack}
			_ = i
			a.noteError(&s, "/orders/:id", "GET", now)
		}
		b := &Batch{}
		a.drainDiag(b)
		return b
	}
	b := run("off")
	if len(b.Errors) != 1 || b.Errors[0].Count != 2 || b.Errors[0].Message != "" || !strings.HasPrefix(b.Errors[0].Frame, "getOrder") {
		t.Fatalf("group: %+v", b.Errors)
	}
	if strings.Contains(strings.Join(b.Errors[0].Frames, "|"), "bob@") {
		t.Fatal("message text leaked through frames")
	}
	b = run("masked")
	if b.Errors[0].Message == "" || strings.ContainsAny(b.Errors[0].Message, "0123456789") {
		t.Fatalf("masked message: %q", b.Errors[0].Message)
	}
}

func TestErrorGroupCap(t *testing.T) {
	now := time.Now()
	a := NewAggregator(AggOptions{}, func() time.Time { return now })
	for i := 0; i < maxErrGroupsPerSvc+30; i++ {
		s := Span{Res: Resource{Service: "api"}, ExcType: "E" + itoa(i)}
		a.noteError(&s, "/x", "GET", now)
	}
	b := &Batch{}
	a.drainDiag(b)
	if len(b.Errors) != maxErrGroupsPerSvc || a.Stats.ErrorDrops != 30 {
		t.Fatalf("cap: %d groups, %d drops", len(b.Errors), a.Stats.ErrorDrops)
	}
}

func TestDecodeExceptionEventJSON(t *testing.T) {
	body := `{"resourceSpans":[{"resource":{"attributes":[{"key":"service.name","value":{"stringValue":"api"}}]},"scopeSpans":[{"spans":[
	 {"traceId":"0102030405060708090a0b0c0d0e0f10","spanId":"0102030405060708","name":"GET","kind":2,"startTimeUnixNano":"1","endTimeUnixNano":"2",
	  "events":[{"name":"exception","attributes":[{"key":"exception.type","value":{"stringValue":"TypeError"}},
	  {"key":"exception.message","value":{"stringValue":"x is undefined"}},{"key":"exception.stacktrace","value":{"stringValue":"TypeError\n    at f (/a/b.js:1:2)"}}]}]}]}]}]}`
	spans, err := DecodeTracesJSON([]byte(body))
	if err != nil || len(spans) != 1 {
		t.Fatalf("decode: %v %d", err, len(spans))
	}
	s := spans[0]
	if s.ExcType != "TypeError" || s.ExcMsg != "x is undefined" || !strings.Contains(s.ExcStack, "b.js") {
		t.Fatalf("exception fields: %+v", s)
	}
}

func TestParseGoStack(t *testing.T) {
	stack := "goroutine 7 [running]:\nruntime/debug.Stack()\n\t/usr/local/go/src/runtime/debug/stack.go:26 +0x5e\nobsidianwatch/management/internal/api.handleThing.func1({0x1, 0x2}, 0xc000123)\n\t/build/management/backend/internal/api/thing.go:42 +0x1d\nnet/http.HandlerFunc.ServeHTTP(0xc0, {0x1, 0x2}, 0x3)\n\t/usr/local/go/src/net/http/server.go:2220 +0x29\n"
	f := parseStack(stack)
	if len(f) != 3 {
		t.Fatalf("frames: %+v", f)
	}
	if f[1].fn != "obsidianwatch/management/internal/api.handleThing.func1" || f[1].line != 42 || f[1].lib || f[1].file != "internal/api/thing.go" {
		t.Fatalf("app frame: %+v", f[1])
	}
	if !f[0].lib || !f[2].lib {
		t.Fatalf("library frames: %+v", f)
	}
}
