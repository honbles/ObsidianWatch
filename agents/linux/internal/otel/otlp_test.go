package otel

import (
	"encoding/json"
	"testing"
)

func TestDecodeTracesPBAllowlist(t *testing.T) {
	res := stdRes("checkout", "prod",
		pbStrAttr("host.name", "attacker-claimed"), pbStrAttr("container.id", "deadbeef"), pbStrAttr("k8s.pod.name", "x"))
	sp := fixSpan{trace: "0123456789abcdef", span: "01234567", name: "GET /orders/{id}", kind: kindServer,
		start: 1_000_000_000, end: 1_050_000_000, status: statusError, excType: "java.sql.SQLSyntaxErrorException",
		attrs: []func(*pbw){pbStrAttr("http.route", "/orders/{id}"), pbStrAttr("http.request.method", "get"),
			pbIntAttr("http.response.status_code", 500), pbStrAttr("client.address", "203.0.113.9"),
			pbStrAttr("url.full", "https://x/orders/7?token=SECRET"), pbStrAttr("http.request.header.authorization", "Bearer abc"),
			pbDblAttr("some.float", 1.5), pbIntAttr("server.port", 5432)}}
	spans, err := DecodeTracesPB(traceReq(res, sp))
	if err != nil || len(spans) != 1 {
		t.Fatalf("decode: %v %d", err, len(spans))
	}
	s := spans[0]
	if s.Res.Service != "checkout" || s.Res.Environment != "prod" || s.Res.InstanceRef != "inst-1" || s.Res.Version != "1.4.0" || s.Res.Language != "java" {
		t.Fatalf("resource: %+v", s.Res)
	}
	if s.Route != "/orders/{id}" || s.Method != "GET" || s.HTTPStatus != 500 || s.ClientAddr != "203.0.113.9" || s.ServerPort != 5432 {
		t.Fatalf("span attrs: %+v", s)
	}
	if s.ExcType != "java.sql.SQLSyntaxErrorException" || s.StatusCode != statusError || !s.IsError() {
		t.Fatalf("exception/status: %+v", s)
	}
	if s.DurationMs() != 50 {
		t.Fatalf("duration %v", s.DurationMs())
	}
	// Anything outside the allowlist, notably the URL with a token and the auth header, must be gone.
	b, _ := json.Marshal(s)
	for _, bad := range []string{"SECRET", "Bearer", "attacker-claimed", "deadbeef"} {
		if contains(string(b), bad) {
			t.Fatalf("leaked %q in %s", bad, b)
		}
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

func TestDecodeTracesPBMalformed(t *testing.T) {
	good := traceReq(stdRes("a", "b"), fixSpan{trace: "t", span: "s", kind: kindServer, start: 1, end: 2})
	for i := 1; i < len(good); i += 3 { // truncations must error or decode, never panic
		_, _ = DecodeTracesPB(good[:i])
	}
	if _, err := DecodeTracesPB([]byte{0x0a, 0xff, 0xff, 0xff, 0xff, 0x0f}); err == nil {
		t.Fatal("oversized length must fail")
	}
	if _, err := DecodeTracesPB([]byte{0x00}); err == nil {
		t.Fatal("field number 0 must fail")
	}
}

func TestDecodeTracesJSON(t *testing.T) {
	body := `{"resourceSpans":[{"resource":{"attributes":[
	  {"key":"service.name","value":{"stringValue":"api"}},
	  {"key":"deployment.environment.name","value":{"stringValue":"staging"}},
	  {"key":"host.name","value":{"stringValue":"fake"}}]},
	 "scopeSpans":[{"spans":[{"traceId":"ABCDEF","spanId":"12","name":"GET /x","kind":2,
	   "startTimeUnixNano":"1000000000","endTimeUnixNano":"1020000000",
	   "attributes":[{"key":"http.route","value":{"stringValue":"/x"}},
	                 {"key":"http.status_code","value":{"intValue":"429"}},
	                 {"key":"http.target","value":{"stringValue":"/x?secret=1"}}],
	   "events":[{"name":"exception","attributes":[{"key":"exception.type","value":{"stringValue":"RateLimit"}}]}],
	   "status":{"code":0}}]}]}]}`
	spans, err := DecodeTracesJSON([]byte(body))
	if err != nil || len(spans) != 1 {
		t.Fatalf("%v %d", err, len(spans))
	}
	s := spans[0]
	if s.Res.Environment != "staging" || s.TraceID != "abcdef" || s.HTTPStatus != 429 || s.ExcType != "RateLimit" || s.DurationMs() != 20 {
		t.Fatalf("%+v", s)
	}
}

func TestDecodeLogsHelperEvents(t *testing.T) {
	pb := logReq(stdRes("shop", "prod"), "auth.login", "trace01",
		pbStrAttr("outcome", "failure"), pbStrAttr("user", "alice@example.com"), pbStrAttr("client.address", "198.51.100.7"),
		pbStrAttr("request.body", "password=hunter2"), pbStrAttr("route", "/login?x=1"))
	logs, err := DecodeLogsPB(pb)
	if err != nil || len(logs) != 1 {
		t.Fatalf("%v %d", err, len(logs))
	}
	l := logs[0]
	if l.EventName != "auth.login" || l.Attrs["outcome"] != "failure" || l.Attrs["user"] != "alice@example.com" {
		t.Fatalf("%+v", l)
	}
	if _, ok := l.Attrs["request.body"]; ok {
		t.Fatal("bodies must never be kept")
	}
	js := `{"resourceLogs":[{"resource":{"attributes":[{"key":"service.name","value":{"stringValue":"shop"}}]},
	  "scopeLogs":[{"logRecords":[{"timeUnixNano":"1700000000000000000","eventName":"ssrf.blocked",
	  "attributes":[{"key":"target_host","value":{"stringValue":"169.254.169.254"}},{"key":"cookie","value":{"stringValue":"s=1"}}]}]}]}]}`
	jl, err := DecodeLogsJSON([]byte(js))
	if err != nil || len(jl) != 1 || jl[0].EventName != "ssrf.blocked" || jl[0].Attrs["target_host"] != "169.254.169.254" || jl[0].Attrs["cookie"] != "" {
		t.Fatalf("%v %+v", err, jl)
	}
}
