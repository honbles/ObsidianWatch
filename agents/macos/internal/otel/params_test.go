package otel

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestQueryParamNames(t *testing.T) {
	for in, want := range map[string]string{
		"q=apple&sort=asc":             "q,sort",
		"q=a&q=b":                      "q",
		"user%5Bname%5D=x&page=1#frag": "user[name],page",
		"flag&q=1":                     "flag,q",
		"":                             "",
		"=novalue&&a=1":                "a",
		"bad name=1&ok=2":              "ok",
		"3f9a8c1b2d4e5f60718293a4b5c6d7e8f9a0b1c2": "", // a bare token is not a parameter name
		"a%ZZ=1&b=2": "b",
	} {
		if got := strings.Join(QueryParamNames(in), ","); got != want {
			t.Errorf("%q: got %q want %q", in, got, want)
		}
	}
	long := strings.Repeat("x", 65) + "=1&ok=2"
	if got := strings.Join(QueryParamNames(long), ","); got != "ok" {
		t.Errorf("an over-long name is dropped: %q", got)
	}
}

// Parameter values must not survive decoding, aggregation or serialisation.
func TestParamNamesNeverCarryValues(t *testing.T) {
	const secret = "S3CRET-VALUE"
	mk := func(attrs string) Span {
		body := `{"resourceSpans":[{"resource":{"attributes":[{"key":"service.name","value":{"stringValue":"api"}}]},
		 "scopeSpans":[{"spans":[{"traceId":"ab","spanId":"12","name":"GET /rest/products/search","kind":2,"startTimeUnixNano":"1","endTimeUnixNano":"2000001",
		 "attributes":[` + attrs + `]}]}]}]}`
		spans, err := DecodeTracesJSON([]byte(body))
		if err != nil || len(spans) != 1 {
			t.Fatalf("%v %d", err, len(spans))
		}
		return spans[0]
	}
	str := func(k, v string) string { return `{"key":"` + k + `","value":{"stringValue":"` + v + `"}}` }
	for name, attrs := range map[string]string{
		"new convention": str("http.route", "/rest/products/search") + "," + str("url.query", "q="+secret+"&sort=asc"),
		"old target":     str("http.route", "/rest/products/search") + "," + str("http.target", "/rest/products/search?q="+secret+"&sort=asc"),
		"old full url":   str("http.route", "/rest/products/search") + "," + str("http.url", "http://u:"+secret+"@h/rest/products/search?q="+secret+"&sort=asc"),
	} {
		s := mk(attrs)
		if strings.Join(s.ParamNames, ",") != "q,sort" {
			t.Fatalf("%s: %v", name, s.ParamNames)
		}
		a, _ := newTestAgg(AggOptions{})
		end := testNow.Add(-time.Minute)
		s.Kind, s.Method, s.HTTPStatus = kindServer, "GET", 200
		s.EndNano, s.StartNano = uint64(end.UnixNano()), uint64(end.UnixNano())-1e6
		a.Ingest(s, verifiedPeer, IdentityVerified)
		a.Ingest(s, verifiedPeer, IdentityVerified)
		b := a.Flush("a1", true)
		if len(b.Params) != 2 || b.Params[0].Name != "q" || b.Params[0].Count != 2 || b.Params[1].Name != "sort" || b.Params[0].Route != "/rest/products/search" {
			t.Fatalf("%s: %+v", name, b.Params)
		}
		raw, _ := json.Marshal(b)
		if strings.Contains(string(raw), secret) {
			t.Fatalf("%s: a parameter value left the aggregator: %s", name, raw)
		}
		if again := a.Flush("a1", true); len(again.Params) != 0 {
			t.Fatalf("%s: counts are per flush: %+v", name, again.Params)
		}
	}
}

func TestParamNamesRequeueAndCaps(t *testing.T) {
	a, _ := newTestAgg(AggOptions{})
	end := testNow.Add(-time.Minute)
	for i := 0; i < maxParamsPerRoute+20; i++ {
		s := srvSpan("/r", 200, 1, end)
		s.ParamNames = []string{"p" + strings.Repeat("a", i%5) + string(rune('A'+i%26)) + string(rune('a'+i/26))}
		a.Ingest(s, verifiedPeer, IdentityVerified)
	}
	un := srvSpan("", 200, 1, end) // no route template: names are not tracked
	un.ParamNames = []string{"zzz"}
	a.Ingest(un, verifiedPeer, IdentityVerified)
	b := a.Flush("a1", true)
	if len(b.Params) > maxParamsPerRoute || a.Stats.ParamDrops == 0 {
		t.Fatalf("per-route cap: %d names, %d drops", len(b.Params), a.Stats.ParamDrops)
	}
	for _, p := range b.Params {
		if p.Name == "zzz" {
			t.Fatal("unmatched requests are not tracked")
		}
	}
	a.Requeue(b)
	if again := a.Flush("a1", true); len(again.Params) != len(b.Params) {
		t.Fatalf("requeue keeps counts: %d vs %d", len(again.Params), len(b.Params))
	}
}

func TestPayloadNameDenied(t *testing.T) {
	for _, n := range []string{"password", "Password", "user_password", "newPassword", "passwd", "apiKey", "api_key", "API-KEY", "auth_token", "accessToken",
		"token", "secret", "client_secret", "cookie", "Authorization", "card_number", "cardNumber", "cvv", "ssn", "otp", "sessionId", "session", "jwt", "csrf", "refresh_token"} {
		if !PayloadNameDenied(n) {
			t.Errorf("%q must be denied", n)
		}
	}
	for _, n := range []string{"q", "sort", "page", "limit", "user", "email", "id", "filter", "keyword", "monkey", "bypass", "category", "passenger", "compass"} {
		if PayloadNameDenied(n) {
			t.Errorf("%q must not be denied", n)
		}
	}
}

func TestPayloadValueMasked(t *testing.T) {
	for _, v := range []string{"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abc123", "Bearer abcdef", "basic dXNlcjpwYXNz", "4111 1111 1111 1111", "4111-1111-1111-1111",
		"-----BEGIN PRIVATE KEY-----", "3f9a8c1b2d4e5f60718293a4b5c6d7e8f9a0b1c2", "QWxhZGRpbjpvcGVuIHNlc2FtZQ12345678901234567890"} {
		if !PayloadValueMasked(v) {
			t.Errorf("%q must be masked", v)
		}
	}
	for _, v := range []string{"apple", "asc", "2026-11-20", "1234567890123", "hello world this is a long search phrase", "", "a-b"} {
		if PayloadValueMasked(v) {
			t.Errorf("%q must not be masked", v)
		}
	}
}

// Only a reviewed route forwards parameter values, only for allowed names, and never a denied name or a
// credential-looking value, whatever the policy says.
func TestPayloadOnlyFromReviewedRoutes(t *testing.T) {
	const jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abc123"
	policy := func(svc, env, route, method string) (map[string]bool, bool) {
		if route == "/rest/products/search" {
			return map[string]bool{"q": true, "password": true, "ref": true, "page": true}, true // an admin even left password unmasked
		}
		return nil, false
	}
	a, _ := newTestAgg(AggOptions{PayloadFn: policy})
	end := testNow.Add(-time.Minute)
	mk := func(route, query string) Span {
		s := srvSpan(route, 200, 1, end)
		s.ParamNames, s.ParamValues = QueryParamNames(query), nil
		_, s.ParamValues = queryParams(query)
		return s
	}
	a.Ingest(mk("/rest/products/search", "q=apple&sort=asc&password=hunter2&ref="+jwt+"&page=2"), verifiedPeer, IdentityVerified)
	a.Ingest(mk("/login", "user=bob&password=hunter3"), verifiedPeer, IdentityVerified)
	b := a.Flush("a1", true)
	if len(b.Payloads) != 1 {
		t.Fatalf("one payload, from the reviewed route only: %+v", b.Payloads)
	}
	p := b.Payloads[0]
	if p.Route != "/rest/products/search" || len(p.Params) != 2 || p.Params["q"] != "apple" || p.Params["page"] != "2" {
		t.Fatalf("allowed parameters: %+v", p)
	}
	if strings.Join(p.Withheld, ",") != "sort,password,ref" { // not allowed, always denied, credential-looking value
		t.Fatalf("withheld: %v", p.Withheld)
	}
	raw, _ := json.Marshal(b)
	for _, leak := range []string{"hunter2", "hunter3", jwt, "asc", "bob"} {
		if strings.Contains(string(raw), `"`+leak+`"`) || strings.Contains(string(raw), leak) {
			t.Fatalf("%q left the agent: %s", leak, raw)
		}
	}
	if a.Stats.PayloadHeld != 1 || a.Stats.PayloadSent != 1 {
		t.Fatalf("stats: %+v", a.Stats)
	}
	// No policy function at all: nothing is ever forwarded.
	n, _ := newTestAgg(AggOptions{})
	n.Ingest(mk("/rest/products/search", "q=apple"), verifiedPeer, IdentityVerified)
	if nb := n.Flush("a1", true); len(nb.Payloads) != 0 {
		t.Fatalf("no policy, no payload: %+v", nb.Payloads)
	}
}

func TestPayloadSamplingAndRequeue(t *testing.T) {
	a, _ := newTestAgg(AggOptions{PayloadFn: func(_, _, _, _ string) (map[string]bool, bool) { return map[string]bool{"q": true}, true }})
	end := testNow.Add(-time.Minute)
	for i := 0; i < 20; i++ {
		s := srvSpan("/r", 200, 1, end)
		s.ParamNames, s.ParamValues = []string{"q"}, map[string]string{"q": "v"}
		a.Ingest(s, verifiedPeer, IdentityVerified)
	}
	b := a.Flush("a1", true)
	if len(b.Payloads) != maxPayloadsPerRoute {
		t.Fatalf("samples per route per flush: %d", len(b.Payloads))
	}
	a.Requeue(b)
	if again := a.Flush("a1", true); len(again.Payloads) != maxPayloadsPerRoute {
		t.Fatalf("requeue: %d", len(again.Payloads))
	}
}

func TestLiveSettingsPayloadPolicy(t *testing.T) {
	l := newLiveSettings()
	l.set([]RemoteService{{Service: "api", Environment: "prod", Payload: []RemotePayloadRoute{
		{Route: "/a", Method: "get", Allow: []string{"q", "password", "bad name", "page"}},
		{Route: "/none", Method: "GET", Allow: []string{}},
	}}}, testNow)
	allow, ok := l.payloadFor("api", "prod", "/a", "GET")
	if !ok || len(allow) != 2 || !allow["q"] || !allow["page"] || allow["password"] {
		t.Fatalf("the agent filters denied and malformed names itself: %v %v", allow, ok)
	}
	if allow, ok := l.payloadFor("api", "prod", "/none", "GET"); !ok || len(allow) != 0 {
		t.Fatalf("reviewed with everything masked: %v %v", allow, ok)
	}
	if _, ok := l.payloadFor("api", "prod", "/b", "GET"); ok {
		t.Fatal("an unlisted route is unreviewed")
	}
	// A service with a policy but no saved settings does not override the privacy settings of the build.
	l.set([]RemoteService{{Service: "api2", Environment: "prod", PolicyOnly: true, CleartextUsers: false, Payload: []RemotePayloadRoute{{Route: "/x", Method: "GET", Allow: []string{"q"}}}}}, testNow)
	if _, ok := l.get("api2", "prod"); ok {
		t.Fatal("a policy-only entry must not count as saved settings")
	}
	if allow, ok := l.payloadFor("api2", "prod", "/x", "GET"); !ok || !allow["q"] {
		t.Fatalf("but its payload routes apply: %v %v", allow, ok)
	}
	l.set(nil, testNow) // a pulled config without policy revokes everything
	if _, ok := l.payloadFor("api", "prod", "/a", "GET"); ok {
		t.Fatal("removed policy must stop capture")
	}
}

func TestBodyParamsFlattenAndCapture(t *testing.T) {
	names, vals := bodyParams(`{"email":"a@b.c","address":{"zip":"100","geo":{"lat":6.5}},"items":[{"sku":"x1","qty":2}],"password":"hunter2"}`)
	want := map[string]string{"email": "a@b.c", "address.zip": "100", "address.geo.lat": "6.5", "items[].sku": "x1", "items[].qty": "2", "password": "hunter2"}
	if len(names) != len(want) {
		t.Fatalf("names %v", names)
	}
	for k, v := range want {
		if vals[k] != v {
			t.Errorf("%s=%q want %q", k, vals[k], v)
		}
	}
	if n, _ := bodyParams("not json"); n != nil {
		t.Error("garbage must yield nothing")
	}
	if n, _ := bodyParams(`[1,2]`); n != nil {
		t.Error("non-object must yield nothing")
	}
	// merged with the query string, query wins on a duplicate name, and an injection in a body field is seen
	var s Span
	s.addQuery("email=q@q.q")
	s.addBody(`{"email":"b@b.b","note":"1' OR '1'='1"}`)
	if s.ParamValues["email"] != "q@q.q" || len(s.ParamNames) != 2 {
		t.Fatalf("merge: %v %v", s.ParamNames, s.ParamValues)
	}
	if paramInjection(s) != "param.sql-injection" {
		t.Fatal("body injection not detected")
	}
	// only reviewed, unmasked, non-denied fields leave
	a := NewAggregator(AggOptions{MaxClientKeys: 10, PayloadFn: func(svc, env, route, method string) (map[string]bool, bool) {
		return map[string]bool{"email": true, "password": true}, true
	}}, time.Now)
	s2 := Span{Kind: kindServer, HTTPStatus: 200, Route: "/signup", Method: "POST", Res: Resource{Service: "shop"}}
	s2.addBody(`{"email":"a@b.c","password":"hunter2","extra":"z"}`)
	a.Ingest(s2, Peer{}, "")
	b := a.Flush("ag", true)
	if len(b.Payloads) != 1 || b.Payloads[0].Params["email"] != "a@b.c" || len(b.Payloads[0].Params) != 1 {
		t.Fatalf("payloads %+v", b.Payloads)
	}
}
