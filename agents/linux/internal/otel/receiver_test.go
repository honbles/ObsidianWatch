package otel

import (
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"obsidianwatch/linux-agent/pkg/schema"
)

type fakeResolver struct{ p Peer }

func (f fakeResolver) Resolve(net.Conn) Peer { return f.p }

func discardLog() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

type recvFixture struct {
	r      *Receiver
	agg    *Aggregator
	url    string
	mu     sync.Mutex
	events []schema.Event
	full   bool
}

func newRecvFixture(t *testing.T, res PeerResolver) *recvFixture {
	t.Helper()
	f := &recvFixture{agg: NewAggregator(AggOptions{}, nil)}
	ec := EventContext{AgentID: "agent-1", Host: "web-01", Hasher: NewHasher("k"),
		IPMode: func(string, string) string { return ClientIPFull }}
	f.r = NewReceiver(ReceiverOptions{Listen: "127.0.0.1:0"}, f.agg, NewBinder(), res, ec, func(ev schema.Event) bool {
		f.mu.Lock()
		defer f.mu.Unlock()
		if f.full {
			return false
		}
		f.events = append(f.events, ev)
		return true
	}, discardLog())
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	if err := f.r.Start(ctx); err != nil {
		t.Fatal(err)
	}
	f.url = "http://" + f.r.Addrs()[0].String()
	return f
}

func post(t *testing.T, url, ct string, body []byte, hdr map[string]string) *http.Response {
	t.Helper()
	req, _ := http.NewRequest("POST", url, bytes.NewReader(body))
	req.Header.Set("Content-Type", ct)
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return resp
}

func goodTraces() []byte {
	now := uint64(time.Now().Add(-time.Minute).UnixNano())
	return traceReq(stdRes("shop", "prod"), fixSpan{trace: "0123456789abcdef", span: "01234567", name: "GET /x", kind: kindServer,
		start: now - 5_000_000, end: now, attrs: []func(*pbw){pbStrAttr("http.route", "/x"), pbIntAttr("http.response.status_code", 200)}})
}

func TestReceiverTracesStampIdentity(t *testing.T) {
	peer := Peer{Resolved: true, PID: 4242, PPID: 1, ProcStart: time.Unix(1700000000, 0), ContainerID: strings.Repeat("a", 64), Exe: "/opt/shop/bin/shop"}
	f := newRecvFixture(t, fakeResolver{peer})
	resp := post(t, f.url+"/v1/traces", "application/x-protobuf", goodTraces(), nil)
	if resp.StatusCode != 200 || resp.Header.Get("Content-Type") != "application/x-protobuf" {
		t.Fatalf("%d %s", resp.StatusCode, resp.Header.Get("Content-Type"))
	}
	b := f.agg.Flush("agent-1", true)
	if b == nil || len(b.Routes) != 1 || len(b.Instances) != 1 {
		t.Fatalf("%+v", b)
	}
	in := b.Instances[0]
	if in.PID != 4242 || in.ContainerID != peer.ContainerID || in.Identity != "verified" || in.Exe != peer.Exe {
		t.Fatalf("identity must come from the connection: %+v", in)
	}
}

func TestReceiverUnresolvedPeerIsAsserted(t *testing.T) {
	f := newRecvFixture(t, fakeResolver{Peer{Reason: "other namespace"}})
	post(t, f.url+"/v1/traces", "application/x-protobuf", goodTraces(), nil)
	b := f.agg.Flush("a", true)
	if b == nil || len(b.Instances) != 1 || b.Instances[0].Identity != "asserted" || b.Instances[0].PID != 0 {
		t.Fatalf("%+v", b)
	}
	if f.r.Stats.Unresolved.Load() != 1 || f.r.Stats.Asserted.Load() != 1 {
		t.Fatal("counters")
	}
}

func TestReceiverSecurityEventsUseNormalChannelWithPIDs(t *testing.T) {
	peer := Peer{Resolved: true, PID: 4242, PPID: 4200, Exe: "/opt/shop/bin/shop", ContainerID: strings.Repeat("b", 64)}
	f := newRecvFixture(t, fakeResolver{peer})
	body := logReq(stdRes("shop", "prod"), "auth.login", "0123456789abcdef",
		pbStrAttr("outcome", "failure"), pbStrAttr("user", "alice@example.com"), pbStrAttr("client.address", "198.51.100.7"),
		pbStrAttr("route", "/login?next=/admin"), pbStrAttr("object_id", "order-77"))
	if resp := post(t, f.url+"/v1/logs", "application/x-protobuf", body, nil); resp.StatusCode != 200 {
		t.Fatalf("%d", resp.StatusCode)
	}
	if len(f.events) != 1 {
		t.Fatalf("events: %d", len(f.events))
	}
	ev := f.events[0]
	if ev.EventType != "app.security" || ev.Source != "app" || ev.AgentID != "agent-1" || ev.Host != "web-01" {
		t.Fatalf("%+v", ev)
	}
	// The own-activity filter needs process and parent ids on every event.
	if ev.PID != 4242 || ev.PPID != 4200 || ev.ProcessName != "shop" || ev.ImagePath != peer.Exe {
		t.Fatalf("pid/ppid: %+v", ev)
	}
	s := string(ev.Raw)
	for _, bad := range []string{"alice@example.com", "order-77", "next=/admin"} {
		if strings.Contains(s, bad) || strings.Contains(ev.UserName, "alice") {
			t.Fatalf("personal data leaked (%q) in %s / %s", bad, s, ev.UserName)
		}
	}
	if !strings.Contains(s, `"event.name":"auth.login"`) || !strings.Contains(s, `"client_ip":"198.51.100.7"`) ||
		!strings.Contains(s, `"route":"/login"`) || !strings.Contains(s, `"identity":"verified"`) || ev.UserName == "" {
		t.Fatalf("raw.app: %s user=%q", s, ev.UserName)
	}
	// A trace touched by a security event is kept.
	f.agg.mu.Lock()
	n := len(f.agg.sec)
	f.agg.mu.Unlock()
	if n != 1 {
		t.Fatal("trace must be flagged as security")
	}
}

func TestReceiverEmitBackpressureIsCountedNotBlocking(t *testing.T) {
	f := newRecvFixture(t, fakeResolver{Peer{Resolved: true, PID: 1, Exe: "/x"}})
	f.full = true
	body := logReq(stdRes("shop", "prod"), "authz.deny", "", pbStrAttr("outcome", "deny"))
	if resp := post(t, f.url+"/v1/logs", "application/x-protobuf", body, nil); resp.StatusCode != 200 {
		t.Fatal(resp.StatusCode)
	}
	if f.r.Stats.EmitDropped.Load() != 1 || f.r.Stats.SecurityEvents.Load() != 0 {
		t.Fatalf("%d %d", f.r.Stats.EmitDropped.Load(), f.r.Stats.SecurityEvents.Load())
	}
}

func TestReceiverHTTPContract(t *testing.T) {
	f := newRecvFixture(t, fakeResolver{Peer{Resolved: true, PID: 1, Exe: "/x"}})
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	zw.Write(goodTraces())
	zw.Close()
	if r := post(t, f.url+"/v1/traces", "application/x-protobuf", gz.Bytes(), map[string]string{"Content-Encoding": "gzip"}); r.StatusCode != 200 {
		t.Fatalf("gzip: %d", r.StatusCode)
	}
	if r := post(t, f.url+"/v1/traces", "text/plain", goodTraces(), nil); r.StatusCode != 415 {
		t.Fatalf("content type: %d", r.StatusCode)
	}
	if r := post(t, f.url+"/v1/traces", "application/x-protobuf", []byte{0x0a, 0xff, 0xff, 0xff, 0x0f}, nil); r.StatusCode != 400 {
		t.Fatalf("malformed: %d", r.StatusCode)
	}
	if r := post(t, f.url+"/v1/traces", "application/x-protobuf", goodTraces(), map[string]string{"Content-Encoding": "br"}); r.StatusCode != 415 {
		t.Fatalf("encoding: %d", r.StatusCode)
	}
	if r := post(t, f.url+"/v1/traces", "application/x-protobuf", bytes.Repeat([]byte{0}, maxRequestBytes+10), nil); r.StatusCode != 413 && r.StatusCode != 400 {
		t.Fatalf("oversize: %d", r.StatusCode)
	}
	if r := post(t, f.url+"/v1/metrics", "application/x-protobuf", []byte{}, nil); r.StatusCode != 200 {
		t.Fatalf("metrics are accepted and ignored: %d", r.StatusCode)
	}
	resp, err := http.Get(f.url + "/v1/traces")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 405 {
		t.Fatalf("GET: %d", resp.StatusCode)
	}
	// gzip bomb: tiny on the wire, huge decompressed.
	var bomb bytes.Buffer
	bw := gzip.NewWriter(&bomb)
	bw.Write(bytes.Repeat([]byte{0}, maxDecompressedBytes+1024))
	bw.Close()
	if r := post(t, f.url+"/v1/traces", "application/x-protobuf", bomb.Bytes(), map[string]string{"Content-Encoding": "gzip"}); r.StatusCode != 413 {
		t.Fatalf("gzip bomb: %d", r.StatusCode)
	}
}

func TestValidateListenRefusesRoutableAddresses(t *testing.T) {
	for _, bad := range []string{"0.0.0.0:4318", ":4318", "[::]:4318", "10.1.2.3:4318", "example.com:4318", "192.168.0.5:4318", "nonsense"} {
		if _, err := ValidateListen(bad); err == nil {
			t.Fatalf("%q must be refused", bad)
		}
	}
	for _, ok := range []string{"127.0.0.1:4318", "localhost:4318", "[::1]:4318", "127.0.0.5:9"} {
		if _, err := ValidateListen(ok); err != nil {
			t.Fatalf("%q: %v", ok, err)
		}
	}
	r := NewReceiver(ReceiverOptions{Listen: "0.0.0.0:0"}, NewAggregator(AggOptions{}, nil), NewBinder(), fakeResolver{}, EventContext{}, nil, discardLog())
	if err := r.Start(context.Background()); err == nil {
		t.Fatal("receiver must refuse to start on a routable address")
	}
}

func TestReceiverOnlyLocal(t *testing.T) {
	f := newRecvFixture(t, fakeResolver{})
	if !f.r.OnlyLocal() {
		t.Fatal("loopback receiver must report local-only")
	}
}

func bytesReader(b []byte) io.Reader { return bytes.NewReader(b) }
