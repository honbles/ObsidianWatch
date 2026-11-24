package otel

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"obsidianwatch/linux-agent/pkg/schema"
)

type fakeBackend struct {
	mu      sync.Mutex
	batches []Batch
	apiKeys []string
	status  int // 0 → 200
	calls   int
	config  string // body served at /api/v1/app/agent-config
	cfgHits int
}

func (f *fakeBackend) handler(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if r.URL.Path == "/api/v1/app/agent-config" && r.Method == "GET" {
		f.cfgHits++
		if f.config == "" || r.URL.Query().Get("agent_id") == "" {
			w.WriteHeader(404)
			return
		}
		_, _ = w.Write([]byte(f.config))
		return
	}
	if r.URL.Path != "/api/v1/app/batch" || r.Method != "POST" {
		http.NotFound(w, r)
		return
	}
	if f.status != 0 {
		w.WriteHeader(f.status)
		return
	}
	var b Batch
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
		http.Error(w, "bad", 400)
		return
	}
	f.batches = append(f.batches, b)
	f.apiKeys = append(f.apiKeys, r.Header.Get("X-API-Key"))
	w.WriteHeader(200)
}

func tlsBackend(t *testing.T, f *fakeBackend) (*httptest.Server, string) {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(f.handler))
	t.Cleanup(srv.Close)
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	return srv, string(pemBytes)
}

func TestServiceEndToEnd(t *testing.T) {
	fb := &fakeBackend{}
	srv, ca := tlsBackend(t, fb)
	var evMu sync.Mutex
	var events []schema.Event
	svc, err := New(Options{
		AgentID: "agent-1", Hostname: "web-01",
		Resolver: fakeResolver{Peer{Resolved: true, PID: os.Getpid(), PPID: os.Getppid(), Exe: "/opt/shop/bin/shop"}}, // portable; the real resolver has its own tests
		Receiver: ReceiverOptions{Listen: "127.0.0.1:0"},
		Sender:   SenderOptions{BackendURL: srv.URL, APIKey: "key-123", CACertPEM: ca, Version: "t"},
		Agg:      AggOptions{BaselinePct: 100}, UserHashKey: "k", FlushInterval: 50 * time.Millisecond,
		Emit:   func(ev schema.Event) bool { evMu.Lock(); events = append(events, ev); evMu.Unlock(); return true },
		Logger: discardLog(),
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- svc.Run(ctx) }()
	var url string
	for i := 0; i < 100 && url == ""; i++ {
		if a := svc.Recv.Addrs(); len(a) > 0 {
			url = "http://" + a[0].String()
		}
		time.Sleep(10 * time.Millisecond)
	}
	if url == "" {
		t.Fatal("receiver did not start")
	}
	if r := post(t, url+"/v1/traces", "application/x-protobuf", goodTraces(), nil); r.StatusCode != 200 {
		t.Fatalf("%d", r.StatusCode)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}

	fb.mu.Lock()
	defer fb.mu.Unlock()
	if len(fb.batches) == 0 {
		t.Fatal("backend received nothing")
	}
	var routes, instances int
	for i, b := range fb.batches {
		if fb.apiKeys[i] != "" || b.AgentID != "agent-1" { // no API key: the agent certificate authenticates
			t.Fatalf("headers/agent: %q %q", fb.apiKeys[i], b.AgentID)
		}
		routes += len(b.Routes)
		for _, in := range b.Instances {
			instances++
			if in.PID != os.Getpid() || in.Identity != "verified" || in.Service != "shop" || in.Environment != "prod" {
				t.Fatalf("instance: %+v", in)
			}
		}
	}
	if routes != 1 || instances == 0 {
		t.Fatalf("routes=%d instances=%d", routes, instances)
	}
}

func TestSenderRetriesThenRequeues(t *testing.T) {
	fb := &fakeBackend{status: 503}
	srv, ca := tlsBackend(t, fb)
	requeued := make(chan *Batch, 1)
	s, err := NewSender(SenderOptions{BackendURL: srv.URL, CACertPEM: ca}, func(b *Batch) { requeued <- b }, discardLog())
	if err != nil {
		t.Fatal(err)
	}
	b := &Batch{AgentID: "a", Routes: []BatchRoute{{Service: "s", Route: "/", Method: "GET", Calls: 5}}}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	go func() { s.deliver(ctx, b) }()
	select {
	case got := <-requeued:
		if got.Routes[0].Calls != 5 {
			t.Fatal("wrong batch handed back")
		}
	case <-time.After(20 * time.Second):
		t.Fatal("batch was neither delivered nor handed back")
	}
	if fb.calls != 3 {
		t.Fatalf("expected 3 attempts, got %d", fb.calls)
	}
}

func TestSenderDoesNotRetryRejections(t *testing.T) {
	fb := &fakeBackend{status: 403}
	srv, ca := tlsBackend(t, fb)
	s, _ := NewSender(SenderOptions{BackendURL: srv.URL, CACertPEM: ca}, func(*Batch) { t.Error("must not requeue a rejected batch") }, discardLog())
	s.deliver(context.Background(), &Batch{AgentID: "a"})
	if fb.calls != 1 || s.Failed.Load() != 1 {
		t.Fatalf("calls=%d failed=%d", fb.calls, s.Failed.Load())
	}
}

func TestSenderQueueDropsOldestAndCounts(t *testing.T) {
	s, _ := NewSender(SenderOptions{BackendURL: "https://127.0.0.1:1"}, nil, discardLog())
	for i := 0; i < 130; i++ {
		s.Send(&Batch{AgentID: "a"})
	}
	if s.Drops.Load() != 30 || len(s.q) != 100 {
		t.Fatalf("drops=%d queue=%d", s.Drops.Load(), len(s.q))
	}
}

func TestSenderRefusesPlainHTTPCAGarbage(t *testing.T) {
	if _, err := NewSender(SenderOptions{BackendURL: "https://x", CACertPEM: "not pem"}, nil, discardLog()); err == nil {
		t.Fatal("invalid CA must fail at construction")
	}
}

func TestNewRequiresNormalChannel(t *testing.T) {
	if _, err := New(Options{}); err == nil || !strings.Contains(err.Error(), "normal channel") {
		t.Fatalf("Emit must be required: %v", err)
	}
}
