package otel

import (
	"context"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"obsidianwatch/agent/pkg/schema"
)

func TestStricterMode(t *testing.T) {
	for _, c := range []struct{ a, b, want string }{
		{"full", "off", "off"}, {"off", "full", "off"}, {"truncated", "full", "truncated"}, {"full", "truncated", "truncated"},
		{"full", "full", "full"}, {"full", "bogus", "full"}, {"bogus", "truncated", "truncated"}, {"x", "y", "full"},
	} {
		if got := stricterMode(c.a, c.b); got != c.want {
			t.Fatalf("stricter(%s,%s)=%s want %s", c.a, c.b, got, c.want)
		}
	}
}

func TestLiveSettingsValidation(t *testing.T) {
	l := newLiveSettings()
	l.set([]RemoteService{{Service: "api", Environment: "", StoreClientIP: "weird", LatencyTargetMs: -4}, {Service: ""}}, time.Now())
	rs, ok := l.get("api", "default")
	if !ok || rs.StoreClientIP != "" || rs.LatencyTargetMs != 0 {
		t.Fatalf("invalid values must be neutralised: %+v %v", rs, ok)
	}
	if _, ok := l.get("", "default"); ok {
		t.Fatal("nameless rows ignored")
	}
}

func TestFetchConfigAndPrecedence(t *testing.T) {
	fb := &fakeBackend{config: `{"services":[
	  {"service":"api","environment":"prod","store_client_ip":"off","cleartext_users":true,"latency_target_ms":250},
	  {"service":"web","environment":"prod","store_client_ip":"full","cleartext_users":false}]}`}
	srv, ca := tlsBackend(t, fb)
	var mu sync.Mutex
	var events []schema.Event
	svc, err := New(Options{
		AgentID: "agent-1", Hostname: "h", Resolver: fakeResolver{Peer{Resolved: true, PID: os.Getpid(), Exe: "/x"}},
		Receiver: ReceiverOptions{Listen: "127.0.0.1:0"}, Sender: SenderOptions{BackendURL: srv.URL, APIKey: "k", CACertPEM: ca},
		UserHashKey: "key", FlushInterval: time.Hour, ConfigInterval: time.Hour,
		ClientIPDefault:   "truncated",          // build floor
		CleartextServices: []string{"web|prod"}, // build opts web into cleartext; pulled settings say no
		Emit:              func(ev schema.Event) bool { mu.Lock(); events = append(events, ev); mu.Unlock(); return true },
		Logger:            discardLog(),
	})
	if err != nil {
		t.Fatal(err)
	}
	// Before the first pull: build configuration alone applies.
	if m := svc.Live; !m.Loaded().IsZero() {
		t.Fatal("nothing pulled yet")
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- svc.Run(ctx) }()
	for i := 0; i < 300 && svc.Live.Loaded().IsZero(); i++ {
		time.Sleep(20 * time.Millisecond)
	}
	if svc.Live.Loaded().IsZero() {
		t.Fatal("settings were not pulled")
	}
	url := "http://" + svc.Recv.Addrs()[0].String()
	send := func(service string) schema.Event {
		mu.Lock()
		events = nil
		mu.Unlock()
		body := logReq(stdRes(service, "prod"), "auth.login", "", pbStrAttr("outcome", "failure"), pbStrAttr("user", "alice@example.com"), pbStrAttr("client.address", "203.0.113.9"))
		if r := post(t, url+"/v1/logs", "application/x-protobuf", body, nil); r.StatusCode != 200 {
			t.Fatalf("%d", r.StatusCode)
		}
		mu.Lock()
		defer mu.Unlock()
		if len(events) != 1 {
			t.Fatalf("events: %d", len(events))
		}
		return events[0]
	}
	// api: pulled "off" is stricter than the build's "truncated" → no address; cleartext user per pulled settings.
	ev := send("api")
	if strings.Contains(string(ev.Raw), "203.0.113") || ev.UserName != "alice@example.com" {
		t.Fatalf("api: user=%q raw=%s", ev.UserName, ev.Raw)
	}
	// web: pulled "full" cannot loosen the build's "truncated"; pulled cleartext=false overrides the build list.
	ev = send("web")
	if !strings.Contains(string(ev.Raw), `"client_ip":"203.0.113.0/24"`) || ev.UserName == "alice@example.com" || ev.UserName == "" {
		t.Fatalf("web: user=%q raw=%s", ev.UserName, ev.Raw)
	}
	// unknown service: build configuration only (truncated, hashed).
	ev = send("other")
	if !strings.Contains(string(ev.Raw), `"client_ip":"203.0.113.0/24"`) || ev.UserName == "alice@example.com" {
		t.Fatalf("other: user=%q raw=%s", ev.UserName, ev.Raw)
	}
	// The per-service latency target feeds the slow-trace threshold.
	if got := svc.Agg.slowMs(svcKey{"api", "prod"}); got != 250 {
		t.Fatalf("slow threshold %d", got)
	}
	cancel()
	<-done
	fb.mu.Lock()
	defer fb.mu.Unlock()
	if fb.cfgHits == 0 {
		t.Fatal("backend never saw the poll")
	}
}

func TestPollKeepsBuildConfigWhenBackendFails(t *testing.T) {
	fb := &fakeBackend{} // no config → 404
	srv, ca := tlsBackend(t, fb)
	svc, err := New(Options{AgentID: "a", Resolver: fakeResolver{}, Receiver: ReceiverOptions{Listen: "127.0.0.1:0"},
		Sender: SenderOptions{BackendURL: srv.URL, CACertPEM: ca}, Emit: func(schema.Event) bool { return true }, Logger: discardLog()})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Send.FetchConfig(context.Background(), "a"); err == nil {
		t.Fatal("a 404 must be an error, not an empty config")
	}
	if !svc.Live.Loaded().IsZero() {
		t.Fatal("failure must not mark settings as loaded")
	}
}
