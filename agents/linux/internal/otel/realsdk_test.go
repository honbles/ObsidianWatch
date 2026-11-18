package otel

// realsdk_test.go - receives telemetry from REAL OpenTelemetry SDKs (the sample apps in
// samples/app) instead of hand-built fixtures. Skipped unless OW_REAL_SDK_OUT is set:
//
//	OW_REAL_SDK_OUT=/tmp/out.json OW_REAL_SDK_SECS=30 go test ./internal/otel -run TestRealSDK -v
//
// It listens on 127.0.0.1:4318 with the real process resolver, collects for the given time while
// samples/app/run_verify.sh drives the sample apps, then writes the aggregated batch and the
// security events to the output file.

import (
	"context"
	"encoding/json"
	"os"
	"strconv"
	"sync"
	"testing"
	"time"

	"obsidianwatch/linux-agent/pkg/schema"
)

func TestRealSDK(t *testing.T) {
	out := os.Getenv("OW_REAL_SDK_OUT")
	if out == "" {
		t.Skip("set OW_REAL_SDK_OUT to run against real SDKs")
	}
	secs, _ := strconv.Atoi(os.Getenv("OW_REAL_SDK_SECS"))
	if secs <= 0 {
		secs = 30
	}
	listen := os.Getenv("OW_REAL_SDK_LISTEN")
	if listen == "" {
		listen = "127.0.0.1:4318"
	}
	agg := NewAggregator(AggOptions{}, nil)
	var mu sync.Mutex
	var events []schema.Event
	ec := EventContext{AgentID: "verify-agent", Host: "verify-host", Hasher: NewHasher("verify-key"),
		IPMode: func(string, string) string { return ClientIPFull }}
	r := NewReceiver(ReceiverOptions{Listen: listen}, agg, NewBinder(), NewPeerResolver(), ec, func(ev schema.Event) bool {
		mu.Lock()
		events = append(events, ev)
		mu.Unlock()
		return true
	}, discardLog())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := r.Start(ctx); err != nil {
		t.Fatal(err)
	}
	t.Logf("receiver on %v for %ds", r.Addrs(), secs)
	if ready := os.Getenv("OW_REAL_SDK_READY"); ready != "" {
		_ = os.WriteFile(ready, []byte("ready"), 0o644)
	}
	time.Sleep(time.Duration(secs) * time.Second)
	b := agg.Flush("verify-agent", true)
	mu.Lock()
	defer mu.Unlock()
	res := map[string]any{"batch": b, "events": events, "stats": map[string]int64{
		"requests": r.Stats.Requests.Load(), "bad": r.Stats.BadRequests.Load(), "spans": r.Stats.Spans.Load(),
		"logs": r.Stats.Logs.Load(), "security": r.Stats.SecurityEvents.Load(), "asserted": r.Stats.Asserted.Load(), "unresolved": r.Stats.Unresolved.Load()}}
	js, _ := json.MarshalIndent(res, "", " ")
	if err := os.WriteFile(out, js, 0o644); err != nil {
		t.Fatal(err)
	}
}
