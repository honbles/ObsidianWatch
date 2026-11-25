package forwarder

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"obsidianwatch/agent/pkg/schema"
)

func evs(from, n int) []schema.Event {
	out := make([]schema.Event, n)
	for i := range out {
		out[i] = schema.Event{ID: fmt.Sprintf("e%05d", from+i)}
	}
	return out
}

func quiet() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func TestPeekDoesNotRemoveAndAckDoes(t *testing.T) {
	dir := t.TempDir()
	q, _ := NewQueue(dir, 0, quiet())
	q.Push(evs(0, 1200)) // spans three segments
	got, rc, err := q.Peek(700)
	if err != nil || len(got) != 700 || got[0].ID != "e00000" || got[699].ID != "e00699" {
		t.Fatalf("peek: %v %d", err, len(got))
	}
	if n, _ := q.Len(); n != 1200 {
		t.Fatalf("peek removed events: len %d", n)
	}
	q.Push(evs(1200, 10)) // appends between peek and ack must survive
	if err := q.Ack(rc); err != nil {
		t.Fatal(err)
	}
	if n, _ := q.Len(); n != 510 {
		t.Fatalf("len after ack = %d", n)
	}
	got, _, _ = q.Peek(1)
	if got[0].ID != "e00700" {
		t.Fatalf("next = %s", got[0].ID)
	}
}

func TestUnackedEventsSurviveRestart(t *testing.T) {
	dir := t.TempDir()
	q, _ := NewQueue(dir, 0, quiet())
	q.Push(evs(0, 30))
	q.Peek(30) // "crash" before Ack
	q.Close()
	q2, _ := NewQueue(dir, 0, quiet())
	got, rc, _ := q2.Peek(100)
	if len(got) != 30 {
		t.Fatalf("after restart %d events", len(got))
	}
	q2.Ack(rc)
	q2.Push(evs(30, 1))
	got, _, _ = q2.Peek(100)
	if len(got) != 1 || got[0].ID != "e00030" {
		t.Fatalf("write segment broken after ack: %+v", got)
	}
}

func newTestForwarder(t *testing.T, url string, q *Queue, batch int) *HTTPForwarder {
	f, err := NewHTTPForwarder(ForwarderConfig{BackendURL: url, BatchSize: batch, FlushInterval: time.Second}, q, "ag-1", "h", "t", quiet())
	if err != nil {
		t.Fatal(err)
	}
	f.retry = RetryPolicy{MaxAttempts: 2, BaseDelay: time.Millisecond, MaxDelay: time.Millisecond, Multiplier: 1}
	return f
}

func TestForwarderKeepsEventsOnFailureAndDrainsOnSuccess(t *testing.T) {
	var status atomic.Int32
	status.Store(503)
	var received atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var b schema.Batch
		json.NewDecoder(r.Body).Decode(&b)
		if s := int(status.Load()); s != 200 {
			w.WriteHeader(s)
			return
		}
		received.Add(int32(len(b.Events)))
	}))
	defer srv.Close()
	q, _ := NewQueue(t.TempDir(), 0, quiet())
	q.Push(evs(0, 250))
	f := newTestForwarder(t, srv.URL, q, 100)

	f.flush(context.Background())
	if n, _ := q.Len(); n != 250 {
		t.Fatalf("503 lost events: %d left", n)
	}
	status.Store(401)
	f.flush(context.Background())
	if n, _ := q.Len(); n != 250 {
		t.Fatalf("401 lost events: %d left", n)
	}
	status.Store(200)
	f.flush(context.Background())
	if n, _ := q.Len(); n != 0 || received.Load() != 250 {
		t.Fatalf("drain: left %d, received %d", n, received.Load())
	}
}

func TestForwarderShrinksOn413AndDropsOn400(t *testing.T) {
	var received atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var b schema.Batch
		json.NewDecoder(r.Body).Decode(&b)
		switch {
		case len(b.Events) > 40:
			w.WriteHeader(413)
		case b.Events[0].ID == "bad":
			w.WriteHeader(400)
		default:
			received.Add(int32(len(b.Events)))
		}
	}))
	defer srv.Close()
	q, _ := NewQueue(t.TempDir(), 0, quiet())
	q.Push([]schema.Event{{ID: "bad"}})
	q.Push(evs(0, 100))
	f := newTestForwarder(t, srv.URL, q, 100)
	f.flush(context.Background())
	if n, _ := q.Len(); n != 0 {
		t.Fatalf("left %d", n)
	}
	// Only the bad event is dropped: batches halve until it is alone.
	if received.Load() != 100 {
		t.Fatalf("received %d of 100 good events", received.Load())
	}
}
