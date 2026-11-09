package api

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"obsidianwatch/backend/pkg/schema"
)

type fakeIngestStore struct {
	events    []schema.Event
	insertErr error
	agents    []string
	host      string
}

func (f *fakeIngestStore) InsertEvents(_ context.Context, ev []schema.Event) error {
	if f.insertErr != nil {
		return f.insertErr
	}
	f.events = append(f.events, ev...)
	return nil
}
func (f *fakeIngestStore) UpsertAgent(_ context.Context, id, hostname, os, version, remoteIP, installKey string, n int) error {
	f.agents = append(f.agents, id)
	f.host = hostname
	return nil
}

func postIngest(h http.HandlerFunc, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest("POST", "/api/v1/ingest", strings.NewReader(body))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr
}

func quietLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func TestIngestValidation(t *testing.T) {
	st := &fakeIngestStore{}
	h := handleIngest(st, 2, quietLogger())
	if rr := postIngest(h, `not json`); rr.Code != 400 {
		t.Errorf("bad json: %d", rr.Code)
	}
	if rr := postIngest(h, `{"events":[{"id":"1"}]}`); rr.Code != 400 {
		t.Errorf("missing agent_id: %d", rr.Code)
	}
	if rr := postIngest(h, `{"agent_id":"a1","events":[]}`); rr.Code != 200 || len(st.events) != 0 {
		t.Errorf("empty batch: %d", rr.Code)
	}
	if rr := postIngest(h, `{"agent_id":"a1","events":[{"id":"1"},{"id":"2"},{"id":"3"}]}`); rr.Code != 413 {
		t.Errorf("oversized batch: %d", rr.Code)
	}
	long := strings.Repeat("a", 129)
	if rr := postIngest(h, `{"agent_id":"`+long+`","events":[{"id":"1"}]}`); rr.Code != 400 {
		t.Errorf("long agent id: %d", rr.Code)
	}
	req := httptest.NewRequest("GET", "/api/v1/ingest", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != 405 {
		t.Errorf("GET: %d", rr.Code)
	}
}

func TestIngestFillsDefaultsAndClampsFuture(t *testing.T) {
	st := &fakeIngestStore{}
	h := handleIngest(st, 100, quietLogger())
	future := time.Now().UTC().Add(48 * time.Hour).Format(time.RFC3339)
	body := `{"agent_id":"agent-fill","events":[{"id":"e1","host":"box1"},{"id":"e2","time":"` + future + `","agent_id":"other"}]}`
	rr := postIngest(h, body)
	if rr.Code != 200 {
		t.Fatalf("code %d: %s", rr.Code, rr.Body.String())
	}
	if len(st.events) != 2 {
		t.Fatalf("stored %d", len(st.events))
	}
	if st.events[0].AgentID != "agent-fill" || st.events[0].Time.IsZero() {
		t.Errorf("defaults not applied: %+v", st.events[0])
	}
	if st.events[1].AgentID != "other" {
		t.Errorf("explicit agent id should be kept")
	}
	if st.events[1].Time.After(time.Now().UTC().Add(11 * time.Minute)) {
		t.Errorf("future event not clamped: %v", st.events[1].Time)
	}
	if st.host != "box1" {
		t.Errorf("hostname should fall back to event host, got %q", st.host)
	}
}

func TestIngestInsertFailureIs500(t *testing.T) {
	st := &fakeIngestStore{insertErr: errors.New("db down")}
	h := handleIngest(st, 100, quietLogger())
	rr := postIngest(h, `{"agent_id":"agent-err","events":[{"id":"e"}]}`)
	if rr.Code != 500 || strings.Contains(rr.Body.String(), "db down") {
		t.Fatalf("code=%d body=%s (must not leak internal error)", rr.Code, rr.Body.String())
	}
	if len(st.agents) != 0 {
		t.Error("agent must not be registered when insert fails")
	}
}

func TestIngestThrottles(t *testing.T) {
	st := &fakeIngestStore{}
	h := handleIngest(st, 1000000, quietLogger())
	ingestThrottle.allow("agent-flood", int(agentBurstEvents)) // drain
	rr := postIngest(h, `{"agent_id":"agent-flood","events":[{"id":"e"},{"id":"f"}]}`)
	if rr.Code != 429 || rr.Header().Get("Retry-After") == "" {
		t.Fatalf("code=%d", rr.Code)
	}
}
