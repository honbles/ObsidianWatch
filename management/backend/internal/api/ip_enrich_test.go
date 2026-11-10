package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func testEnricher(t *testing.T, status int, calls *int32) *ipEnricher {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(calls, 1)
		if r.Header.Get("Key") != "k" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(status)
		_, _ = w.Write([]byte(`{"data":{"abuseConfidenceScore":87,"totalReports":12,"countryCode":"RU","isp":"EvilNet","isTor":true}}`))
	}))
	t.Cleanup(srv.Close)
	e := newIPEnricher()
	e.baseURL = srv.URL
	return e
}

func TestIPEnrichLookupAndCache(t *testing.T) {
	var calls int32
	e := testEnricher(t, 200, &calls)
	r, err := e.lookup(context.Background(), "k", "203.0.113.9")
	if err != nil || r.AbuseScore != 87 || !r.IsTor || r.Cached {
		t.Fatalf("first lookup: %+v %v", r, err)
	}
	r, err = e.lookup(context.Background(), "k", "203.0.113.9")
	if err != nil || !r.Cached || calls != 1 {
		t.Fatalf("second lookup should hit cache: %+v %v calls=%d", r, err, calls)
	}
}

func TestIPEnrichRejectsBadTargets(t *testing.T) {
	var calls int32
	e := testEnricher(t, 200, &calls)
	for _, ip := range []string{"10.0.0.1", "127.0.0.1", "169.254.1.1", "::1", "0.0.0.0", "evil.com", "", "1.2.3.4/../x"} {
		if _, err := e.lookup(context.Background(), "k", ip); err == nil {
			t.Errorf("%q should be rejected", ip)
		}
	}
	if calls != 0 {
		t.Fatalf("no upstream call should be made for rejected input, got %d", calls)
	}
}

func TestIPEnrichBadKeyAndBudget(t *testing.T) {
	var calls int32
	e := testEnricher(t, 200, &calls)
	if _, err := e.lookup(context.Background(), "wrong", "203.0.113.9"); err == nil {
		t.Error("rejected key must surface as an error")
	}
	e.used, e.day = abuseDailyBudget, e.now().UTC().Format("2006-01-02")
	if _, err := e.lookup(context.Background(), "k", "203.0.113.10"); err != errEnrichBudget {
		t.Errorf("expected budget error, got %v", err)
	}
}
