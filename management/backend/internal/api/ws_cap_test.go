package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHubRejectsWhenFull(t *testing.T) {
	h := &Hub{clients: make(map[*client]bool)}
	for i := 0; i < maxHubClients; i++ {
		h.clients[&client{}] = true
	}
	if !h.full() {
		t.Fatal("hub at capacity must report full")
	}
	w := httptest.NewRecorder()
	h.ServeWS(w, httptest.NewRequest(http.MethodGet, "/ws/events", nil))
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("got %d, want 503", w.Code)
	}
}
