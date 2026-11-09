package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"obsidianwatch/management/internal/auth"
)

func TestAILimitedPerUser(t *testing.T) {
	h := aiLimited(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) })
	call := func(user string) int {
		r := httptest.NewRequest(http.MethodPost, "/api/v1/ai/chat", nil)
		r = r.WithContext(context.WithValue(r.Context(), auth.ClaimsKey, &auth.Claims{Username: user}))
		w := httptest.NewRecorder()
		h(w, r)
		return w.Code
	}
	for i := 0; i < 40; i++ {
		if c := call("ai-user-a"); c != 200 {
			t.Fatalf("request %d: got %d", i+1, c)
		}
	}
	if call("ai-user-a") != 429 {
		t.Fatal("41st request must be limited")
	}
	if call("ai-user-b") != 200 {
		t.Fatal("another user must not share the budget")
	}
}
