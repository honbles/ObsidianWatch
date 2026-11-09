package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestValidateLocalLLMURL(t *testing.T) {
	good := map[string]string{
		"http://localhost:11434":        "http://localhost:11434",
		"http://10.0.0.5:8000/v1/":      "http://10.0.0.5:8000/v1",
		"https://llm.internal.example/": "https://llm.internal.example",
		"":                              "",
	}
	for in, want := range good {
		got, err := validateLocalLLMURL(in)
		if err != nil || got != want {
			t.Errorf("%q -> %q, %v (want %q)", in, got, err, want)
		}
	}
	for _, bad := range []string{"ftp://x", "http://user:pw@host", "http://169.254.169.254", "http://0.0.0.0:1", "http://h/?q=1", "notaurl", "javascript:alert(1)"} {
		if _, err := validateLocalLLMURL(bad); err == nil {
			t.Errorf("%q should be rejected", bad)
		}
	}
}

func TestLocalChatEndpoint(t *testing.T) {
	for in, want := range map[string]string{
		"http://h:11434":               "http://h:11434/v1/chat/completions",
		"http://h/v1":                  "http://h/v1/chat/completions",
		"http://h/v1/chat/completions": "http://h/v1/chat/completions",
		"http://h/openai/v1/":          "http://h/openai/v1/chat/completions",
	} {
		if got := localChatEndpoint(in); got != want {
			t.Errorf("%s -> %s, want %s", in, got, want)
		}
	}
}

func TestCallLocalLLM(t *testing.T) {
	var gotAuth, gotModel string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		var b struct {
			Model string `json:"model"`
		}
		json.NewDecoder(r.Body).Decode(&b)
		gotModel = b.Model
		if strings.Contains(r.URL.Path, "fail") {
			http.Error(w, "boom", 500)
			return
		}
		w.Write([]byte(`{"choices":[{"message":{"content":"{\"q\":\"host:web1\",\"since\":\"24h\"}"}}]}`))
	}))
	defer srv.Close() // loopback server: the local client must not be blocked by the SSRF guard

	m := localLLM{Endpoint: localChatEndpoint(srv.URL), Model: "llama3", APIKey: "k"}
	out, err := callLocalLLM(context.Background(), m, "sys", "find web1")
	if err != nil || !strings.Contains(out, "host:web1") {
		t.Fatalf("out=%q err=%v", out, err)
	}
	if gotAuth != "Bearer k" || gotModel != "llama3" {
		t.Fatalf("auth=%q model=%q", gotAuth, gotModel)
	}
	if _, err := callLocalLLM(context.Background(), localLLM{Endpoint: srv.URL + "/fail", Model: "m"}, "s", "p"); err == nil {
		t.Fatal("HTTP 500 must be an error")
	}
	// The reply goes through the same validator as hosted output.
	if q, since, err := validateNLQuery(out); err != nil || q == "" || since == "" {
		t.Fatalf("local output must satisfy validateNLQuery: %q %q %v", q, since, err)
	}
}

func TestRunNLProvidersFailover(t *testing.T) {
	ok := func(context.Context) (string, error) { return `{"q":"host:web1","since":"24h"}`, nil }
	boom := func(context.Context) (string, error) { return "", errors.New("503") }
	junk := func(context.Context) (string, error) { return "I cannot help with that", nil }

	// First fails, second answers.
	q, _, model, trail, err := runNLProviders(context.Background(), []nlProvider{
		{Name: "groq", Model: "g", Call: boom}, {Name: "anthropic", Model: "a", Call: ok},
	}, time.Second)
	if err != nil || q != "host:web1" || model != "a" || strings.Join(trail, ",") != "groq:error,anthropic:ok" {
		t.Fatalf("failover: q=%q model=%q trail=%v err=%v", q, model, trail, err)
	}
	// Invalid output also falls through to the next provider.
	if _, _, model, _, err := runNLProviders(context.Background(), []nlProvider{
		{Name: "local", Model: "l", Call: junk}, {Name: "groq", Model: "g", Call: ok},
	}, time.Second); err != nil || model != "g" {
		t.Fatalf("invalid output must fail over: model=%q err=%v", model, err)
	}
	// Everyone errors -> transport-style failure.
	if _, _, _, _, err := runNLProviders(context.Background(), []nlProvider{{Name: "a", Call: boom}, {Name: "b", Call: boom}}, time.Second); !errors.Is(err, errAllNLProvidersFailed) {
		t.Fatalf("want errAllNLProvidersFailed, got %v", err)
	}
	// Only invalid replies -> the validation error, not a "provider down" error.
	if _, _, _, _, err := runNLProviders(context.Background(), []nlProvider{{Name: "a", Call: junk}}, time.Second); err == nil || errors.Is(err, errAllNLProvidersFailed) {
		t.Fatalf("want validation error, got %v", err)
	}
	// A hung provider is cut off by the per-call timeout and the next one runs.
	hang := func(ctx context.Context) (string, error) { <-ctx.Done(); return "", ctx.Err() }
	if _, _, model, _, err := runNLProviders(context.Background(), []nlProvider{
		{Name: "slow", Model: "s", Call: hang}, {Name: "ok", Model: "o", Call: ok},
	}, 50*time.Millisecond); err != nil || model != "o" {
		t.Fatalf("timeout failover: model=%q err=%v", model, err)
	}
}
