package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	neturl "net/url"
	"strings"
	"time"

	"obsidianwatch/management/internal/store"
)

// P-14 / P-15: optional self-hosted model for natural-language search.
//
// Any server that speaks the OpenAI chat-completions protocol works: Ollama
// (http://host:11434), vLLM, llama.cpp's server, LM Studio, LocalAI. When
// configured it is preferred over the hosted providers, so the analyst's
// question never leaves the network. Admin settings (ai.local_url,
// ai.local_model, ai.local_api_key) are stored like the other AI settings.

const (
	settingLocalURL   = "ai.local_url"
	settingLocalModel = "ai.local_model"
	settingLocalKey   = "ai.local_api_key"
)

type localLLM struct {
	Endpoint string // full chat-completions URL
	Model    string
	APIKey   string // optional
}

// validateLocalLLMURL normalises an admin-supplied base URL. Unlike connector
// URLs, plain http and private/loopback hosts are expected here (the model runs
// on the same box or LAN), but userinfo, non-http(s) schemes and the cloud
// metadata/link-local range are refused.
func validateLocalLLMURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", nil
	}
	if len(raw) > 300 {
		return "", errors.New("URL too long")
	}
	u, err := neturl.Parse(raw)
	if err != nil || u.Host == "" {
		return "", errors.New("not a valid URL")
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", errors.New("URL must start with http:// or https://")
	}
	if u.User != nil {
		return "", errors.New("URL must not contain credentials")
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return "", errors.New("URL must not contain a query or fragment")
	}
	if a, err := netip.ParseAddr(u.Hostname()); err == nil {
		a = a.Unmap()
		if a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast() || a.IsUnspecified() || a.IsMulticast() {
			return "", errors.New("address not allowed")
		}
	}
	return strings.TrimRight(u.Scheme+"://"+u.Host+u.EscapedPath(), "/"), nil
}

// localChatEndpoint turns a base URL into the chat-completions endpoint.
func localChatEndpoint(base string) string {
	base = strings.TrimRight(base, "/")
	switch {
	case strings.HasSuffix(base, "/chat/completions"):
		return base
	case strings.HasSuffix(base, "/v1"):
		return base + "/chat/completions"
	default:
		return base + "/v1/chat/completions"
	}
}

// loadLocalLLM returns the configured local model, or ok=false if either the
// URL or the model name is missing.
func loadLocalLLM(ctx context.Context, db *store.DB) (localLLM, bool) {
	url, _ := db.GetSetting(ctx, settingLocalURL)
	model, _ := db.GetSetting(ctx, settingLocalModel)
	key, _ := db.GetSetting(ctx, settingLocalKey)
	if strings.TrimSpace(url) == "" || strings.TrimSpace(model) == "" {
		return localLLM{}, false
	}
	return localLLM{Endpoint: localChatEndpoint(url), Model: strings.TrimSpace(model), APIKey: key}, true
}

// localLLMClient deliberately bypasses the outbound SSRF guard on
// http.DefaultClient: the destination is an admin-configured local service,
// usually on loopback or a private address.
var localLLMClient = &http.Client{Timeout: 120 * time.Second}

const maxLocalLLMResponse = 4 << 20

// callLocalLLM sends one system+user exchange and returns the reply text.
func callLocalLLM(ctx context.Context, m localLLM, system, prompt string) (string, error) {
	body, _ := json.Marshal(map[string]interface{}{
		"model":       m.Model,
		"temperature": 0.1,
		"max_tokens":  1024,
		"stream":      false,
		"messages": []map[string]string{
			{"role": "system", "content": system},
			{"role": "user", "content": prompt},
		},
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, m.Endpoint, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	if m.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+m.APIKey)
	}
	resp, err := localLLMClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxLocalLLMResponse))
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("local model returned HTTP %d", resp.StatusCode)
	}
	var out struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
		Error *struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return "", fmt.Errorf("local model returned invalid JSON")
	}
	if out.Error != nil && out.Error.Message != "" {
		return "", fmt.Errorf("local model error: %s", out.Error.Message)
	}
	if len(out.Choices) == 0 || strings.TrimSpace(out.Choices[0].Message.Content) == "" {
		return "", errors.New("local model returned no content")
	}
	return out.Choices[0].Message.Content, nil
}
