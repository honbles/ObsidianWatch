package otel

// remoteconfig.go - per-service settings the agent pulls from the backend (outbound HTTPS
// only), so a change in the UI takes effect without rebuilding the agent: client-address
// storage mode, cleartext user identifiers and the slow-trace threshold.
//
// Precedence (privacy first): the build configuration is a floor. For the client-address
// mode the STRICTER of the build value and the pulled value wins. Cleartext user ids are
// sent only when the pulled settings say so, or, when the service has no pulled settings
// at all, when the build configuration lists the service.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sync"
	"time"
)

// RemoteService mirrors the backend's AppRemoteService.
type RemoteService struct {
	Service         string `json:"service"`
	Environment     string `json:"environment"`
	StoreClientIP   string `json:"store_client_ip"`
	CleartextUsers  bool   `json:"cleartext_users"`
	LatencyTargetMs int    `json:"latency_target_ms"`
}

var modeRank = map[string]int{ClientIPFull: 0, ClientIPTruncated: 1, ClientIPOff: 2}

// stricterMode returns the more private of two client-address modes (unknown values lose).
func stricterMode(a, b string) string {
	ra, oka := modeRank[a]
	rb, okb := modeRank[b]
	switch {
	case !oka && !okb:
		return ClientIPFull
	case !oka:
		return b
	case !okb:
		return a
	case rb > ra:
		return b
	}
	return a
}

type liveSettings struct {
	mu  sync.RWMutex
	svc map[string]RemoteService
	at  time.Time
}

func newLiveSettings() *liveSettings { return &liveSettings{svc: map[string]RemoteService{}} }

func (l *liveSettings) set(list []RemoteService, now time.Time) {
	m := make(map[string]RemoteService, len(list))
	for _, r := range list {
		if r.Service == "" {
			continue
		}
		if _, ok := modeRank[r.StoreClientIP]; !ok {
			r.StoreClientIP = "" // invalid: ignore for the privacy mode
		}
		if r.LatencyTargetMs < 0 {
			r.LatencyTargetMs = 0
		}
		m[r.Service+"|"+envOf(r.Environment)] = r
	}
	l.mu.Lock()
	l.svc, l.at = m, now
	l.mu.Unlock()
}

func (l *liveSettings) get(svc, env string) (RemoteService, bool) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	r, ok := l.svc[svc+"|"+envOf(env)]
	return r, ok
}

// Loaded reports when settings were last pulled (zero before the first success).
func (l *liveSettings) Loaded() time.Time {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.at
}

// FetchConfig asks the backend for the per-service settings.
func (s *Sender) FetchConfig(ctx context.Context, agentID string) ([]RemoteService, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.opt.BackendURL+"/api/v1/app/agent-config?agent_id="+url.QueryEscape(agentID), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "obsidianwatch-agent/"+s.opt.Version)
	if s.opt.APIKey != "" {
		req.Header.Set("X-API-Key", s.opt.APIKey)
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("agent-config: HTTP %d", resp.StatusCode)
	}
	var out struct {
		Services []RemoteService `json:"services"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&out); err != nil {
		return nil, fmt.Errorf("agent-config: %w", err)
	}
	return out.Services, nil
}
