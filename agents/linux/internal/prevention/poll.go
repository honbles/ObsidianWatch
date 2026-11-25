package prevention

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

// Poller fetches the set and modes from the server (through the backend,
// with the agent certificate). With the server unreachable the last saved
// set keeps applying.
type Poller struct {
	Engine     *Engine
	BackendURL string
	AgentID    string
	TLS        *tls.Config
	Interval   time.Duration // default 15 minutes; the server can shorten it
}

type pollAnswer struct {
	Version string            `json:"version"`
	Modes   map[string]string `json:"modes"`
	Dirs    []string          `json:"hash_watch_dirs"`
	Refresh int               `json:"refresh_seconds"`
	Set     *Set              `json:"set"`
}

func (p *Poller) Run(ctx context.Context) {
	client := &http.Client{Timeout: 60 * time.Second, Transport: &http.Transport{TLSClientConfig: p.TLS, ForceAttemptHTTP2: true}}
	wait := 20 * time.Second // first fetch shortly after start
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
		next, err := p.once(ctx, client)
		if err != nil {
			p.Engine.logger.Warn("prevention: cannot fetch the indicator set; keeping the last one", "err", err)
			wait = 5 * time.Minute
			continue
		}
		wait = next
	}
}

func (p *Poller) once(ctx context.Context, client *http.Client) (time.Duration, error) {
	_, _, _, have := p.Engine.Counts()
	u := p.BackendURL + "/api/v1/agent/prevention?agent_id=" + url.QueryEscape(p.AgentID) + "&have=" + url.QueryEscape(have)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return 0, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return 0, fmt.Errorf("HTTP %d: %s", resp.StatusCode, b)
	}
	var a pollAnswer
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<20)).Decode(&a); err != nil {
		return 0, err
	}
	p.Engine.Update(a.Set, a.Modes, a.Dirs)
	every := p.Interval
	if every <= 0 {
		every = 15 * time.Minute
	}
	if a.Refresh >= 60 && time.Duration(a.Refresh)*time.Second < every {
		every = time.Duration(a.Refresh) * time.Second
	}
	return every, nil
}

// Update applies a new set (nil keeps the current one) and modes, then
// saves both so they survive restarts and outages.
func (e *Engine) Update(set *Set, modes map[string]string, dirs []string) {
	e.mu.RLock()
	cur := e.snapshotLocked()
	oldModes := map[string]string{}
	for k, v := range e.modes {
		oldModes[k] = v
	}
	e.mu.RUnlock()
	if set == nil {
		set = &cur
	}
	e.apply(*set, modes, dirs)
	ips, hashes, domains, ver := e.Counts()
	for _, k := range []string{"ip", "hash", "domain"} {
		if v := e.Mode(k); oldModes[k] != v {
			e.logger.Info("prevention: mode changed", "type", k, "from", oldModes[k], "to", v)
		}
	}
	e.logger.Info("prevention: indicator set", "version", ver, "ips", ips, "hashes", hashes, "domains", domains,
		"ip_mode", e.Mode("ip"), "hash_mode", e.Mode("hash"), "domain_mode", e.Mode("domain"))
	e.save()
	if modes["hash"] != Off && set.Version != cur.Version {
		e.do(func() { e.sweepProcesses() })
	}
}
