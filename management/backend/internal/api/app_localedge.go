package api

import (
	"context"
	"encoding/json"
	"net"
	"strconv"
	"strings"
	"time"

	"obsidianwatch/management/internal/store"
)

// Local dependency resolution (spec F3). A client span to localhost:11434 names a port on the same host;
// when a discovered or instrumented service listens on that port on one of the caller's hosts, the edge
// is shown as a call to that service instead of an anonymous "localhost:11434".

type appLocalTarget struct {
	ServiceID int64
	Name      string
	Env       string
	Agent     string
}

type appLocalIndex struct {
	byPort  map[int][]appLocalTarget
	agentOf map[int64]map[string]bool // service id -> agents it has live instances on
}

// appLocalPort extracts the port of a loopback endpoint ("localhost:11434", "127.0.0.1:5432", "[::1]:80").
func appLocalPort(dst string) (int, bool) {
	h, p, err := net.SplitHostPort(strings.TrimSpace(dst))
	if err != nil {
		return 0, false
	}
	h = strings.ToLower(strings.Trim(h, "[]"))
	if ip := net.ParseIP(h); !(h == "localhost" || (ip != nil && (ip.IsLoopback() || ip.IsUnspecified()))) {
		return 0, false
	}
	n, err := strconv.Atoi(p)
	if err != nil || n <= 0 || n > 65535 {
		return 0, false
	}
	return n, true
}

// appListenPorts reads a listen array of numbers or "addr:port" strings.
func appListenPorts(raw []byte) []int {
	var items []json.RawMessage
	if json.Unmarshal(raw, &items) != nil {
		return nil
	}
	var out []int
	for _, it := range items {
		var n int
		if json.Unmarshal(it, &n) == nil && n > 0 {
			out = append(out, n)
			continue
		}
		var s string
		if json.Unmarshal(it, &s) == nil {
			if i := strings.LastIndexByte(s, ':'); i >= 0 {
				s = s[i+1:]
			}
			if p, err := strconv.Atoi(s); err == nil && p > 0 {
				out = append(out, p)
			}
		}
	}
	return out
}

func appLoadLocalIndex(ctx context.Context, idb *store.DB) *appLocalIndex {
	ix := &appLocalIndex{byPort: map[int][]appLocalTarget{}, agentOf: map[int64]map[string]bool{}}
	rows, err := idb.QueryContext(ctx, `
		SELECT i.service_id, s.name, s.environment, i.agent_id, i.listen
		FROM service_instances i JOIN services s ON s.id = i.service_id
		WHERE i.stopped_at IS NULL AND i.last_seen > $1 LIMIT 5000`, time.Now().UTC().Add(-appInstanceFresh))
	if err != nil {
		return ix
	}
	defer rows.Close()
	for rows.Next() {
		var t appLocalTarget
		var listen []byte
		if rows.Scan(&t.ServiceID, &t.Name, &t.Env, &t.Agent, &listen) != nil {
			continue
		}
		if ix.agentOf[t.ServiceID] == nil {
			ix.agentOf[t.ServiceID] = map[string]bool{}
		}
		ix.agentOf[t.ServiceID][t.Agent] = true
		for _, p := range appListenPorts(listen) {
			ix.byPort[p] = append(ix.byPort[p], t)
		}
	}
	return ix
}

// Resolve returns the service listening on the loopback endpoint on one of the caller's hosts.
func (ix *appLocalIndex) Resolve(src int64, dst string) (appLocalTarget, bool) {
	port, ok := appLocalPort(dst)
	if !ok {
		return appLocalTarget{}, false
	}
	for _, c := range ix.byPort[port] {
		if c.ServiceID != src && ix.agentOf[src][c.Agent] {
			return c, true
		}
	}
	return appLocalTarget{}, false
}
