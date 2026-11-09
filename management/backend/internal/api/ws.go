package api

import (
	"context"
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	neturl "net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"obsidianwatch/management/internal/store"
)

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 4096,
	CheckOrigin:     checkWSOrigin,
}

type client struct {
	conn *websocket.Conn
	send chan []byte
}

// Hub manages all WebSocket connections and broadcasts new events.
type Hub struct {
	mu      sync.RWMutex
	clients map[*client]bool
	db      *store.DB
	logger  *slog.Logger
}

func NewHub(db *store.DB, logger *slog.Logger) *Hub {
	return &Hub{
		clients: make(map[*client]bool),
		db:      db,
		logger:  logger,
	}
}

// Run starts the background poller that pushes new events to all clients.
//
// F-26: this used to page by event time ("time > lastCheck ORDER BY time
// DESC LIMIT 50") — a burst of more than 50 events in one 2s tick silently
// dropped everything past the 50 newest, and an event that arrived late
// (agent reconnect, retried flush) with a `time` older than lastCheck
// never matched the filter at all, since lastCheck only ever moves
// forward. It now uses the same ingested_at cursor as the detection/alert
// engines (pageEventCursor, D-01/D-02): nothing is skipped regardless of
// burst size, and a full page just means the next tick resumes exactly
// where this one stopped instead of losing the overflow.
func (h *Hub) Run(ctx context.Context) {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			h.pushCursor(ctx)
		}
	}
}

func (h *Hub) pushCursor(ctx context.Context) {
	events, err := pageEventCursor(ctx, h.db, "ws-feed", store.EventFilter{}, 5*time.Second, 2000)
	if err != nil {
		h.logger.Warn("ws hub: cursor query failed", "err", err)
		return
	}
	if len(events) == 0 {
		return
	}
	// Broadcast in batches so one giant backlog page doesn't become one
	// giant WebSocket frame.
	const batchSize = 200
	for i := 0; i < len(events); i += batchSize {
		end := i + batchSize
		if end > len(events) {
			end = len(events)
		}
		msg, err := json.Marshal(map[string]interface{}{
			"type":   "events",
			"events": events[i:end],
		})
		if err != nil {
			continue
		}
		h.broadcast(msg)
	}
}

func (h *Hub) broadcast(msg []byte) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	for c := range h.clients {
		select {
		case c.send <- msg:
		default:
			// Client's send buffer is full — drop.
		}
	}
}

// maxHubClients bounds concurrent dashboard sockets; each holds a goroutine pair
// and a send buffer, so an unbounded count is a memory-exhaustion lever for
// any authenticated user.
const maxHubClients = 1000

func (h *Hub) full() bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return len(h.clients) >= maxHubClients
}

func (h *Hub) register(c *client) {
	h.mu.Lock()
	h.clients[c] = true
	h.mu.Unlock()
}

func (h *Hub) unregister(c *client) {
	h.mu.Lock()
	delete(h.clients, c)
	h.mu.Unlock()
}

// ServeWS upgrades the HTTP connection to WebSocket and starts read/write pumps.
func (h *Hub) ServeWS(w http.ResponseWriter, r *http.Request) {
	if h.full() {
		http.Error(w, `{"error":"too many live connections"}`, http.StatusServiceUnavailable)
		return
	}
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		h.logger.Warn("ws: upgrade failed", "err", err)
		return
	}

	c := &client{conn: conn, send: make(chan []byte, 64)}
	h.register(c)
	h.logger.Info("ws: client connected", "remote", r.RemoteAddr)

	// Write pump
	go func() {
		defer func() {
			h.unregister(c)
			conn.Close()
		}()
		for {
			msg, ok := <-c.send
			if !ok {
				conn.WriteMessage(websocket.CloseMessage, []byte{})
				return
			}
			conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if err := conn.WriteMessage(websocket.TextMessage, msg); err != nil {
				return
			}
		}
	}()

	// Read pump — just handles pings/pongs and close.
	go func() {
		defer func() {
			h.unregister(c)
			conn.Close()
		}()
		conn.SetReadLimit(512)
		conn.SetReadDeadline(time.Now().Add(60 * time.Second))
		conn.SetPongHandler(func(string) error {
			conn.SetReadDeadline(time.Now().Add(60 * time.Second))
			return nil
		})
		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				return
			}
		}
	}()
}

// checkWSOrigin (M-10) replaces the blanket `return true`. Browsers always
// send an Origin header on WebSocket upgrades, and cross-site pages could
// otherwise open authenticated sockets from a victim's browser. Allowed: no
// Origin (non-browser clients such as agents), an Origin whose host matches
// the request Host, or one listed in OW_ALLOWED_ORIGINS (comma-separated,
// e.g. "https://siem.example.com").
func checkWSOrigin(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}
	u, err := neturl.Parse(origin)
	if err != nil || u.Host == "" {
		return false
	}
	// nginx forwards `Host $host`, which drops the port, so compare
	// hostnames only (ports on the same host are the same site for this
	// purpose; scheme/port mismatches are still covered by the allow-list).
	reqHost := r.Host
	if h, _, err := net.SplitHostPort(reqHost); err == nil {
		reqHost = h
	}
	if strings.EqualFold(u.Hostname(), reqHost) {
		return true
	}
	for _, a := range strings.Split(os.Getenv("OW_ALLOWED_ORIGINS"), ",") {
		if a = strings.TrimSpace(a); a != "" && strings.EqualFold(strings.TrimRight(a, "/"), strings.TrimRight(origin, "/")) {
			return true
		}
	}
	return false
}
