package api

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"obsidianwatch/management/internal/store"
)

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 4096,
	CheckOrigin:     func(r *http.Request) bool { return true },
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
func (h *Hub) Run(ctx context.Context) {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	lastCheck := time.Now().Add(-5 * time.Second)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			events, err := h.db.LatestEvents(ctx, lastCheck, 50)
			if err != nil {
				h.logger.Warn("ws hub: query failed", "err", err)
				continue
			}
			lastCheck = time.Now()
			if len(events) == 0 {
				continue
			}
			msg, err := json.Marshal(map[string]interface{}{
				"type":   "events",
				"events": events,
			})
			if err != nil {
				continue
			}
			h.broadcast(msg)
		}
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
