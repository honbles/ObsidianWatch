//go:build windows

package collector

// live_response.go — Windows live response agent component.
//
// Spawns cmd.exe directly via os/exec — no SSH, no user creation.
// The agent runs as SYSTEM, so we just exec cmd.exe and pipe
// stdin/stdout through the existing management WebSocket tunnel.
//
// Security:
//   - Shell runs as the same user as the agent (SYSTEM by default)
//   - No new users created, no net user commands
//   - All traffic goes over the existing TLS-encrypted WebSocket tunnel

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

const lrReconnectInterval = 15 * time.Second

type LiveResponseCollector struct {
	agentID          string
	hostname         string
	managementURL    string
	apiKey           string
	caFile           string
	caPEM            string
	allowInsecureTLS bool
	logger           *slog.Logger
}

func NewLiveResponseCollector(agentID, hostname, managementURL, apiKey, caFile, managementCAFile string, allowInsecureTLS bool, logger *slog.Logger) *LiveResponseCollector {
	return &LiveResponseCollector{
		agentID:          agentID,
		hostname:         hostname,
		managementURL:    managementURL,
		apiKey:           apiKey,
		caFile:           resolveCAFile(managementCAFile, caFile),
		allowInsecureTLS: allowInsecureTLS,
		logger:           logger,
	}
}

func (c *LiveResponseCollector) SetCAPEM(pem string) { c.caPEM = pem }

func (c *LiveResponseCollector) Run(ctx context.Context) error {
	c.logger.Info("live-response: starting (direct shell, no SSH)")
	for {
		if err := c.runTunnel(ctx); err != nil {
			c.logger.Warn("live-response: tunnel disconnected", "err", err)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(lrReconnectInterval):
			c.logger.Info("live-response: reconnecting tunnel...")
		}
	}
}

func (c *LiveResponseCollector) runTunnel(ctx context.Context) error {
	mgmt := strings.TrimRight(c.managementURL, "/")
	// C-1: the tunnel carries the API key and a remote shell; never cleartext.
	if !strings.HasPrefix(strings.ToLower(mgmt), "https://") {
		return fmt.Errorf("live-response: refusing non-https management URL %q (tunnel requires wss)", mgmt)
	}
	wsURL := "wss://" + mgmt[len("https://"):]
	wsURL += fmt.Sprintf("/api/v1/live-response/agent-tunnel?agent_id=%s", c.agentID)

	dialer := wsDialerForCAPEM(c.caPEM, c.caFile, c.allowInsecureTLS)
	headers := http.Header{}
	headers.Set("X-API-Key", c.apiKey)

	conn, _, err := dialer.DialContext(ctx, wsURL, headers)
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	defer conn.Close()
	conn.SetReadLimit(1 << 20) // server frames are commands/keystrokes; bound them

	c.logger.Info("live-response: tunnel connected")

	// Register as direct-shell mode — no credentials needed
	conn.WriteJSON(map[string]interface{}{
		"type":    "register_credentials",
		"payload": json.RawMessage(`{"username":"SYSTEM","mode":"direct-shell"}`),
	})

	type sessionEntry struct{ ch chan []byte }
	sessions := make(map[string]*sessionEntry)
	var mu sync.Mutex
	var wsWriteMu sync.Mutex

	writeJSON := func(v interface{}) error {
		wsWriteMu.Lock()
		defer wsWriteMu.Unlock()
		return conn.WriteJSON(v)
	}

	for {
		_, msg, err := conn.ReadMessage()
		if err != nil {
			return fmt.Errorf("read: %w", err)
		}

		var env struct {
			Type    string          `json:"type"`
			Token   string          `json:"token"`
			Payload json.RawMessage `json:"payload"`
		}
		if err := json.Unmarshal(msg, &env); err != nil {
			continue
		}

		switch env.Type {
		case "open_session":
			tok := env.Token
			c.logger.Info("live-response: session requested", "token", tok[:8]+"...")
			ch := make(chan []byte, 256)
			mu.Lock()
			sessions[tok] = &sessionEntry{ch: ch}
			mu.Unlock()
			go func() {
				c.handleSession(ctx, tok, ch, writeJSON)
				mu.Lock()
				delete(sessions, tok)
				mu.Unlock()
			}()

		case "data":
			tok := env.Token
			mu.Lock()
			entry, ok := sessions[tok]
			mu.Unlock()
			if ok {
				select {
				case entry.ch <- []byte(env.Payload):
				default:
					c.logger.Warn("live-response: data channel full, dropping", "token", tok[:8]+"...")
				}
			}

		case "close_session":
			tok := env.Token
			mu.Lock()
			entry, ok := sessions[tok]
			if ok {
				close(entry.ch)
				delete(sessions, tok)
			}
			mu.Unlock()
		}
	}
}

// handleSession spawns cmd.exe directly — no SSH needed.
func (c *LiveResponseCollector) handleSession(ctx context.Context, token string, inCh chan []byte, writeJSON func(interface{}) error) {
	// Find PowerShell or fall back to cmd.exe
	shell := "powershell.exe"
	if _, err := exec.LookPath(shell); err != nil {
		shell = "cmd.exe"
	}

	cmd := exec.CommandContext(ctx, shell)
	cmd.Env = append(os.Environ(),
		"OBSIDIANWATCH_LIVE_RESPONSE=1",
		"TERM=xterm-256color",
	)

	stdin, err := cmd.StdinPipe()
	if err != nil {
		writeJSON(map[string]interface{}{"type": "session_error", "token": token, "error": err.Error()})
		return
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		writeJSON(map[string]interface{}{"type": "session_error", "token": token, "error": err.Error()})
		return
	}
	cmd.Stderr = cmd.Stdout

	if err := cmd.Start(); err != nil {
		c.logger.Warn("live-response: shell start failed", "err", err)
		writeJSON(map[string]interface{}{"type": "session_error", "token": token, "error": err.Error()})
		return
	}

	c.logger.Info("live-response: shell session started", "token", token[:8]+"...", "shell", shell)

	done := make(chan struct{}, 2)

	// stdin: WebSocket → shell
	go func() {
		defer func() { stdin.Close(); done <- struct{}{} }()
		for payload := range inCh {
			var raw []byte
			if err := json.Unmarshal(payload, &raw); err == nil {
				if _, err := stdin.Write(raw); err != nil {
					return
				}
			}
		}
	}()

	// stdout: shell → WebSocket
	go func() {
		defer func() { done <- struct{}{} }()
		buf := make([]byte, 32*1024)
		for {
			n, err := stdout.Read(buf)
			if n > 0 {
				payload, _ := json.Marshal(buf[:n])
				writeJSON(map[string]interface{}{
					"type": "data", "token": token,
					"payload": json.RawMessage(payload),
				})
			}
			if err != nil {
				if err != io.EOF {
					c.logger.Debug("live-response: stdout read end", "err", err)
				}
				writeJSON(map[string]interface{}{"type": "session_end", "token": token})
				return
			}
		}
	}()

	select {
	case <-done:
		cmd.Process.Kill()
	case <-ctx.Done():
		cmd.Process.Kill()
	}
	go func() {
		for range inCh {
		}
	}()
	cmd.Wait()
}
