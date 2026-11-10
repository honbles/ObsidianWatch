//go:build darwin

package collector

// live_response.go — macOS live response agent component.
//
// Spawns a shell directly via os/exec with a PTY — no SSH, no user creation.
// The agent already runs as root, so we just exec /bin/zsh with a PTY and
// pipe stdin/stdout through the existing management WebSocket tunnel.

import (
	"obsidianwatch/macos-agent/internal/ownproc"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

const lrReconnectInterval = 15 * time.Second

// sessionEntry is one live-response shell session as seen by the tunnel loop.
type sessionEntry struct {
	ch  chan []byte
	ptm atomic.Pointer[os.File] // set once the shell PTY exists (resize)
}

func clampTermDim(v, def int) int {
	if v < 10 || v > 500 {
		return def
	}
	return v
}

type LiveResponseCollector struct {
	agentID       string
	hostname      string
	managementURL string
	apiKey        string
	caFile        string
	logger        *slog.Logger
}

func NewLiveResponseCollector(agentID, hostname, managementURL, apiKey, caFile, managementCAFile string, logger *slog.Logger) *LiveResponseCollector {
	return &LiveResponseCollector{
		agentID:       agentID,
		hostname:      hostname,
		managementURL: managementURL,
		apiKey:        apiKey,
		caFile:        resolveCAFile(managementCAFile, caFile),
		logger:        logger,
	}
}

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

	dialer := wsDialerForCA(c.caFile)
	headers := http.Header{}
	headers.Set("X-API-Key", c.apiKey)

	conn, _, err := dialer.DialContext(ctx, wsURL, headers)
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	defer conn.Close()
	conn.SetReadLimit(1 << 20) // server frames are commands/keystrokes; bound them

	c.logger.Info("live-response: tunnel connected")

	conn.WriteJSON(map[string]interface{}{
		"type":    "register_credentials",
		"payload": json.RawMessage(`{"username":"root","mode":"direct-shell"}`),
	})

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
			Cols    int             `json:"cols"`
			Rows    int             `json:"rows"`
		}
		if err := json.Unmarshal(msg, &env); err != nil {
			continue
		}

		switch env.Type {
		case "open_session":
			tok := env.Token
			cols, rows := env.Cols, env.Rows
			if cols == 0 { cols = 120 }
			if rows == 0 { rows = 30 }
			c.logger.Info("live-response: session requested", "token", tok[:8]+"...")
			ch := make(chan []byte, 256)
			mu.Lock()
			entry := &sessionEntry{ch: ch}
			sessions[tok] = entry
			mu.Unlock()
			go func() {
				c.handleSession(ctx, tok, ch, writeJSON, cols, rows, entry)
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

func (c *LiveResponseCollector) handleSession(ctx context.Context, token string, inCh chan []byte, writeJSON func(interface{}) error, cols, rows int, entry *sessionEntry) {
	ptm, pts, err := openPTY()
	if err != nil {
		c.logger.Warn("live-response: PTY open failed", "err", err)
		writeJSON(map[string]interface{}{"type": "session_error", "token": token, "error": err.Error()})
		return
	}
	defer ptm.Close()

	setWinsize(ptm, cols, rows)
	entry.ptm.Store(ptm)
	defer entry.ptm.Store(nil)

	// Prefer zsh (default on macOS Catalina+), fall back to bash
	shell := "/bin/zsh"
	if _, err := os.Stat(shell); err != nil {
		shell = "/bin/bash"
	}

	cmd := exec.CommandContext(ctx, shell, "-l")
	cmd.Stdin = pts
	cmd.Stdout = pts
	cmd.Stderr = pts
	cmd.SysProcAttr = &unix.SysProcAttr{
		Setsid:  true,
		Setctty: true,
		Ctty:    0,
	}
	cmd.Env = []string{
		"TERM=xterm-256color",
		"HOME=/var/root",
		"USER=root",
		"SHELL=" + shell,
		"PATH=/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin",
		"OBSIDIANWATCH_LIVE_RESPONSE=1",
	}

	if err := cmd.Start(); err != nil {
		c.logger.Warn("live-response: shell start failed", "err", err)
		writeJSON(map[string]interface{}{"type": "session_error", "token": token, "error": err.Error()})
		pts.Close()
		return
	}
	ownproc.Exclude(cmd.Process.Pid) // analyst commands stay visible
	pts.Close()

	c.logger.Info("live-response: shell session started", "token", token[:8]+"...", "shell", shell)

	done := make(chan struct{}, 2)

	go func() {
		defer func() { done <- struct{}{} }()
		for payload := range inCh {
			var raw []byte
			if err := json.Unmarshal(payload, &raw); err == nil {
				if _, err := ptm.Write(raw); err != nil {
					return
				}
			}
		}
	}()

	go func() {
		defer func() { done <- struct{}{} }()
		buf := make([]byte, 32*1024)
		for {
			n, err := ptm.Read(buf)
			if n > 0 {
				payload, _ := json.Marshal(buf[:n])
				writeJSON(map[string]interface{}{
					"type": "data", "token": token,
					"payload": json.RawMessage(payload),
				})
			}
			if err != nil {
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
	go func() { for range inCh {} }()
	cmd.Wait()
}

func openPTY() (*os.File, *os.File, error) {
	ptm, err := os.OpenFile("/dev/ptmx", os.O_RDWR, 0)
	if err != nil {
		return nil, nil, fmt.Errorf("open ptmx: %w", err)
	}
	if err := grantPT(ptm); err != nil {
		ptm.Close()
		return nil, nil, fmt.Errorf("grantpt: %w", err)
	}
	if err := unlockPT(ptm); err != nil {
		ptm.Close()
		return nil, nil, fmt.Errorf("unlockpt: %w", err)
	}
	ptsName, err := ptsName(ptm)
	if err != nil {
		ptm.Close()
		return nil, nil, fmt.Errorf("ptsname: %w", err)
	}
	pts, err := os.OpenFile(ptsName, os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		ptm.Close()
		return nil, nil, fmt.Errorf("open pts %s: %w", ptsName, err)
	}
	return ptm, pts, nil
}

func grantPT(f *os.File) error {
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, f.Fd(), unix.TIOCPTYGNAME, 0)
	_ = errno
	return nil
}

func unlockPT(f *os.File) error {
	var n int32 = 0
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, f.Fd(), unix.TIOCPTYUNLK, uintptr(unsafe.Pointer(&n)))
	_ = errno
	return nil
}

func ptsName(f *os.File) (string, error) {
	// On macOS use TIOCPTYGNAME to get slave name
	buf := make([]byte, 128)
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, f.Fd(), unix.TIOCPTYGNAME, uintptr(unsafe.Pointer(&buf[0])))
	if errno != 0 {
		return "", errno
	}
	// buf contains null-terminated string like "/dev/tty...."  
	n := 0
	for n < len(buf) && buf[n] != 0 {
		n++
	}
	return string(buf[:n]), nil
}

type winsize struct {
	Rows uint16
	Cols uint16
	X    uint16
	Y    uint16
}

func setWinsize(f *os.File, cols, rows int) {
	ws := winsize{Rows: uint16(rows), Cols: uint16(cols)}
	unix.Syscall(unix.SYS_IOCTL, f.Fd(), unix.TIOCSWINSZ, uintptr(unsafe.Pointer(&ws)))
}
