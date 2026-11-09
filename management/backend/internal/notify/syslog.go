package notify

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"obsidianwatch/management/internal/store"
)

// P-09: forward new alerts to an external SIEM/syslog collector as CEF over
// UDP, TCP or TLS. Unlike webhooks, private addresses are allowed here —
// collectors normally live inside the network and the target is set by an
// authenticated admin. Settings key: "notify.syslog".

const SyslogSettingKey = "notify.syslog"

type SyslogConfig struct {
	Enabled     bool   `json:"enabled"`
	Host        string `json:"host"`
	Port        int    `json:"port"`
	Proto       string `json:"proto"` // udp | tcp | tls
	MinSeverity int    `json:"min_severity"`
}

type SyslogForwarder struct {
	db     *store.DB
	logger *slog.Logger
	queue  chan store.Alert

	mu       sync.RWMutex
	cfg      SyslogConfig
	loadedAt time.Time
}

func NewSyslogForwarder(db *store.DB, logger *slog.Logger) *SyslogForwarder {
	f := &SyslogForwarder{db: db, logger: logger, queue: make(chan store.Alert, 1000)}
	go f.worker()
	return f
}

func (f *SyslogForwarder) Enqueue(a store.Alert) {
	select {
	case f.queue <- a:
	default:
		f.logger.Warn("syslog queue full; dropping alert forward", "alert", a.ID)
	}
}

func (f *SyslogForwarder) Reload() {
	f.mu.Lock()
	f.loadedAt = time.Time{}
	f.mu.Unlock()
}

func (f *SyslogForwarder) load(ctx context.Context) SyslogConfig {
	f.mu.RLock()
	if time.Since(f.loadedAt) < 30*time.Second {
		c := f.cfg
		f.mu.RUnlock()
		return c
	}
	f.mu.RUnlock()
	var c SyslogConfig
	if v, err := f.db.GetSetting(ctx, SyslogSettingKey); err == nil && v != "" {
		json.Unmarshal([]byte(v), &c)
	}
	f.mu.Lock()
	f.cfg, f.loadedAt = c, time.Now()
	f.mu.Unlock()
	return c
}

// cefEscape escapes header fields (| and \) and extension values (= and \, newlines).
func cefHeader(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, "|", `\|`)
	return strings.NewReplacer("\n", " ", "\r", " ").Replace(s)
}

func cefExt(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, "=", `\=`)
	return strings.NewReplacer("\n", `\n`, "\r", `\n`).Replace(s)
}

// FormatCEF renders an alert as an RFC 3164 syslog line carrying a CEF record.
func FormatCEF(a store.Alert) string {
	sev := map[int]int{1: 1, 2: 3, 3: 5, 4: 8, 5: 10}[a.Severity]
	host, _ := os.Hostname()
	if host == "" {
		host = "obsidianwatch"
	}
	desc := a.Description
	if r := []rune(desc); len(r) > 1000 {
		desc = string(r[:1000]) // rune-safe so multi-byte text is never cut mid-character
	}
	cef := fmt.Sprintf("CEF:0|ObsidianWatch|SIEM|1.0|%s|%s|%d|rt=%d dhost=%s deviceExternalId=%d cs1Label=eventType cs1=%s cs2Label=agentId cs2=%s msg=%s",
		cefHeader(a.EventType), cefHeader(a.Title), sev,
		a.CreatedAt.UnixMilli(), cefExt(a.Host), a.ID, cefExt(a.EventType), cefExt(a.AgentID), cefExt(desc))
	// facility 4 (auth) * 8 + severity: crit=2, err=3, warn=4, notice=5, info=6
	sysSev := map[int]int{5: 2, 4: 3, 3: 4, 2: 5, 1: 6}[a.Severity]
	if sysSev == 0 {
		sysSev = 6
	}
	return fmt.Sprintf("<%d>%s %s obsidianwatch: %s", 4*8+sysSev, a.CreatedAt.Format("Jan _2 15:04:05"), host, cef)
}

func (f *SyslogForwarder) worker() {
	for a := range f.queue {
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		cfg := f.load(ctx)
		if cfg.Enabled && cfg.Host != "" && a.Severity >= cfg.MinSeverity {
			if err := f.send(ctx, cfg, FormatCEF(a)); err != nil {
				f.logger.Warn("syslog forward failed", "err", err)
			}
		}
		cancel()
	}
}

func (f *SyslogForwarder) send(ctx context.Context, cfg SyslogConfig, line string) error {
	port := cfg.Port
	if port == 0 {
		port = 514
	}
	addr := net.JoinHostPort(cfg.Host, fmt.Sprint(port))
	var d net.Dialer
	var conn net.Conn
	var err error
	switch strings.ToLower(cfg.Proto) {
	case "tcp":
		conn, err = d.DialContext(ctx, "tcp", addr)
		line += "\n"
	case "tls":
		td := tls.Dialer{NetDialer: &d, Config: &tls.Config{MinVersion: tls.VersionTLS12, ServerName: cfg.Host}}
		conn, err = td.DialContext(ctx, "tcp", addr)
		line += "\n"
	default:
		conn, err = d.DialContext(ctx, "udp", addr)
	}
	if err != nil {
		return err
	}
	defer conn.Close()
	conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	_, err = conn.Write([]byte(line))
	return err
}

// SendTest sends a sample CEF event with the given config.
func (f *SyslogForwarder) SendTest(ctx context.Context, cfg SyslogConfig) error {
	return f.send(ctx, cfg, FormatCEF(store.Alert{
		ID: 0, Title: "ObsidianWatch syslog test", Severity: 3, Host: "test-host", EventType: "test",
		Description: "Test event from ObsidianWatch", CreatedAt: time.Now(),
	}))
}
