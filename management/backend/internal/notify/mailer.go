package notify

import (
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"net/smtp"
	"strings"
	"sync"
	"time"

	"obsidianwatch/management/internal/config"
	"obsidianwatch/management/internal/store"
)

type Mailer struct {
	mu  sync.RWMutex
	cfg config.SMTPConfig

	// F-27: alert emails go through a bounded queue with a single worker
	// and a per-minute cap instead of one goroutine per alert. Alerts over
	// the cap (or arriving with a full queue) are counted and folded into
	// a single digest email.
	queueOnce sync.Once
	queue     chan store.Alert
	dropMu    sync.Mutex
	dropped   int
	droppedHi int
}

const (
	mailQueueSize    = 200
	mailPerMinuteCap = 20
)

func NewMailer(cfg config.SMTPConfig) *Mailer {
	return &Mailer{cfg: cfg}
}

func (m *Mailer) config() config.SMTPConfig {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.cfg
}

func (m *Mailer) Enabled() bool {
	c := m.config()
	return c.Enabled && c.Host != "" && len(c.To) > 0
}

// QueueAlert enqueues an alert email without blocking the detection path.
func (m *Mailer) QueueAlert(a store.Alert) {
	m.queueOnce.Do(func() {
		m.queue = make(chan store.Alert, mailQueueSize)
		go m.worker()
	})
	select {
	case m.queue <- a:
	default:
		m.noteDropped(a)
	}
}

func (m *Mailer) noteDropped(a store.Alert) {
	m.dropMu.Lock()
	m.dropped++
	if a.Severity >= 5 {
		m.droppedHi++
	}
	m.dropMu.Unlock()
}

func (m *Mailer) worker() {
	windowStart := time.Now()
	sent := 0
	digestTick := time.NewTicker(5 * time.Minute)
	defer digestTick.Stop()
	for {
		select {
		case a := <-m.queue:
			if time.Since(windowStart) >= time.Minute {
				windowStart, sent = time.Now(), 0
			}
			if sent >= mailPerMinuteCap {
				m.noteDropped(a)
				continue
			}
			sent++
			if err := m.SendAlert(a); err != nil {
				slog.Warn("mailer: send failed", "err", err)
			}
		case <-digestTick.C:
			m.dropMu.Lock()
			n, hi := m.dropped, m.droppedHi
			m.dropped, m.droppedHi = 0, 0
			m.dropMu.Unlock()
			if n > 0 {
				err := m.SendAlert(store.Alert{
					Title: fmt.Sprintf("Alert digest: %d additional alerts suppressed by rate limit", n),
					Description: fmt.Sprintf("%d alert emails (%d critical) exceeded the %d/min email cap and were not sent individually. Review the Alerts page.",
						n, hi, mailPerMinuteCap),
					Severity: 4, Status: "open", Host: "system", EventType: "digest", CreatedAt: time.Now(),
				})
				if err != nil {
					slog.Warn("mailer: digest send failed", "err", err)
				}
			}
		}
	}
}

// headerSafe strips CR/LF so alert text can't inject mail headers.
func headerSafe(s string) string {
	return strings.NewReplacer("\r", " ", "\n", " ").Replace(s)
}

func (m *Mailer) SendAlert(alert store.Alert) error {
	if !m.Enabled() {
		return nil
	}
	cfg := m.config()

	severityLabel := map[int]string{1: "INFO", 2: "LOW", 3: "MEDIUM", 4: "HIGH", 5: "CRITICAL"}
	sev := severityLabel[alert.Severity]
	if sev == "" {
		sev = fmt.Sprintf("%d", alert.Severity)
	}

	subject := headerSafe(fmt.Sprintf("[ObsidianWatch] [%s] %s", sev, alert.Title))

	body := fmt.Sprintf(`ObsidianWatch Alert Notification
===========================

Title:      %s
Severity:   %s (%d/5)
Status:     %s
Host:       %s
Event Type: %s
Time:       %s

Description:
%s

---
This is an automated alert from ObsidianWatch Management Platform.
To manage this alert, log in to your ObsidianWatch dashboard.
`,
		alert.Title,
		sev, alert.Severity,
		alert.Status,
		alert.Host,
		alert.EventType,
		alert.CreatedAt.Format(time.RFC1123),
		alert.Description,
	)

	msg := fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n%s",
		cfg.From,
		strings.Join(cfg.To, ", "),
		subject,
		body,
	)

	addr := fmt.Sprintf("%s:%d", cfg.Host, cfg.Port)
	auth := smtp.PlainAuth("", cfg.Username, cfg.Password, cfg.Host)

	if cfg.UseTLS {
		return m.sendTLS(cfg, addr, auth, msg)
	}
	return smtp.SendMail(addr, auth, cfg.From, cfg.To, []byte(msg))
}

func (m *Mailer) sendTLS(cfg config.SMTPConfig, addr string, auth smtp.Auth, msg string) error {
	host, _, _ := net.SplitHostPort(addr)
	tlsCfg := &tls.Config{ServerName: host}

	conn, err := tls.Dial("tcp", addr, tlsCfg)
	if err != nil {
		// Fall back to STARTTLS
		return smtp.SendMail(addr, auth, cfg.From, cfg.To, []byte(msg))
	}
	defer conn.Close()

	client, err := smtp.NewClient(conn, host)
	if err != nil {
		return err
	}
	defer client.Close()

	if err := client.Auth(auth); err != nil {
		return err
	}
	if err := client.Mail(cfg.From); err != nil {
		return err
	}
	for _, to := range cfg.To {
		if err := client.Rcpt(to); err != nil {
			return err
		}
	}
	w, err := client.Data()
	if err != nil {
		return err
	}
	_, err = fmt.Fprint(w, msg)
	if err != nil {
		return err
	}
	return w.Close()
}

// TestConnection sends a test email to verify SMTP config.
func (m *Mailer) TestConnection() error {
	if !m.Enabled() {
		return fmt.Errorf("SMTP is not enabled or not configured")
	}
	return m.SendAlert(store.Alert{
		Title:       "ObsidianWatch SMTP Test",
		Description: "This is a test email from ObsidianWatch to verify your SMTP configuration is working correctly.",
		Severity:    1,
		Status:      "open",
		Host:        "system",
		EventType:   "test",
		CreatedAt:   time.Now(),
	})
}

func (m *Mailer) MinSeverity() int {
	c := m.config()
	if c.MinSeverity == 0 {
		return 4
	}
	return c.MinSeverity
}

// UpdateConfig replaces the mailer config at runtime — called when settings are saved via UI.
func (m *Mailer) UpdateConfig(cfg config.SMTPConfig) {
	m.mu.Lock()
	m.cfg = cfg
	m.mu.Unlock()
}

