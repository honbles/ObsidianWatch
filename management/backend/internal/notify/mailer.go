package notify

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/smtp"
	"strings"
	"time"

	"obsidianwatch/management/internal/config"
	"obsidianwatch/management/internal/store"
)

type Mailer struct {
	cfg config.SMTPConfig
}

func NewMailer(cfg config.SMTPConfig) *Mailer {
	return &Mailer{cfg: cfg}
}

func (m *Mailer) Enabled() bool {
	return m.cfg.Enabled && m.cfg.Host != "" && len(m.cfg.To) > 0
}

func (m *Mailer) SendAlert(alert store.Alert) error {
	if !m.Enabled() {
		return nil
	}

	severityLabel := map[int]string{1: "INFO", 2: "LOW", 3: "MEDIUM", 4: "HIGH", 5: "CRITICAL"}
	sev := severityLabel[alert.Severity]
	if sev == "" {
		sev = fmt.Sprintf("%d", alert.Severity)
	}

	subject := fmt.Sprintf("[ObsidianWatch] [%s] %s", sev, alert.Title)

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
		m.cfg.From,
		strings.Join(m.cfg.To, ", "),
		subject,
		body,
	)

	addr := fmt.Sprintf("%s:%d", m.cfg.Host, m.cfg.Port)
	auth := smtp.PlainAuth("", m.cfg.Username, m.cfg.Password, m.cfg.Host)

	if m.cfg.UseTLS {
		return m.sendTLS(addr, auth, msg)
	}
	return smtp.SendMail(addr, auth, m.cfg.From, m.cfg.To, []byte(msg))
}

func (m *Mailer) sendTLS(addr string, auth smtp.Auth, msg string) error {
	host, _, _ := net.SplitHostPort(addr)
	tlsCfg := &tls.Config{ServerName: host}

	conn, err := tls.Dial("tcp", addr, tlsCfg)
	if err != nil {
		// Fall back to STARTTLS
		return smtp.SendMail(addr, auth, m.cfg.From, m.cfg.To, []byte(msg))
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
	if err := client.Mail(m.cfg.From); err != nil {
		return err
	}
	for _, to := range m.cfg.To {
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
	if m.cfg.MinSeverity == 0 {
		return 4
	}
	return m.cfg.MinSeverity
}

// UpdateConfig replaces the mailer config at runtime — called when settings are saved via UI.
func (m *Mailer) UpdateConfig(cfg config.SMTPConfig) {
	m.cfg = cfg
}

