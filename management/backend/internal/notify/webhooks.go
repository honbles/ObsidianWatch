package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	neturl "net/url"
	"strings"
	"sync"
	"time"

	"obsidianwatch/management/internal/store"
)

// P-08: alert fan-out to chat/webhook channels (Slack, Microsoft Teams,
// Discord, generic JSON). Channel configuration is stored (sealed at rest,
// because webhook URLs are bearer secrets) under the settings key
// "notify.webhooks". Sending is queued, rate-capped and SSRF-guarded.

const (
	WebhookSettingKey = "notify.webhooks"
	webhookQueueSize  = 500
	webhookPerMinute  = 60
)

type WebhookChannel struct {
	Name        string `json:"name"`
	Type        string `json:"type"` // slack | teams | discord | generic
	URL         string `json:"url"`
	MinSeverity int    `json:"min_severity"`
	Enabled     bool   `json:"enabled"`
}

type WebhookDispatcher struct {
	db     *store.DB
	logger *slog.Logger

	mu       sync.RWMutex
	channels []WebhookChannel
	loadedAt time.Time

	queue  chan store.Alert
	client *http.Client
}

func NewWebhookDispatcher(db *store.DB, logger *slog.Logger) *WebhookDispatcher {
	d := &WebhookDispatcher{
		db:     db,
		logger: logger,
		queue:  make(chan store.Alert, webhookQueueSize),
		client: &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{DialContext: safeDial}},
	}
	go d.worker()
	return d
}

// Enqueue is the store.AlertCreatedHook target; it never blocks.
func (d *WebhookDispatcher) Enqueue(a store.Alert) {
	select {
	case d.queue <- a:
	default:
		d.logger.Warn("webhook queue full; dropping alert notification", "alert", a.ID)
	}
}

// ValidateWebhookURL enforces https and a public host (SSRF guard #1; the
// dialer re-checks the resolved address at connect time, guard #2).
func ValidateWebhookURL(raw string) error {
	u, err := neturl.Parse(raw)
	if err != nil || u.Host == "" {
		return fmt.Errorf("invalid URL")
	}
	if u.Scheme != "https" {
		return fmt.Errorf("webhook URL must use https")
	}
	if u.User != nil {
		return fmt.Errorf("webhook URL must not contain credentials")
	}
	host := u.Hostname()
	if strings.EqualFold(host, "localhost") || strings.HasSuffix(strings.ToLower(host), ".internal") ||
		strings.HasSuffix(strings.ToLower(host), ".local") {
		return fmt.Errorf("webhook host not allowed")
	}
	if ip := net.ParseIP(host); ip != nil && isPrivateIP(ip) {
		return fmt.Errorf("webhook host resolves to a private address")
	}
	return nil
}

var cgnatNet = &net.IPNet{IP: net.IPv4(100, 64, 0, 0), Mask: net.CIDRMask(10, 32)}

func isPrivateIP(ip net.IP) bool {
	// 100.64.0.0/10 (carrier-grade NAT) is not covered by IsPrivate but is
	// commonly used for internal cloud/VPN ranges.
	if cgnatNet.Contains(ip) {
		return true
	}
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsUnspecified() || ip.IsMulticast()
}

// safeDial resolves the host and refuses private/loopback/link-local targets.
func safeDial(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	for _, ia := range ips {
		if isPrivateIP(ia.IP) {
			return nil, fmt.Errorf("blocked private address %s", ia.IP)
		}
	}
	var d net.Dialer
	return d.DialContext(ctx, network, net.JoinHostPort(ips[0].IP.String(), port))
}

func (d *WebhookDispatcher) load(ctx context.Context) []WebhookChannel {
	d.mu.RLock()
	if time.Since(d.loadedAt) < 30*time.Second {
		ch := d.channels
		d.mu.RUnlock()
		return ch
	}
	d.mu.RUnlock()
	var chs []WebhookChannel
	if v, err := d.db.GetSetting(ctx, WebhookSettingKey); err == nil && v != "" {
		json.Unmarshal([]byte(v), &chs)
	}
	d.mu.Lock()
	d.channels, d.loadedAt = chs, time.Now()
	d.mu.Unlock()
	return chs
}

// Reload forces the next send to re-read the configuration.
func (d *WebhookDispatcher) Reload() {
	d.mu.Lock()
	d.loadedAt = time.Time{}
	d.mu.Unlock()
}

func (d *WebhookDispatcher) worker() {
	windowStart := time.Now()
	sent := 0
	for a := range d.queue {
		if time.Since(windowStart) > time.Minute {
			windowStart, sent = time.Now(), 0
		}
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		for _, ch := range d.load(ctx) {
			if !ch.Enabled || a.Severity < ch.MinSeverity {
				continue
			}
			if sent >= webhookPerMinute {
				d.logger.Warn("webhook rate cap reached; notification skipped", "alert", a.ID)
				break
			}
			sent++
			if err := d.send(ctx, ch, a); err != nil {
				d.logger.Warn("webhook send failed", "channel", ch.Name, "err", err)
			}
		}
		cancel()
	}
}

var sevNames = map[int]string{1: "Info", 2: "Low", 3: "Medium", 4: "High", 5: "Critical"}

func trunc(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}

// payload builds the provider-specific JSON body.
func payload(ch WebhookChannel, a store.Alert) ([]byte, error) {
	sev := sevNames[a.Severity]
	if sev == "" {
		sev = fmt.Sprint(a.Severity)
	}
	title := fmt.Sprintf("[%s] %s", sev, trunc(a.Title, 200))
	body := trunc(a.Description, 1500)
	meta := fmt.Sprintf("Host: %s | Type: %s | Alert #%d", a.Host, a.EventType, a.ID)
	switch strings.ToLower(ch.Type) {
	case "slack":
		return json.Marshal(map[string]interface{}{
			"text": title,
			"blocks": []map[string]interface{}{
				{"type": "header", "text": map[string]string{"type": "plain_text", "text": trunc(title, 150)}},
				{"type": "section", "text": map[string]string{"type": "mrkdwn", "text": trunc(body, 2900)}},
				{"type": "context", "elements": []map[string]string{{"type": "mrkdwn", "text": meta}}},
			},
		})
	case "teams":
		colour := map[int]string{5: "B71C1C", 4: "E65100", 3: "F9A825"}[a.Severity]
		if colour == "" {
			colour = "607D8B"
		}
		return json.Marshal(map[string]interface{}{
			"@type": "MessageCard", "@context": "https://schema.org/extensions",
			"summary": title, "themeColor": colour, "title": title,
			"sections": []map[string]interface{}{{"text": body, "facts": []map[string]string{
				{"name": "Host", "value": a.Host}, {"name": "Type", "value": a.EventType},
				{"name": "Alert", "value": fmt.Sprint(a.ID)}}}},
		})
	case "discord":
		return json.Marshal(map[string]interface{}{
			"content": trunc(title, 190),
			"embeds":  []map[string]interface{}{{"description": trunc(body, 3900), "footer": map[string]string{"text": meta}}},
		})
	default:
		return json.Marshal(map[string]interface{}{
			"id": a.ID, "title": a.Title, "description": a.Description, "severity": a.Severity,
			"severity_name": sev, "host": a.Host, "event_type": a.EventType,
			"agent_id": a.AgentID, "created_at": a.CreatedAt, "source": "obsidianwatch",
		})
	}
}

func (d *WebhookDispatcher) send(ctx context.Context, ch WebhookChannel, a store.Alert) error {
	if err := ValidateWebhookURL(ch.URL); err != nil {
		return err
	}
	b, err := payload(ch, a)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, ch.URL, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := d.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	if resp.StatusCode >= 300 {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return nil
}

// SendTest posts a sample alert to one channel (used by the settings UI).
func (d *WebhookDispatcher) SendTest(ctx context.Context, ch WebhookChannel) error {
	return d.send(ctx, ch, store.Alert{
		ID: 0, Title: "ObsidianWatch test notification", Severity: 3, Host: "test-host",
		EventType: "test", Description: "This is a test message from ObsidianWatch. If you can read this, the channel works.",
		CreatedAt: time.Now(),
	})
}
