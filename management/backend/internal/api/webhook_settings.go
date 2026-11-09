package api

import (
	"encoding/json"
	"net/http"
	"strings"

	"obsidianwatch/management/internal/auth"
	"obsidianwatch/management/internal/notify"
	"obsidianwatch/management/internal/store"
)

// P-08: webhook/chat notification channel settings.

const maskedURL = "••••••••"

func loadWebhookChannels(r *http.Request, db *store.DB) []notify.WebhookChannel {
	var chs []notify.WebhookChannel
	if v, err := db.GetSetting(r.Context(), notify.WebhookSettingKey); err == nil && v != "" {
		json.Unmarshal([]byte(v), &chs)
	}
	return chs
}

func handleGetWebhooks(db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		chs := loadWebhookChannels(r, db)
		out := make([]notify.WebhookChannel, 0, len(chs))
		for _, c := range chs {
			if c.URL != "" {
				// URLs are bearer secrets: show only the host.
				host := c.URL
				if i := strings.Index(host, "://"); i >= 0 {
					host = host[i+3:]
				}
				if i := strings.Index(host, "/"); i >= 0 {
					host = host[:i]
				}
				c.URL = "https://" + host + "/" + maskedURL
			}
			out = append(out, c)
		}
		writeJSON(w, 200, map[string]interface{}{"channels": out})
	}
}

func handleSaveWebhooks(db *store.DB, d *notify.WebhookDispatcher) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
		var req struct {
			Channels []notify.WebhookChannel `json:"channels"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, 400, map[string]string{"error": "invalid request"})
			return
		}
		if len(req.Channels) > 20 {
			writeJSON(w, 400, map[string]string{"error": "too many channels (max 20)"})
			return
		}
		existing := map[string]string{}
		for _, c := range loadWebhookChannels(r, db) {
			existing[c.Name] = c.URL
		}
		for i := range req.Channels {
			c := &req.Channels[i]
			c.Name = strings.TrimSpace(c.Name)
			if c.Name == "" || len(c.Name) > 80 {
				writeJSON(w, 400, map[string]string{"error": "each channel needs a name (max 80 chars)"})
				return
			}
			switch strings.ToLower(c.Type) {
			case "slack", "teams", "discord", "generic":
			default:
				writeJSON(w, 400, map[string]string{"error": "type must be slack, teams, discord or generic"})
				return
			}
			// A masked URL means "keep the stored one".
			if strings.Contains(c.URL, maskedURL) {
				c.URL = existing[c.Name]
			}
			if err := notify.ValidateWebhookURL(c.URL); err != nil {
				writeJSON(w, 400, map[string]string{"error": c.Name + ": " + err.Error()})
				return
			}
			if c.MinSeverity < 1 || c.MinSeverity > 5 {
				c.MinSeverity = 4
			}
		}
		b, _ := json.Marshal(req.Channels)
		if err := db.SetSetting(r.Context(), notify.WebhookSettingKey, string(b)); err != nil {
			writeJSON(w, 500, map[string]string{"error": "failed to save"})
			return
		}
		d.Reload()
		if c := auth.GetClaims(r); c != nil {
			db.WriteAudit(r.Context(), c.Username, "save_webhook_channels", "settings:notify.webhooks", "", clientIP(r))
		}
		writeJSON(w, 200, map[string]string{"status": "saved"})
	}
}

func handleTestWebhook(db *store.DB, d *notify.WebhookDispatcher) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
		var ch notify.WebhookChannel
		if err := json.NewDecoder(r.Body).Decode(&ch); err != nil {
			writeJSON(w, 400, map[string]string{"error": "invalid request"})
			return
		}
		if strings.Contains(ch.URL, maskedURL) {
			for _, c := range loadWebhookChannels(r, db) {
				if c.Name == ch.Name {
					ch.URL = c.URL
				}
			}
		}
		if err := d.SendTest(r.Context(), ch); err != nil {
			writeJSON(w, 400, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, 200, map[string]string{"status": "sent"})
	}
}

// ── Syslog / CEF forwarding (P-09) ────────────────────────────────────────────

func handleGetSyslog(db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var c notify.SyslogConfig
		if v, err := db.GetSetting(r.Context(), notify.SyslogSettingKey); err == nil && v != "" {
			json.Unmarshal([]byte(v), &c)
		}
		writeJSON(w, 200, c)
	}
}

func validateSyslogConfig(c *notify.SyslogConfig) string {
	c.Host = strings.TrimSpace(c.Host)
	if c.Host == "" || len(c.Host) > 253 || strings.ContainsAny(c.Host, "/ \t") {
		return "valid host required"
	}
	if c.Port < 0 || c.Port > 65535 {
		return "invalid port"
	}
	switch strings.ToLower(c.Proto) {
	case "udp", "tcp", "tls":
	case "":
		c.Proto = "udp"
	default:
		return "proto must be udp, tcp or tls"
	}
	if c.MinSeverity < 1 || c.MinSeverity > 5 {
		c.MinSeverity = 3
	}
	return ""
}

func handleSaveSyslog(db *store.DB, f *notify.SyslogForwarder) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, 8<<10)
		var c notify.SyslogConfig
		if err := json.NewDecoder(r.Body).Decode(&c); err != nil {
			writeJSON(w, 400, map[string]string{"error": "invalid request"})
			return
		}
		if msg := validateSyslogConfig(&c); msg != "" {
			writeJSON(w, 400, map[string]string{"error": msg})
			return
		}
		b, _ := json.Marshal(c)
		if err := db.SetSetting(r.Context(), notify.SyslogSettingKey, string(b)); err != nil {
			writeJSON(w, 500, map[string]string{"error": "failed to save"})
			return
		}
		f.Reload()
		if cl := auth.GetClaims(r); cl != nil {
			db.WriteAudit(r.Context(), cl.Username, "save_syslog_forwarding", "settings:notify.syslog", c.Host, clientIP(r))
		}
		writeJSON(w, 200, map[string]string{"status": "saved"})
	}
}

func handleTestSyslog(f *notify.SyslogForwarder) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, 8<<10)
		var c notify.SyslogConfig
		if err := json.NewDecoder(r.Body).Decode(&c); err != nil {
			writeJSON(w, 400, map[string]string{"error": "invalid request"})
			return
		}
		if msg := validateSyslogConfig(&c); msg != "" {
			writeJSON(w, 400, map[string]string{"error": msg})
			return
		}
		if err := f.SendTest(r.Context(), c); err != nil {
			writeJSON(w, 400, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, 200, map[string]string{"status": "sent"})
	}
}
