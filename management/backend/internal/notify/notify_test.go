package notify

import (
	"net"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"obsidianwatch/management/internal/store"
)

func TestValidateWebhookURL(t *testing.T) {
	bad := []string{
		"", "http://hooks.example.com/x", "https://localhost/x", "https://svc.internal/x", "https://printer.local/x",
		"https://127.0.0.1/x", "https://10.0.0.5/x", "https://192.168.1.1/x", "https://169.254.169.254/latest",
		"https://100.64.1.1/x", "https://[::1]/x", "https://user:pw@hooks.example.com/x", "https://0.0.0.0/x",
	}
	for _, u := range bad {
		if ValidateWebhookURL(u) == nil {
			t.Errorf("should reject %q", u)
		}
	}
	for _, u := range []string{"https://hooks.slack.com/services/T/B/x", "https://8.8.8.8/hook"} {
		if err := ValidateWebhookURL(u); err != nil {
			t.Errorf("should accept %q: %v", u, err)
		}
	}
}

func TestIsPrivateIP(t *testing.T) {
	for ip, want := range map[string]bool{
		"10.1.2.3": true, "172.16.0.1": true, "100.127.255.255": true, "100.128.0.1": false,
		"8.8.8.8": false, "::ffff:127.0.0.1": true, "fe80::1": true, "2606:4700::1111": false,
	} {
		if got := isPrivateIP(net.ParseIP(ip)); got != want {
			t.Errorf("%s: got %v want %v", ip, got, want)
		}
	}
}

func TestFormatCEFEscaping(t *testing.T) {
	a := store.Alert{ID: 9, Severity: 4, Title: "bad|title\nline2", EventType: "x|y", Host: "h=1",
		Description: "a=b\nc\\d", AgentID: "ag", CreatedAt: time.Unix(1700000000, 0)}
	line := FormatCEF(a)
	if strings.Contains(line, "\n") {
		t.Fatal("CEF line must be a single line")
	}
	if !strings.Contains(line, `bad\|title line2`) || !strings.Contains(line, `dhost=h\=1`) || !strings.Contains(line, `msg=a\=b\nc\\d`) {
		t.Fatalf("escaping wrong: %s", line)
	}
	if !strings.Contains(line, "|8|") {
		t.Fatalf("severity 4 should map to CEF 8: %s", line)
	}
}

func TestFormatCEFTruncatesRuneSafe(t *testing.T) {
	a := store.Alert{Severity: 3, Description: strings.Repeat("é", 1500), CreatedAt: time.Now()}
	if line := FormatCEF(a); !utf8.ValidString(line) {
		t.Fatal("truncation produced invalid UTF-8")
	}
}

func TestTrunc(t *testing.T) {
	if trunc("héllo", 10) != "héllo" || trunc("héllo", 2) != "hé…" {
		t.Fatal("trunc wrong")
	}
}
