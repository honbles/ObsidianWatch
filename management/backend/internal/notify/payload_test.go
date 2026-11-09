package notify

import (
	"encoding/json"
	"strings"
	"testing"

	"obsidianwatch/management/internal/store"
)

func TestPayloadFormats(t *testing.T) {
	a := store.Alert{ID: 7, Title: "Test alert", Description: "desc", Host: "web1", EventType: "process", Severity: 4}
	for _, typ := range []string{"slack", "teams", "discord", "generic"} {
		b, err := payload(WebhookChannel{Type: typ}, a)
		if err != nil {
			t.Fatalf("%s: %v", typ, err)
		}
		var m map[string]interface{}
		if json.Unmarshal(b, &m) != nil {
			t.Fatalf("%s: invalid JSON", typ)
		}
		if !strings.Contains(string(b), "Test alert") {
			t.Errorf("%s: title missing", typ)
		}
	}
}

func TestPayloadTruncatesLongDescription(t *testing.T) {
	a := store.Alert{Title: "t", Description: strings.Repeat("x", 10000), Severity: 3}
	b, err := payload(WebhookChannel{Type: "slack"}, a)
	if err != nil {
		t.Fatal(err)
	}
	if len(b) > 6000 {
		t.Errorf("payload not truncated: %d bytes", len(b))
	}
}
