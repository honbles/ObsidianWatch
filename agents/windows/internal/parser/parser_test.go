package parser

import (
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"obsidianwatch/agent/pkg/schema"
)

func quietLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func validEvent() schema.Event {
	return schema.Event{AgentID: "a1", Host: "h1", Time: time.Now(), Source: "Security", EventID: 4688}
}

func TestNormalizeRejectsMalformed(t *testing.T) {
	n := NewNormalizer(quietLogger())
	if err := n.Normalize(nil); err == nil {
		t.Fatal("nil event must error")
	}
	for name, mut := range map[string]func(*schema.Event){
		"agent": func(e *schema.Event) { e.AgentID = "" },
		"host":  func(e *schema.Event) { e.Host = "" },
		"time":  func(e *schema.Event) { e.Time = time.Time{} },
	} {
		e := validEvent()
		mut(&e)
		if err := n.Normalize(&e); err == nil {
			t.Errorf("%s: missing field must be rejected", name)
		}
	}
}

func TestNormalizeDefaultsAndHygiene(t *testing.T) {
	n := NewNormalizer(quietLogger())
	e := validEvent()
	e.UserName = "  alice\x00 "
	e.CommandLine = strings.Repeat("A", 5000)
	if err := n.Normalize(&e); err != nil {
		t.Fatal(err)
	}
	if e.EventType != schema.EventTypeProcess {
		t.Errorf("4688 should classify as process, got %q", e.EventType)
	}
	if e.Severity != schema.SeverityInfo {
		t.Errorf("zero severity should floor to info, got %d", e.Severity)
	}
	if e.UserName != "alice" {
		t.Errorf("username not sanitised: %q", e.UserName)
	}
	if !strings.HasSuffix(e.CommandLine, "[truncated]") || len(e.CommandLine) > 4200 {
		t.Errorf("command line not truncated: len=%d", len(e.CommandLine))
	}
	if e.OS != "windows" {
		t.Errorf("OS default: %q", e.OS)
	}
}

func TestClassifyByEventID(t *testing.T) {
	cases := []struct {
		id     uint32
		source string
		want   schema.EventType
	}{
		{4624, "Security", schema.EventTypeLogon},
		{4625, "Security", schema.EventTypeLogon},
		{4688, "Security", schema.EventTypeProcess},
		{4663, "Security", schema.EventTypeFile},
		{4657, "Security", schema.EventTypeRegistry},
		{5156, "Security", schema.EventTypeNetwork},
		{1, "Sysmon", schema.EventTypeSysmon},
		{9999, "Security", schema.EventTypeRaw},
	}
	for _, c := range cases {
		if got := classifyByEventID(c.id, c.source); got != c.want {
			t.Errorf("id %d src %s: got %q want %q", c.id, c.source, got, c.want)
		}
	}
}

func TestSeverityOnlyRaisedNeverLowered(t *testing.T) {
	if got := adjustSeverityByEventID(4720, schema.SeverityInfo); got != schema.SeverityHigh {
		t.Errorf("4720 should raise to high, got %d", got)
	}
	if got := adjustSeverityByEventID(4625, schema.SeverityCritical); got != schema.SeverityCritical {
		t.Errorf("existing critical must not be lowered, got %d", got)
	}
	if got := adjustSeverityByEventID(1234, schema.SeverityLow); got != schema.SeverityLow {
		t.Errorf("unknown id must keep severity, got %d", got)
	}
}

func TestNormalizeBatchDropsInvalid(t *testing.T) {
	n := NewNormalizer(quietLogger())
	bad := validEvent()
	bad.Host = ""
	out := n.NormalizeBatch([]schema.Event{validEvent(), bad, validEvent()})
	if len(out) != 2 {
		t.Fatalf("expected 2 valid events, got %d", len(out))
	}
}

func TestEnricherOverridesIdentityAndIsDeterministic(t *testing.T) {
	en := NewEnricher(HostInfo{AgentID: "real-agent", Hostname: "real-host", OS: "windows"}, quietLogger())
	e1 := validEvent()
	e1.AgentID, e1.Host = "forged", "forged"
	e1.DstIP = " 010.0.0.1 "
	e2 := e1
	en.Enrich(&e1)
	en.Enrich(&e2)
	if e1.AgentID != "real-agent" || e1.Host != "real-host" {
		t.Fatalf("collector-supplied identity must be overridden: %+v", e1)
	}
	if e1.ID == "" || e1.ID != e2.ID {
		t.Fatalf("ID must be non-empty and deterministic: %q vs %q", e1.ID, e2.ID)
	}
	e2.RecordID = 99
	en.Enrich(&e2)
	if e1.ID == e2.ID {
		t.Fatal("different record IDs must give different IDs")
	}
}

func TestIsPrivateIP(t *testing.T) {
	for ip, want := range map[string]bool{
		"10.1.2.3": true, "172.16.5.1": true, "172.32.0.1": false, "192.168.1.1": true,
		"127.0.0.1": true, "169.254.1.1": true, "8.8.8.8": false, "::1": true, "not-an-ip": false,
	} {
		if got := IsPrivateIP(ip); got != want {
			t.Errorf("%s: got %v want %v", ip, got, want)
		}
	}
}
