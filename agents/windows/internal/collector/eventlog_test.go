//go:build windows

package collector

import (
	"io"
	"log/slog"
	"testing"

	"obsidianwatch/agent/pkg/schema"
)

func testCollector() *EventLogCollector {
	return &EventLogCollector{agentID: "a1", host: "h1", logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
}

func xmlEvent(id, level, data string) []byte {
	return []byte(`<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">` +
		`<System><Provider Name="Microsoft-Windows-Security-Auditing"/><EventID>` + id + `</EventID>` +
		`<Level>` + level + `</Level><TimeCreated SystemTime="2026-01-02T03:04:05.123456700Z"/>` +
		`<EventRecordID>42</EventRecordID><Channel>Security</Channel><Computer>WS01</Computer></System>` +
		`<EventData>` + data + `</EventData></Event>`)
}

func TestParseProcessCreation4688(t *testing.T) {
	ev := testCollector().parseEventXML(xmlEvent("4688", "0",
		`<Data Name="SubjectUserName">alice</Data><Data Name="NewProcessName">C:\Windows\System32\cmd.exe</Data>`+
			`<Data Name="NewProcessId">0x1a4</Data><Data Name="ParentProcessId">100</Data><Data Name="CommandLine">cmd /c whoami</Data>`))
	if ev == nil {
		t.Fatal("event dropped")
	}
	if ev.EventType != schema.EventTypeProcess || ev.EventID != 4688 || ev.RecordID != 42 {
		t.Errorf("bad classification: %+v", ev)
	}
	if ev.PID != 420 || ev.PPID != 100 || ev.UserName != "alice" || ev.CommandLine != "cmd /c whoami" {
		t.Errorf("bad fields: pid=%d ppid=%d user=%q cmd=%q", ev.PID, ev.PPID, ev.UserName, ev.CommandLine)
	}
	if ev.Time.Year() != 2026 {
		t.Errorf("time not parsed: %v", ev.Time)
	}
}

func TestNoisyNetworkLogonDropped(t *testing.T) {
	for _, lt := range []string{"0", "3", "4", "5"} {
		if ev := testCollector().parseEventXML(xmlEvent("4624", "0", `<Data Name="LogonType">`+lt+`</Data>`)); ev != nil {
			t.Errorf("logon type %s should be dropped", lt)
		}
	}
	ev := testCollector().parseEventXML(xmlEvent("4624", "0", `<Data Name="LogonType">10</Data><Data Name="TargetUserName">bob</Data>`))
	if ev == nil || ev.EventType != schema.EventTypeLogon || ev.Severity != schema.SeverityMedium {
		t.Errorf("RDP logon should be kept at medium: %+v", ev)
	}
}

func TestFailedNetworkLogonIsHigh(t *testing.T) {
	ev := testCollector().parseEventXML(xmlEvent("4625", "0", `<Data Name="LogonType">3</Data>`))
	if ev == nil || ev.Severity != schema.SeverityHigh {
		t.Errorf("failed network logon should be high: %+v", ev)
	}
}

func TestNetworkEvent5156(t *testing.T) {
	ev := testCollector().parseEventXML(xmlEvent("5156", "0",
		`<Data Name="SourceAddress">10.0.0.5</Data><Data Name="DestAddress">8.8.8.8</Data>`+
			`<Data Name="SourcePort">50000</Data><Data Name="DestPort">443</Data><Data Name="Protocol">6</Data>`))
	if ev == nil || ev.DstIP != "8.8.8.8" || ev.DstPort != 443 || ev.Proto != "tcp" {
		t.Errorf("bad network parse: %+v", ev)
	}
}

func TestMalformedXMLBecomesRawEvent(t *testing.T) {
	ev := testCollector().parseEventXML([]byte("<Event><System>"))
	if ev == nil || ev.EventType != schema.EventTypeRaw {
		t.Fatalf("malformed xml should yield a raw event, got %+v", ev)
	}
}

func TestHelpers(t *testing.T) {
	if v, err := parseHexOrDec("0x10"); err != nil || v != 16 {
		t.Errorf("hex: %d %v", v, err)
	}
	if v, err := parseHexOrDec(" 42 "); err != nil || v != 42 {
		t.Errorf("dec: %d %v", v, err)
	}
	if firstOf(map[string]string{"A": "-", "B": "x"}, "A", "B") != "x" {
		t.Error("firstOf must skip '-' placeholders")
	}
	if windowsLevelToSeverity(1) != schema.SeverityCritical || windowsLevelToSeverity(4) != schema.SeverityInfo {
		t.Error("level mapping wrong")
	}
}
